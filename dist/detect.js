/**
 * antipython - detect attempts to mutate files through a Python interpreter.
 *
 * The policy: a Python interpreter must never be the thing that writes a file
 * during agent work. Use the edit/write tools instead. What IS allowed is
 * running real Python scripts and normal module invocations (pytest, pip, ...).
 *
 * Pipeline:
 *   1. splitCommand  - quote/heredoc aware shell splitter
 *   2. findPython    - locate interpreter invocations in each command segment
 *   3. classify      - decide whether the payload is a real script, a module
 *                      run, or inline code authored by the model
 *   4. scanCode      - regex edit-intent scan over inline code
 *
 * The same policy covers `sed -i`: any in-place rewrite of a file is off
 * limits, not just the ones routed through an interpreter.
 */
const REDIRECT_TWO_CHAR = [">>", "&>>", "<<", "<&", ">&", ">|", "<>"];
const REDIRECT_ONE_CHAR = new Set([">", "<"]);
const SEPARATOR_TWO_CHAR = ["&&", "||", ";;", "|&"];
const SEPARATOR_ONE_CHAR = new Set([";", "|", "&", "\n", "(", ")", "{", "}"]);
/** Python flags that consume the following argv entry as a value. */
const PYTHON_VALUED_FLAGS = new Set(["-c", "-m", "-W", "-X", "--command", "--module"]);
export function splitCommand(command) {
    const segments = [];
    let argv = [];
    let redirects = [];
    let heredocs = [];
    let raw = "";
    let buf = "";
    let wordStarted = false;
    let pendingRedirect = null;
    let pendingHeredocs = [];
    let pendingStrip = false;
    let pipelined = false;
    let quote = null;
    let i = 0;
    const endToken = () => {
        if (pendingRedirect) {
            redirects.push({ op: pendingRedirect, target: buf });
            pendingRedirect = null;
        }
        else if (wordStarted && buf.length > 0) {
            argv.push(buf);
        }
        else if (wordStarted && buf.length === 0) {
            argv.push("");
        }
        buf = "";
        wordStarted = false;
    };
    const endSegment = (piped) => {
        endToken();
        if (argv.length > 0 || redirects.length > 0 || heredocs.length > 0) {
            segments.push({ argv, redirects, heredocs, raw: raw.trim(), piped });
        }
        argv = [];
        redirects = [];
        heredocs = [];
        raw = "";
        pendingHeredocs = [];
        pendingStrip = false;
    };
    const readHeredocBody = (delim, strip) => {
        let body = "";
        for (;;) {
            const nl = command.indexOf("\n", i);
            const line = nl === -1 ? command.slice(i) : command.slice(i, nl);
            const candidate = strip ? line.replace(/^\t+/, "") : line;
            if (candidate === delim) {
                i = nl === -1 ? command.length : nl + 1;
                return body;
            }
            body += line + "\n";
            if (nl === -1) {
                i = command.length;
                return body;
            }
            i = nl + 1;
        }
    };
    while (i < command.length) {
        const ch = command[i];
        // inside quotes: everything is literal content of the current word
        if (quote) {
            if (ch === "\\" && quote === '"' && i + 1 < command.length) {
                buf += command[i] + command[i + 1];
                raw += ch + command[i + 1];
                i += 2;
                continue;
            }
            if (ch === quote) {
                buf += ch;
                raw += ch;
                quote = null;
                i++;
                continue;
            }
            buf += ch;
            raw += ch;
            i++;
            continue;
        }
        if (ch === "\\" && i + 1 < command.length) {
            buf += command[i + 1];
            raw += ch + command[i + 1];
            wordStarted = true;
            i += 2;
            continue;
        }
        if (ch === "'" || ch === '"') {
            quote = ch;
            buf += ch;
            raw += ch;
            wordStarted = true;
            i++;
            continue;
        }
        if (ch === "$" && command[i + 1] === "(") {
            // command substitution: the inner text is scanned as its own segment
            endToken();
            raw += "$( ";
            i += 2;
            continue;
        }
        if (ch === " " || ch === "\t") {
            if (!pendingRedirect)
                endToken();
            raw += ch;
            i++;
            continue;
        }
        // here-string: <<< word
        if (ch === "<" && command[i + 1] === "<" && command[i + 2] === "<") {
            endToken();
            pendingRedirect = "<<<";
            wordStarted = true;
            raw += "<<<";
            i += 3;
            continue;
        }
        // heredoc: << delim / <<- delim
        if (ch === "<" && command[i + 1] === "<") {
            const head = /^<<(-?)[ \t]*/.exec(command.slice(i));
            let j = i + head[0].length;
            let delim = "";
            while (j < command.length && !/[\s;|<>&()]/.test(command[j])) {
                delim += command[j];
                j++;
            }
            if (delim) {
                endToken();
                const cleanDelim = /^(['"])(.*)\1$/.exec(delim)?.[2] ?? delim;
                pendingHeredocs.push(cleanDelim);
                pendingStrip = head[1] === "-";
                pendingRedirect = `<<${head[1]}${cleanDelim}`;
                wordStarted = true;
                raw += command.slice(i, j);
                i = j;
                continue;
            }
        }
        if (ch === ">" || ch === "<") {
            const two = command.slice(i, i + 2);
            const base = REDIRECT_TWO_CHAR.includes(two) ? two : REDIRECT_ONE_CHAR.has(ch) ? ch : null;
            if (base) {
                let fd = "";
                if (!pendingRedirect && !wordStarted && /^\d+$/.test(buf)) {
                    fd = buf;
                    buf = "";
                }
                endToken();
                pendingRedirect = fd + base;
                wordStarted = true;
                raw += base;
                i += base.length;
                continue;
            }
        }
        const twoSep = command.slice(i, i + 2);
        if (SEPARATOR_TWO_CHAR.includes(twoSep)) {
            endSegment(pipelined);
            pipelined = false;
            raw += twoSep;
            i += 2;
            continue;
        }
        if (SEPARATOR_ONE_CHAR.has(ch)) {
            if (ch === "\n") {
                // heredoc bodies for this line are consumed after the newline
                const nlPos = i;
                endToken();
                const bodies = [];
                for (const delim of pendingHeredocs) {
                    bodies.push({ delim, body: readHeredocBody(delim, pendingStrip) });
                }
                if (argv.length > 0 || redirects.length > 0 || bodies.length > 0) {
                    segments.push({ argv, redirects, heredocs: bodies, raw: raw.trim(), piped: pipelined });
                }
                argv = [];
                redirects = [];
                heredocs = [];
                pendingHeredocs = [];
                pendingStrip = false;
                raw = "";
                pipelined = false;
                i = nlPos + 1;
                continue;
            }
            const pipe = ch === "|";
            endSegment(pipelined);
            if (pipe)
                pipelined = true;
            raw += ch;
            i++;
            continue;
        }
        buf += ch;
        raw += ch;
        wordStarted = true;
        i++;
    }
    endSegment(pipelined);
    return segments;
}
const PYTHON_BASENAMES = new Set([
    "python",
    "python2",
    "python3",
    "py",
    "pythonw",
    "pypy",
    "pypy3",
    "ipython",
]);
export function basename(word) {
    const base = word.split("/").pop() ?? word;
    return base.replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();
}
export function isPythonBinary(word) {
    const base = basename(word);
    if (PYTHON_BASENAMES.has(base))
        return true;
    return /^python(2|3)?(\.\d{1,2})?$/.test(base);
}
/** subcommands/launchers that may sit in front of the interpreter */
const RUNNERS = new Set([
    "run",
    "exec",
    "env",
    "command",
    "sudo",
    "doas",
    "time",
    "nice",
    "nohup",
    "stdbuf",
    "timeout",
    "autoenv",
    "uv",
    "poetry",
    "pipenv",
    "conda",
    "hatch",
    "pdm",
    "rye",
    "pixi",
]);
/**
 * Shell control words that may precede a command word. The splitter breaks a
 * compound command at `;`, so a loop or conditional body arrives as its own
 * segment starting with one of these.
 */
const CONTROL_WORDS = new Set([
    "do",
    "then",
    "else",
    "elif",
    "if",
    "while",
    "until",
    "for",
    "in",
    "case",
    "esac",
    "fi",
    "done",
    "time",
    "coproc",
    "select",
    "function",
    "not",
    "return",
]);
export function findPythonIndex(argv) {
    for (let i = 0; i < argv.length; i++) {
        const word = argv[i];
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word))
            continue;
        if (!isPythonBinary(word))
            continue;
        // everything before the interpreter must be a benign prefix
        let ok = true;
        for (let j = 0; j < i; j++) {
            const prev = argv[j];
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(prev))
                continue;
            if (RUNNERS.has(basename(prev)) || RUNNERS.has(prev))
                continue;
            if (/^-(?:[a-z]*n)?\d+$/.test(prev))
                continue;
            if (prev === "--")
                continue;
            if (CONTROL_WORDS.has(prev))
                continue;
            ok = false;
            break;
        }
        if (ok)
            return i;
    }
    return -1;
}
const SED_BASENAMES = new Set(["sed", "gsed"]);
/**
 * launchers that hand the rest of their argv to sed: `xargs`, and the find
 * primaries (`-exec`/`-ok`, whose `rargs` companion may follow the command).
 */
const SED_LAUNCHERS = new Set(["xargs", "-exec", "-execdir", "-ok", "-okdir", "rargs"]);
export function isSedBinary(word) {
    return SED_BASENAMES.has(basename(word));
}
/**
 * index of a sed invocation, or -1. Mirrors findPythonIndex: everything before
 * the command word has to be a benign prefix (runner, env assignment, or a flag
 * of a launcher like `xargs -0`).
 */
export function findSedIndex(argv) {
    for (let i = 0; i < argv.length; i++) {
        const word = argv[i];
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word))
            continue;
        if (!isSedBinary(word))
            continue;
        // find's `find . -name x -exec sed ...` needs the launcher rule, not a
        // per-word allowlist: everything in between is find's own arguments.
        if (argv.slice(0, i).some((w) => SED_LAUNCHERS.has(w)))
            return i;
        let ok = true;
        for (let j = 0; j < i; j++) {
            const prev = argv[j];
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(prev))
                continue;
            if (RUNNERS.has(basename(prev)) || RUNNERS.has(prev))
                continue;
            if (/^-[A-Za-z0-9][\w.-]*$/.test(prev))
                continue;
            if (CONTROL_WORDS.has(prev))
                continue;
            ok = false;
            break;
        }
        if (ok)
            return i;
    }
    return -1;
}
/**
 * Does this raw argv token switch sed to in-place mode?
 *
 * Matched against the unstripped token so a quoted word (`echo "sed -i"`) can
 * never look like a flag. `-i`, clustered flags like `-ni` / `-Ei`, the GNU
 * suffix form `-i.bak` and `--in-place` all count; `-f script` and
 * `-e expr` do not, since their value swallows the rest of the cluster.
 */
export function isInPlaceFlag(token) {
    if (token === "--in-place" || token.startsWith("--in-place="))
        return true;
    if (!/^-[^-]/.test(token))
        return false;
    const cluster = token.slice(1).split(".")[0];
    for (const ch of cluster) {
        if (ch === "i")
            return true;
        if (ch === "f" || ch === "e" || ch === "s")
            return false;
    }
    return false;
}
/** the in-place flag of a sed segment, or null when it only reads */
function findInPlaceFlag(argv) {
    const index = findSedIndex(argv);
    if (index < 0)
        return null;
    for (let i = index + 1; i < argv.length; i++) {
        const token = argv[i];
        if (token === "--")
            break;
        if (isInPlaceFlag(token))
            return token;
    }
    return null;
}
/** .py files the shell part of the command creates, with their inline content */
function collectCreatedFiles(segments) {
    const created = new Map();
    const record = (path, content) => {
        const target = path.replace(/^["']|["']$/g, "").trim();
        if (!target || !/\.pyw?$/i.test(target))
            return;
        const key = target.replace(/^\.\//, "");
        if (!created.has(key))
            created.set(key, { content });
        const base = key.split("/").pop();
        if (!created.has(base))
            created.set(base, { content });
    };
    for (const segment of segments) {
        const heredoc = segment.heredocs[0]?.body ?? "";
        const producerWords = segment.argv.join(" ");
        for (const redirect of segment.redirects) {
            if (!redirect.op.includes(">"))
                continue;
            if (redirect.op.includes("<<"))
                continue;
            const target = redirect.target;
            if (/^\d+$/.test(target) || target === "&-" || target.startsWith("&"))
                continue;
            record(target, heredoc || producerWords);
        }
        if (segment.argv.some((a) => basename(a) === "tee")) {
            for (const arg of segment.argv) {
                if (basename(arg) === "tee" || arg.startsWith("-"))
                    continue;
                record(arg, heredoc || producerWords);
            }
        }
    }
    return created;
}
function classify(segment, created, producer) {
    const index = findPythonIndex(segment.argv);
    if (index < 0)
        return { kind: "allow", why: "no interpreter" };
    const args = segment.argv.slice(index + 1);
    let sawStdinRedirect = false;
    for (let k = 0; k < args.length; k++) {
        const token = stripQuotes(args[k]);
        if (token === "-c" || token === "--command") {
            return { kind: "inline", code: stripQuotes(args[k + 1] ?? ""), via: "inline-c" };
        }
        if (token.startsWith("--command=")) {
            return { kind: "inline", code: stripQuotes(token.slice("--command=".length)), via: "inline-c" };
        }
        if (/^-c.+/.test(token)) {
            return { kind: "inline", code: stripQuotes(token.slice(2)), via: "inline-c" };
        }
        if (token === "-m" || token === "--module" || token.startsWith("--module=")) {
            return { kind: "allow", why: "module invocation" };
        }
        if (token === "-") {
            sawStdinRedirect = true;
            continue;
        }
        if (PYTHON_VALUED_FLAGS.has(token)) {
            k++;
            continue;
        }
        if (token.startsWith("-"))
            continue;
        // first positional argument: a real script file
        if (/\.pyw?$/i.test(token)) {
            const key = token.replace(/^\.\//, "");
            const base = key.split("/").pop();
            const authored = created.get(key) ?? created.get(base);
            if (authored && authored.content.trim()) {
                return { kind: "inline", code: authored.content, via: "generated-script" };
            }
            return { kind: "allow", why: "real script file" };
        }
        break;
    }
    const hereString = segment.redirects.find((r) => r.op === "<<<");
    if (hereString) {
        return { kind: "inline", code: stripQuotes(hereString.target), via: "here-string" };
    }
    const heredoc = segment.heredocs[0];
    if (heredoc) {
        return { kind: "inline", code: heredoc.body, via: "heredoc-stdin" };
    }
    if (segment.piped && producer) {
        const piped = producer.argv.join(" ");
        if (looksLikePython(piped)) {
            return { kind: "inline", code: piped, via: "pipe-stdin" };
        }
        return { kind: "allow", why: "piped input is not a python program" };
    }
    if (sawStdinRedirect) {
        return { kind: "allow", why: "stdin redirected from an existing file" };
    }
    return { kind: "allow", why: "no inline code" };
}
/** Does the piped-in text look like a python program? */
function looksLikePython(code) {
    return /\b(?:import|from)\s+\w|def\s+\w+\s*\(|print\s*\(|\bopen\s*\(|\w+\s*=/.test(code);
}
function stripQuotes(word) {
    const first = word[0];
    if ((first === '"' || first === "'") && word.length > 1 && word.endsWith(first)) {
        return word.slice(1, -1);
    }
    return word;
}
/**
 * Does a file-mode string grant write access? Only `w`, `x`, `a` and `+`
 * do; `r`, `b`, `t` and `U` alone are read-only. The charset guard keeps
 * non-mode strings (paths, encodings like `utf-8`/`latin-1`) from matching.
 */
function isWriteMode(mode) {
    if (!/^[rwxaUbt+]+$/.test(mode))
        return false;
    return /[wax+]/.test(mode);
}
/**
 * True when any quoted literal inside the text is a file mode granting
 * write access. Scans literals rather than the whole argument so a dynamic
 * mode (`'w' if x else 'r'`) still blocks while `encoding='latin-1'` (not
 * in the mode position) is never even examined.
 */
function hasWriteLiteral(text) {
    const re = /"([^"]*)"|'([^']*)'/g;
    let m;
    while ((m = re.exec(text)) !== null) {
        if (isWriteMode(m[1] ?? m[2] ?? ""))
            return true;
    }
    return false;
}
/**
 * True when the code opens a file for writing. Parses `open(...)` calls so
 * read-only opens (`open(f)`, `open(f, 'r')`, `open(f, 'rb')`,
 * `open(f, encoding='utf-8')`) stay allowed while `w`/`a`/`x`/`+` modes
 * (positional or `mode=`) still block. A dotted call (`Path(p).open('w')`,
 * `gzip.open(f, 'wt')`) checks both the first and second positional args
 * since pathlib's method takes mode first while module-level `io.open` and
 * friends take the file first. Keyword args other than `mode=` are skipped
 * so `encoding='latin-1'` can never match.
 */
function hasOpenWrite(code) {
    const re = /(\.)?\bopen\s*\(/g;
    let m;
    while ((m = re.exec(code)) !== null) {
        const dotted = m[1] === ".";
        let i = m.index + m[0].length;
        let depth = 1;
        let quote = null;
        let cur = "";
        const args = [];
        let closed = false;
        while (i < code.length) {
            const ch = code[i];
            if (quote) {
                cur += ch;
                if (ch === "\\" && i + 1 < code.length) {
                    cur += code[i + 1];
                    i += 2;
                    continue;
                }
                if (ch === quote)
                    quote = null;
                i++;
                continue;
            }
            if (ch === '"' || ch === "'") {
                quote = ch;
                cur += ch;
                i++;
                continue;
            }
            if (ch === "(" || ch === "[" || ch === "{") {
                depth++;
                cur += ch;
                i++;
                continue;
            }
            if (ch === ")" || ch === "]" || ch === "}") {
                if (ch === ")" && depth === 1) {
                    args.push(cur);
                    closed = true;
                    i++;
                    break;
                }
                depth--;
                cur += ch;
                i++;
                continue;
            }
            if (ch === "," && depth === 1) {
                args.push(cur);
                cur = "";
                i++;
                continue;
            }
            cur += ch;
            i++;
        }
        if (!closed)
            continue;
        const isKwarg = (arg) => /^\s*[A-Za-z_]\w*\s*=/.test(arg);
        const positional = dotted ? [args[0], args[1]] : [args[1]];
        for (const arg of positional) {
            if (arg === undefined || isKwarg(arg))
                continue;
            if (hasWriteLiteral(arg))
                return true;
        }
        for (const arg of args) {
            const kw = /^\s*mode\s*=\s*([\s\S]*?)\s*$/.exec(arg);
            if (kw && hasWriteLiteral(kw[1]))
                return true;
        }
    }
    return false;
}
const EDIT_INTENT = [
    {
        name: "os.open() with write flags",
        re: /\bos\.open\s*\(\s*[^,]+,[^)]*O_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)/,
    },
    { name: ".write()/.writelines() call", re: /\.write(?:lines|bytes|text)?\s*\(/ },
    { name: ".write_text()/.write_bytes() call", re: /\.write_(?:text|bytes)\s*\(/ },
    { name: "print(..., file=...)", re: /\bprint\s*\([^)]*\bfile\s*=/ },
    { name: "sys.stdout/sys.stderr reassignment", re: /\bsys\.(?:stdout|stderr)\s*=\s*(?!sys\.)/ },
    { name: "serializing into a file object", re: /\b(?:json\.dump|pickle\.dump|yaml\.dump|csv\.writer)\s*\(/ },
    {
        name: "filesystem mutation",
        re: /\bos\.(?:remove|unlink|rmdir|removedirs|rename|replace|mkdir|makedirs|truncate|chmod|chown|chgrp|lchown|link|symlink|utime|chflags)\s*\(/,
    },
    { name: "shutil call", re: /\bshutil\.\w+\s*\(/ },
    {
        name: "pathlib mutation",
        re: /\.unlink\s*\(|\.rmdir\s*\(|\.touch\s*\(|\.rename\s*\(|\.symlink_to\s*\(|\.mkdir\s*\(|\.chmod\s*\(/,
    },
    {
        name: "tempfile written in place",
        re: /\btempfile\.\w+\s*\([^)]*\)\s*(?:\.\w+\s*\(|as\s+\w+)|os\.fdopen\s*\(/,
    },
];
const PROCESS_RE = /\b(?:subprocess\.\w+|os\.system|os\.popen|pty\.spawn|commands\.getoutput)\s*\(/;
const MUTATOR_RE = /\b(?:rm|rmdir|mv|cp|dd|truncate|chmod|chown|chgrp|unlink|touch|install|shred|tee)\b|\bsed\s*[,\s]\s*-i|\btar\s+-x|\bgit\s+(?:apply|checkout|reset|clean)\b|>>?/;
/** remove code that writes to the terminal so it cannot look like a file write */
function stripConsoleWrites(code) {
    return code
        .replace(/\bsys\.(?:stdout|stderr)\.write(?:lines)?\s*\(/g, "console_write(")
        .replace(/\bsys\.(?:stdout|stderr)\s*=\s*(?!sys\.)/g, "console_stream = None")
        .replace(/\bprint\s*\(([^)]*)\)/g, (match, inner) => {
        const target = /\bfile\s*=\s*([A-Za-z_][\w.]*)/.exec(inner);
        if (!target)
            return "console_print()";
        if (/^sys\.(?:stdout|stderr)$/.test(target[1]))
            return "console_print()";
        return match;
    });
}
export function scanCode(code) {
    if (!code.trim())
        return null;
    const normalized = stripConsoleWrites(code);
    if (hasOpenWrite(normalized))
        return "open() in a writing mode";
    for (const { name, re } of EDIT_INTENT) {
        if (re.test(normalized))
            return name;
    }
    // ['sed', '-i', 'f'] -> sed,-i,f so argv-shaped literals are still matched
    const collapsed = normalized.replace(/(['"])\s*,\s*\1/g, ",");
    if (PROCESS_RE.test(collapsed) && MUTATOR_RE.test(collapsed)) {
        return "shelling out to a mutating command";
    }
    return null;
}
function excerpt(code) {
    const line = code
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l.length > 0);
    const text = (line ?? "").replace(/\s+/g, " ");
    return text.length > 160 ? text.slice(0, 157) + "..." : text;
}
export function detect(command) {
    if (!command)
        return null;
    const mentionsPython = /python|\bpy\b|pypy/i.test(command);
    const mentionsSed = /\b(?:g?sed)\b/i.test(command);
    if (!mentionsPython && !mentionsSed)
        return null;
    const segments = splitCommand(command);
    if (mentionsSed) {
        for (const segment of segments) {
            const flag = findInPlaceFlag(segment.argv);
            if (!flag)
                continue;
            const invocation = segment.raw || segment.argv.join(" ");
            return {
                reason: `in-place replacement (${flag})`,
                invocation,
                excerpt: excerpt(invocation),
                via: "in-place-sed",
            };
        }
    }
    if (!mentionsPython)
        return null;
    const created = collectCreatedFiles(segments);
    for (let i = 0; i < segments.length; i++) {
        const segment = segments[i];
        if (findPythonIndex(segment.argv) < 0)
            continue;
        const payload = classify(segment, created, segments[i - 1]);
        if (payload.kind === "allow")
            continue;
        const reason = scanCode(payload.code);
        if (!reason)
            continue;
        return {
            reason,
            invocation: segment.raw || segment.argv.join(" "),
            excerpt: excerpt(payload.code),
            via: payload.via,
        };
    }
    return null;
}
