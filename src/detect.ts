/**
 * antipython - detect attempts to mutate files through an interpreter.
 *
 * The policy: an interpreter must never be the thing that writes a file during
 * agent work. Use the edit/write tools instead. What IS allowed is running real
 * scripts and normal module invocations (pytest, pip, node script.js, ...).
 *
 * Python and Node share the same shape of misuse, so they share the pipeline:
 *
 *   1. splitCommand  - quote/heredoc aware shell splitter
 *   2. findPython/findNode - locate interpreter invocations in each segment
 *   3. classify      - decide whether the payload is a real script, a module
 *                      run, or inline code authored by the model
 *   4. scanCode      - regex edit-intent scan over inline code
 *
 * The same policy covers `sed -i`: any in-place rewrite of a file is off
 * limits, not just the ones routed through an interpreter.
 */

export type Violation = {
  /** short human readable reason, shown in the error message */
  reason: string
  /** which runtime the payload ran under; `sed` is its own in-place rewriter */
  runtime: "python" | "node" | "sed"
  /** the interpreter invocation that triggered it */
  invocation: string
  /** the offending code, trimmed for the error message */
  excerpt: string
  /** how the code reached the interpreter */
  via:
    | "inline-c"
    | "inline-eval"
    | "heredoc-stdin"
    | "pipe-stdin"
    | "here-string"
    | "generated-script"
    | "in-place-sed"
}

export type Segment = {
  argv: string[]
  redirects: Redirect[]
  heredocs: Heredoc[]
  raw: string
  /** true when this segment's stdin comes from a pipe */
  piped: boolean
}

type Redirect = { op: string; target: string }
type Heredoc = { delim: string; body: string }

const REDIRECT_TWO_CHAR = [">>", "&>>", "<<", "<&", ">&", ">|", "<>"]
const REDIRECT_ONE_CHAR = new Set([">", "<"])
const SEPARATOR_TWO_CHAR = ["&&", "||", ";;", "|&"]
const SEPARATOR_ONE_CHAR = new Set([";", "|", "&", "\n", "(", ")", "{", "}"])

/** Python flags that consume the following argv entry as a value. */
const PYTHON_VALUED_FLAGS = new Set(["-c", "-m", "-W", "-X", "--command", "--module"])

export function splitCommand(command: string): Segment[] {
  const segments: Segment[] = []
  let argv: string[] = []
  let redirects: Redirect[] = []
  let heredocs: Heredoc[] = []
  let raw = ""
  let buf = ""
  let wordStarted = false
  let pendingRedirect: string | null = null
  let pendingHeredocs: string[] = []
  let pendingStrip = false
  let pipelined = false
  let quote: '"' | "'" | null = null
  let i = 0

  const endToken = () => {
    if (pendingRedirect) {
      redirects.push({ op: pendingRedirect, target: buf })
      pendingRedirect = null
    } else if (wordStarted && buf.length > 0) {
      argv.push(buf)
    } else if (wordStarted && buf.length === 0) {
      argv.push("")
    }
    buf = ""
    wordStarted = false
  }

  const endSegment = (piped: boolean) => {
    endToken()
    if (argv.length > 0 || redirects.length > 0 || heredocs.length > 0) {
      segments.push({ argv, redirects, heredocs, raw: raw.trim(), piped })
    }
    argv = []
    redirects = []
    heredocs = []
    raw = ""
    pendingHeredocs = []
    pendingStrip = false
  }

  const readHeredocBody = (delim: string, strip: boolean): string => {
    let body = ""
    for (;;) {
      const nl = command.indexOf("\n", i)
      const line = nl === -1 ? command.slice(i) : command.slice(i, nl)
      const candidate = strip ? line.replace(/^\t+/, "") : line
      if (candidate === delim) {
        i = nl === -1 ? command.length : nl + 1
        return body
      }
      body += line + "\n"
      if (nl === -1) {
        i = command.length
        return body
      }
      i = nl + 1
    }
  }

  while (i < command.length) {
    const ch = command[i]!

    // inside quotes: everything is literal content of the current word
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < command.length) {
        buf += command[i]! + command[i + 1]!
        raw += ch + command[i + 1]!
        i += 2
        continue
      }
      if (ch === quote) {
        buf += ch
        raw += ch
        quote = null
        i++
        continue
      }
      buf += ch
      raw += ch
      i++
      continue
    }

    if (ch === "\\" && i + 1 < command.length) {
      buf += command[i + 1]
      raw += ch + command[i + 1]!
      wordStarted = true
      i += 2
      continue
    }

    if (ch === "'" || ch === '"') {
      quote = ch
      buf += ch
      raw += ch
      wordStarted = true
      i++
      continue
    }

    if (ch === "$" && command[i + 1] === "(") {
      // command substitution: the inner text is scanned as its own segment
      endToken()
      raw += "$( "
      i += 2
      continue
    }

    if (ch === " " || ch === "\t") {
      if (!pendingRedirect) endToken()
      raw += ch
      i++
      continue
    }

    // here-string: <<< word
    if (ch === "<" && command[i + 1] === "<" && command[i + 2] === "<") {
      endToken()
      pendingRedirect = "<<<"
      wordStarted = true
      raw += "<<<"
      i += 3
      continue
    }

    // heredoc: << delim / <<- delim
    if (ch === "<" && command[i + 1] === "<") {
      const head = /^<<(-?)[ \t]*/.exec(command.slice(i))!
      let j = i + head[0].length
      let delim = ""
      while (j < command.length && !/[\s;|<>&()]/.test(command[j]!)) {
        delim += command[j]
        j++
      }
      if (delim) {
        endToken()
        const cleanDelim = /^(['"])(.*)\1$/.exec(delim)?.[2] ?? delim
        pendingHeredocs.push(cleanDelim)
        pendingStrip = head[1] === "-"
        pendingRedirect = `<<${head[1]}${cleanDelim}`
        wordStarted = true
        raw += command.slice(i, j)
        i = j
        continue
      }
    }

    if (ch === ">" || ch === "<") {
      const two = command.slice(i, i + 2)
      const base = REDIRECT_TWO_CHAR.includes(two) ? two : REDIRECT_ONE_CHAR.has(ch) ? ch : null
      if (base) {
        let fd = ""
        if (!pendingRedirect && !wordStarted && /^\d+$/.test(buf)) {
          fd = buf
          buf = ""
        }
        endToken()
        pendingRedirect = fd + base
        wordStarted = true
        raw += base
        i += base.length
        continue
      }
    }

    const twoSep = command.slice(i, i + 2)
    if (SEPARATOR_TWO_CHAR.includes(twoSep)) {
      endSegment(pipelined)
      pipelined = false
      raw += twoSep
      i += 2
      continue
    }

    if (SEPARATOR_ONE_CHAR.has(ch)) {
      if (ch === "\n") {
        // heredoc bodies for this line are consumed after the newline
        const nlPos = i
        endToken()
        const bodies: Heredoc[] = []
        for (const delim of pendingHeredocs) {
          bodies.push({ delim, body: readHeredocBody(delim, pendingStrip) })
        }
        if (argv.length > 0 || redirects.length > 0 || bodies.length > 0) {
          segments.push({ argv, redirects, heredocs: bodies, raw: raw.trim(), piped: pipelined })
        }
        argv = []
        redirects = []
        heredocs = []
        pendingHeredocs = []
        pendingStrip = false
        raw = ""
        pipelined = false
        i = nlPos + 1
        continue
      }
      const pipe = ch === "|"
      endSegment(pipelined)
      if (pipe) pipelined = true
      raw += ch
      i++
      continue
    }

    buf += ch
    raw += ch
    wordStarted = true
    i++
  }

  endSegment(pipelined)
  return segments
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
])

export function basename(word: string): string {
  const base = word.split("/").pop() ?? word
  return base.replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase()
}

export function isPythonBinary(word: string): boolean {
  const base = basename(word)
  if (PYTHON_BASENAMES.has(base)) return true
  return /^python(2|3)?(\.\d{1,2})?$/.test(base)
}

const NODE_BASENAMES = new Set(["node", "nodejs", "bun", "bunx", "deno"])

/** `eval` is deno's subcommand for evaluating a code string, not a script path */
const NODE_EVAL_SUBCOMMANDS = new Set(["eval"])

export function isNodeBinary(word: string): boolean {
  return NODE_BASENAMES.has(basename(word))
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
  "npm",
  "npx",
  "pnpm",
  "yarn",
  "bun",
  "bunx",
  "deno",
])

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
])

/** a count/duration value that belongs to a launcher: `timeout 5`, `nice 10` */
const NUMERIC_VALUE_RE = /^\d+(?:\.\d+)?[smhd]?$/i

/**
 * Must every word before the interpreter be a benign prefix for it to be the
 * command actually being run?
 *
 * Benign means: a runner (`sudo`, `uv run`, `npm exec`), an env assignment, a
 * shell control word, or an option together with its value (`sudo -u deploy`,
 * `timeout -s KILL 5`). A bare word with no flag or runner in front of it means
 * something else owns the pipeline, so what follows is its argument, not a
 * command: `echo python3 -c "..."` is text being printed.
 */
export function benignPrefix(argv: string[], index: number): boolean {
  let expectValue = false
  for (let j = 0; j < index; j++) {
    const prev = argv[j]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(prev)) continue
    if (RUNNERS.has(basename(prev)) || RUNNERS.has(prev)) continue
    if (CONTROL_WORDS.has(prev)) continue
    if (prev === "--") continue
    if (prev.startsWith("-")) {
      expectValue = true
      continue
    }
    if (expectValue) {
      expectValue = false
      continue
    }
    if (NUMERIC_VALUE_RE.test(prev)) continue
    return false
  }
  return true
}

export function findPythonIndex(argv: string[]): number {
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) continue
    if (!isPythonBinary(word)) continue
    if (benignPrefix(argv, i)) return i
  }
  return -1
}

type Payload =
  | { kind: "allow"; why: string }
  | { kind: "inline"; code: string; via: Violation["via"] }

/**
 * index of a node invocation, or -1. Same benign-prefix rule as
 * findPythonIndex: `npm exec -- node -e ...` must still be recognised, so the
 * runner words have been added to RUNNERS.
 */
export function findNodeIndex(argv: string[]): number {
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) continue
    if (!isNodeBinary(word)) continue
    if (!benignPrefix(argv, i)) continue
    // `bun run node -e ...`: the first node-family word is only a launcher
    // here, so a real interpreter further along owns the payload instead.
    const next = argv[i + 1]
    if (
      next !== undefined &&
      (RUNNERS.has(basename(next)) || RUNNERS.has(next)) &&
      argv.slice(i + 2).some((w) => isNodeBinary(w))
    ) {
      continue
    }
    return i
  }
  return -1
}

/** node/bun flags whose argument is the code to evaluate */
const NODE_EVAL_FLAGS = new Set(["-e", "--eval", "-p", "--print"])
/** node/bun flags whose value is the next argv entry, not a script path */
const NODE_VALUED_FLAGS = new Set([
  "-r",
  "--require",
  "-C",
  "--conditions",
  "--env-file",
  "--input-type",
  "--loader",
  "--experimental-loader",
  "--title",
  "--max-old-space-size",
  "--max-semi-space-size",
  "--stack-size",
  "--cpu-prof-dir",
  "--heap-prof-dir",
  "--diagnostic-dir",
  "--report-dir",
  "--redirect-warnings",
  "--snapshot-blob",
  "--policy-integrity",
])

/** script extensions a node-family runtime executes directly */
const NODE_SCRIPT_RE = /\.(?:js|mjs|cjs|jsx|ts|mts|cts)$/i

const SED_BASENAMES = new Set(["sed", "gsed"])

/**
 * launchers that hand the rest of their argv to sed: `xargs`, and the find
 * primaries (`-exec`/`-ok`, whose `rargs` companion may follow the command).
 */
const SED_LAUNCHERS = new Set(["xargs", "-exec", "-execdir", "-ok", "-okdir", "rargs"])

export function isSedBinary(word: string): boolean {
  return SED_BASENAMES.has(basename(word))
}

/**
 * index of a sed invocation, or -1. Mirrors findPythonIndex: everything before
 * the command word has to be a benign prefix (runner, env assignment, or a flag
 * of a launcher like `xargs -0`).
 */
export function findSedIndex(argv: string[]): number {
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) continue
    if (!isSedBinary(word)) continue
    // find's `find . -name x -exec sed ...` needs the launcher rule, not a
    // per-word allowlist: everything in between is find's own arguments.
    if (argv.slice(0, i).some((w) => SED_LAUNCHERS.has(w))) return i
    let ok = true
    for (let j = 0; j < i; j++) {
      const prev = argv[j]!
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(prev)) continue
      if (RUNNERS.has(basename(prev)) || RUNNERS.has(prev)) continue
      if (/^-[A-Za-z0-9][\w.-]*$/.test(prev)) continue
      if (CONTROL_WORDS.has(prev)) continue
      ok = false
      break
    }
    if (ok) return i
  }
  return -1
}

/**
 * Does this raw argv token switch sed to in-place mode?
 *
 * Matched against the unstripped token so a quoted word (`echo "sed -i"`) can
 * never look like a flag. `-i`, clustered flags like `-ni` / `-Ei`, the GNU
 * suffix form `-i.bak` and `--in-place` all count; `-f script` and
 * `-e expr` do not, since their value swallows the rest of the cluster.
 */
export function isInPlaceFlag(token: string): boolean {
  if (token === "--in-place" || token.startsWith("--in-place=")) return true
  if (!/^-[^-]/.test(token)) return false
  const cluster = token.slice(1).split(".")[0]!
  for (const ch of cluster) {
    if (ch === "i") return true
    if (ch === "f" || ch === "e" || ch === "s") return false
  }
  return false
}

/** the in-place flag of a sed segment, or null when it only reads */
function findInPlaceFlag(argv: string[]): string | null {
  const index = findSedIndex(argv)
  if (index < 0) return null
  for (let i = index + 1; i < argv.length; i++) {
    const token = argv[i]!
    if (token === "--") break
    if (isInPlaceFlag(token)) return token
  }
  return null
}

/** script files the shell part of the command creates, with their inline content */
function collectCreatedFiles(segments: Segment[]): Map<string, { content: string }> {
  const created = new Map<string, { content: string }>()
  const record = (path: string, content: string) => {
    const target = path.replace(/^["']|["']$/g, "").trim()
    if (!target || !/\.(?:pyw?|js|mjs|cjs|ts|mts|cts)$/i.test(target)) return
    const key = target.replace(/^\.\//, "")
    if (!created.has(key)) created.set(key, { content })
    const base = key.split("/").pop()!
    if (!created.has(base)) created.set(base, { content })
  }
  for (const segment of segments) {
    const heredoc = segment.heredocs[0]?.body ?? ""
    const producerWords = segment.argv.join(" ")
    for (const redirect of segment.redirects) {
      if (!redirect.op.includes(">")) continue
      if (redirect.op.includes("<<")) continue
      const target = redirect.target
      if (/^\d+$/.test(target) || target === "&-" || target.startsWith("&")) continue
      record(target, heredoc || producerWords)
    }
    if (segment.argv.some((a) => basename(a) === "tee")) {
      for (const arg of segment.argv) {
        if (basename(arg) === "tee" || arg.startsWith("-")) continue
        record(arg, heredoc || producerWords)
      }
    }
  }
  return created
}

function classify(segment: Segment, created: Map<string, { content: string }>, producer?: Segment): Payload {
  const index = findPythonIndex(segment.argv)
  if (index < 0) return { kind: "allow", why: "no interpreter" }
  const args = segment.argv.slice(index + 1)

  let sawStdinRedirect = false
  for (let k = 0; k < args.length; k++) {
    const token = stripQuotes(args[k]!)
    if (token === "-c" || token === "--command") {
      return { kind: "inline", code: stripQuotes(args[k + 1] ?? ""), via: "inline-c" }
    }
    if (token.startsWith("--command=")) {
      return { kind: "inline", code: stripQuotes(token.slice("--command=".length)), via: "inline-c" }
    }
    if (/^-c.+/.test(token)) {
      return { kind: "inline", code: stripQuotes(token.slice(2)), via: "inline-c" }
    }
    if (token === "-m" || token === "--module" || token.startsWith("--module=")) {
      return { kind: "allow", why: "module invocation" }
    }
    if (token === "-") {
      sawStdinRedirect = true
      continue
    }
    if (PYTHON_VALUED_FLAGS.has(token)) {
      k++
      continue
    }
    if (token.startsWith("-")) continue
    // first positional argument: a real script file
    if (/\.pyw?$/i.test(token)) {
      const key = token.replace(/^\.\//, "")
      const base = key.split("/").pop()!
      const authored = created.get(key) ?? created.get(base)
      if (authored && authored.content.trim()) {
        return { kind: "inline", code: authored.content, via: "generated-script" }
      }
      return { kind: "allow", why: "real script file" }
    }
    break
  }

  const hereString = segment.redirects.find((r) => r.op === "<<<")
  if (hereString) {
    return { kind: "inline", code: stripQuotes(hereString.target), via: "here-string" }
  }
  const heredoc = segment.heredocs[0]
  if (heredoc) {
    return { kind: "inline", code: heredoc.body, via: "heredoc-stdin" }
  }
  if (segment.piped && producer) {
    const piped = producer.argv.join(" ")
    if (looksLikePython(piped)) {
      return { kind: "inline", code: piped, via: "pipe-stdin" }
    }
    return { kind: "allow", why: "piped input is not a python program" }
  }
  if (sawStdinRedirect) {
    return { kind: "allow", why: "stdin redirected from an existing file" }
  }
  return { kind: "allow", why: "no inline code" }
}

/** Does the piped-in text look like a python program? */
function looksLikePython(code: string): boolean {
  return /\b(?:import|from)\s+\w|def\s+\w+\s*\(|print\s*\(|\bopen\s*\(|\w+\s*=/.test(code)
}

/** Does the piped-in text look like a javascript program? */
function looksLikeJS(code: string): boolean {
  return (
    /\b(?:require|import|export|const|let|var|function|class|async|await|return|console|process|module|Deno)\b|=>|\.\w+\s*\(/.test(
      code,
    )
  )
}

function stripQuotes(word: string): string {
  const first = word[0]
  if ((first === '"' || first === "'") && word.length > 1 && word.endsWith(first)) {
    return word.slice(1, -1)
  }
  return word
}

/**
 * Calls that mutate the filesystem.
 *
 * The write family is matched at identifier level, not call level: `fs['writeFileSync'](...)`
 * and `const w = fs.writeFileSync; w(...)` are the same act, and those identifiers
 * essentially never appear in javascript that does not write a file. Everything
 * else stays call-shaped, because a bare `rm` inside a string is not a deletion.
 */
const JS_MUTATIONS: { name: string; re: RegExp }[] = [
  {
    name: "fs write call (writeFile/appendFile/writeFileSync/createWriteStream)",
    re: /\b(?:writeFileSync|appendFileSync|writeFile|appendFile|createWriteStream)\b/,
  },
  {
    name: "fs removal (unlink/rm/rmdir)",
    re: /\b(?:fs|fsp|fs\.promises|fsExtra)\s*\.\s*(?:unlink|rm|rmdir|unlinkSync|rmSync|rmdirSync)\s*\(/,
  },
  { name: "destructured fs removal (unlinkSync/rmSync/rmdirSync)", re: /\b(?:unlinkSync|rmSync|rmdirSync)\s*\(/ },
  {
    name: "fs copy/rename (copyFile/rename/cp)",
    re: /\b(?:fs|fsp|fs\.promises|fsExtra)\s*\.\s*(?:copyFile|rename|cp|copyFileSync|renameSync|cpSync)\s*\(/,
  },
  {
    name: "destructured fs copy/rename (copyFileSync/renameSync)",
    re: /\b(?:copyFileSync|renameSync|cpSync)\s*\(/,
  },
  {
    name: "fs directory mutation (mkdir/mkdtemp)",
    re: /\b(?:fs|fsp|fs\.promises|fsExtra)\s*\.\s*(?:mkdir|mkdtemp|mkdirSync|mkdtempSync|ensureDirSync)\s*\(/,
  },
  { name: "destructured fs directory mutation (mkdirSync/mkdtempSync)", re: /\b(?:mkdirSync|mkdtempSync)\s*\(/ },
  {
    name: "fs metadata mutation (chmod/chown/truncate/link/symlink/utimes)",
    re: /\b(?:fs|fsp|fs\.promises|fsExtra)\s*\.\s*(?:chmod|chown|lchown|fchmod|fchown|truncate|ftruncate|utimes|futimes|link|symlink|chmodSync|chownSync|lchownSync|fchmodSync|fchownSync|truncateSync|ftruncateSync|utimesSync|futimesSync|linkSync|symlinkSync)\s*\(/,
  },
  {
    name: "destructured fs metadata mutation",
    re: /\b(?:chmodSync|chownSync|lchownSync|fchmodSync|fchownSync|truncateSync|ftruncateSync|utimesSync|futimesSync|linkSync|symlinkSync)\s*\(/,
  },
  {
    name: "Deno filesystem mutation",
    re: /\bDeno\s*\.\s*(?:writeFile|writeTextFile|writeFileSync|writeTextFileSync|remove|removeSync|mkdir|mkdirSync|rename|renameSync|copyFile|copyFileSync|chmod|chmodSync|truncate|truncateSync|symlink|symlinkSync)\s*\(/,
  },
  { name: "fs.open() with a write flag (O_WRONLY/O_CREAT/...)", re: /\bO_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)\b/ },
]

const JS_PROCESS_RE =
  /\b(?:execSync|execFileSync|spawnSync|fork|spawn)\s*\(|\b(?:child_process|node:child_process)\s*\.\s*(?:exec|execFile|spawn|execSync|execFileSync|spawnSync)\s*\(/

/** shell words that change the filesystem; `>`/`>>` only when not part of `=>` or `>=` */
const JS_MUTATOR_RE =
  /\b(?:rm|rmdir|mv|cp|dd|truncate|chmod|chown|chgrp|unlink|touch|install|shred|tee)\b|\bsed\b[^)]*-i\b|\btar\s+-x|\bgit\s+(?:apply|checkout|reset|clean)\b|(?:^|[^=])>>?(?![=>])/

/**
 * Edit-intent scan over javascript code.
 *
 * The write family is matched at identifier level, not call level: `fs['writeFileSync'](...)`
 * and `const w = fs.writeFileSync; w(...)` are the same act, and those identifiers
 * essentially never appear in javascript that does not write a file. Everything
 * else stays call-shaped, because a bare `rm` inside a string is not a deletion.
 */
export function scanNodeCode(code: string): string | null {
  if (!code.trim()) return null
  if (hasOpenWrite(code)) return "fs.open() in a writing mode"
  for (const { name, re } of JS_MUTATIONS) {
    if (re.test(code)) return name
  }
  const collapsed = code.replace(/(['"])\s*,\s*\1/g, ",")
  if (JS_PROCESS_RE.test(collapsed) && JS_MUTATOR_RE.test(collapsed)) {
    return "shelling out to a mutating command"
  }
  return null
}

/**
 * Decide whether the payload of a node invocation is inline code authored by
 * the model, or a real script the model is allowed to run.
 */
function classifyNode(segment: Segment, created: Map<string, { content: string }>, producer?: Segment): Payload {
  const index = findNodeIndex(segment.argv)
  if (index < 0) return { kind: "allow", why: "no interpreter" }
  const args = segment.argv.slice(index + 1)

  let sawStdinRedirect = false
  for (let k = 0; k < args.length; k++) {
    const token = stripQuotes(args[k]!)
    if (NODE_EVAL_FLAGS.has(token)) {
      return { kind: "inline", code: stripQuotes(args[k + 1] ?? ""), via: "inline-eval" }
    }
    if (token.startsWith("--eval=")) {
      return { kind: "inline", code: stripQuotes(token.slice("--eval=".length)), via: "inline-eval" }
    }
    if (token.startsWith("--print=")) {
      return { kind: "inline", code: stripQuotes(token.slice("--print=".length)), via: "inline-eval" }
    }
    if (/^-[ep].+/.test(token)) {
      return { kind: "inline", code: stripQuotes(token.slice(2)), via: "inline-eval" }
    }
    if (token.startsWith("--") && token.includes("=")) continue
    if (NODE_VALUED_FLAGS.has(token)) {
      k++
      continue
    }
    if (token === "-") {
      sawStdinRedirect = true
      continue
    }
    if (token.startsWith("-")) continue
    // `deno eval <code>` is deno's evaluate subcommand, not a script path
    if (NODE_EVAL_SUBCOMMANDS.has(token) && basename(segment.argv[index]!) === "deno") {
      const value = args.slice(k + 1).find((t) => !t.startsWith("-"))
      if (value === undefined) return { kind: "allow", why: "eval without a code argument" }
      return { kind: "inline", code: stripQuotes(value), via: "inline-eval" }
    }
    // first positional argument: a real script file
    if (NODE_SCRIPT_RE.test(token)) {
      const key = token.replace(/^\.\//, "")
      const base = key.split("/").pop()!
      const authored = created.get(key) ?? created.get(base)
      if (authored && authored.content.trim()) {
        return { kind: "inline", code: authored.content, via: "generated-script" }
      }
    }
    return { kind: "allow", why: "real script file" }
  }

  const hereString = segment.redirects.find((r) => r.op === "<<<")
  if (hereString) {
    return { kind: "inline", code: stripQuotes(hereString.target), via: "here-string" }
  }
  const heredoc = segment.heredocs[0]
  if (heredoc) {
    return { kind: "inline", code: heredoc.body, via: "heredoc-stdin" }
  }
  if (segment.piped && producer) {
    const piped = producer.argv.join(" ")
    if (looksLikeJS(piped)) {
      return { kind: "inline", code: piped, via: "pipe-stdin" }
    }
    return { kind: "allow", why: "piped input is not a javascript program" }
  }
  if (sawStdinRedirect) {
    return { kind: "allow", why: "stdin redirected from an existing file" }
  }
  return { kind: "allow", why: "no inline code" }
}

/**
 * Does a file-mode string grant write access? Only `w`, `x`, `a` and `+`
 * do; `r`, `b`, `t` and `U` alone are read-only. The charset guard keeps
 * non-mode strings (paths, encodings like `utf-8`/`latin-1`) from matching.
 */
function isWriteMode(mode: string): boolean {
  if (!/^[rwxaUbt+]+$/.test(mode)) return false
  return /[wax+]/.test(mode)
}

/**
 * True when any quoted literal inside the text is a file mode granting
 * write access. Scans literals rather than the whole argument so a dynamic
 * mode (`'w' if x else 'r'`) still blocks while `encoding='latin-1'` (not
 * in the mode position) is never even examined.
 */
function hasWriteLiteral(text: string): boolean {
  const re = /"([^"]*)"|'([^']*)'/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (isWriteMode(m[1] ?? m[2] ?? "")) return true
  }
  return false
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
function hasOpenWrite(code: string): boolean {
  const re = /(\.)?\b(?:open|openSync)\s*\(/g
  let m: RegExpExecArray | null
  while ((m = re.exec(code)) !== null) {
    const dotted = m[1] === "."
    let i = m.index + m[0].length
    let depth = 1
    let quote: string | null = null
    let cur = ""
    const args: string[] = []
    let closed = false
    while (i < code.length) {
      const ch = code[i]!
      if (quote) {
        cur += ch
        if (ch === "\\" && i + 1 < code.length) {
          cur += code[i + 1]
          i += 2
          continue
        }
        if (ch === quote) quote = null
        i++
        continue
      }
      if (ch === '"' || ch === "'") {
        quote = ch
        cur += ch
        i++
        continue
      }
      if (ch === "(" || ch === "[" || ch === "{") {
        depth++
        cur += ch
        i++
        continue
      }
      if (ch === ")" || ch === "]" || ch === "}") {
        if (ch === ")" && depth === 1) {
          args.push(cur)
          closed = true
          i++
          break
        }
        depth--
        cur += ch
        i++
        continue
      }
      if (ch === "," && depth === 1) {
        args.push(cur)
        cur = ""
        i++
        continue
      }
      cur += ch
      i++
    }
    if (!closed) continue
    const isKwarg = (arg: string): boolean => /^\s*[A-Za-z_]\w*\s*=/.test(arg)
    const positional = dotted ? [args[0], args[1]] : [args[1]]
    for (const arg of positional) {
      if (arg === undefined || isKwarg(arg)) continue
      if (hasWriteLiteral(arg)) return true
    }
    for (const arg of args) {
      const kw = /^\s*mode\s*=\s*([\s\S]*?)\s*$/.exec(arg)
      if (kw && hasWriteLiteral(kw[1]!)) return true
    }
  }
  return false
}

const EDIT_INTENT: { name: string; re: RegExp }[] = [
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
]

const PROCESS_RE = /\b(?:subprocess\.\w+|os\.system|os\.popen|pty\.spawn|commands\.getoutput)\s*\(/
const MUTATOR_RE =
  /\b(?:rm|rmdir|mv|cp|dd|truncate|chmod|chown|chgrp|unlink|touch|install|shred|tee)\b|\bsed\s*[,\s]\s*-i|\btar\s+-x|\bgit\s+(?:apply|checkout|reset|clean)\b|>>?/

/** remove code that writes to the terminal so it cannot look like a file write */
function stripConsoleWrites(code: string): string {
  return code
    .replace(/\bsys\.(?:stdout|stderr)\.write(?:lines)?\s*\(/g, "console_write(")
    .replace(/\bsys\.(?:stdout|stderr)\s*=\s*(?!sys\.)/g, "console_stream = None")
    .replace(/\bprint\s*\(([^)]*)\)/g, (match, inner: string) => {
      const target = /\bfile\s*=\s*([A-Za-z_][\w.]*)/.exec(inner)
      if (!target) return "console_print()"
      if (/^sys\.(?:stdout|stderr)$/.test(target[1]!)) return "console_print()"
      return match
    })
}

export function scanCode(code: string): string | null {
  if (!code.trim()) return null
  const normalized = stripConsoleWrites(code)
  if (hasOpenWrite(normalized)) return "open() in a writing mode"
  for (const { name, re } of EDIT_INTENT) {
    if (re.test(normalized)) return name
  }
  // ['sed', '-i', 'f'] -> sed,-i,f so argv-shaped literals are still matched
  const collapsed = normalized.replace(/(['"])\s*,\s*\1/g, ",")
  if (PROCESS_RE.test(collapsed) && MUTATOR_RE.test(collapsed)) {
    return "shelling out to a mutating command"
  }
  return null
}

function excerpt(code: string): string {
  const line = code
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.length > 0)
  const text = (line ?? "").replace(/\s+/g, " ")
  return text.length > 160 ? text.slice(0, 157) + "..." : text
}

export function detect(command: string): Violation | null {
  if (!command) return null
  const mentionsPython = /python|\bpy\b|pypy/i.test(command)
  const mentionsSed = /\b(?:g?sed)\b/i.test(command)
  const mentionsNode = /\b(?:node|nodejs|bun|bunx|deno)\b/i.test(command)
  if (!mentionsPython && !mentionsSed && !mentionsNode) return null
  const segments = splitCommand(command)

  if (mentionsSed) {
    for (const segment of segments) {
      const flag = findInPlaceFlag(segment.argv)
      if (!flag) continue
      const invocation = segment.raw || segment.argv.join(" ")
      return {
        reason: `in-place replacement (${flag})`,
        runtime: "sed",
        invocation,
        excerpt: excerpt(invocation),
        via: "in-place-sed",
      }
    }
  }

  const created = collectCreatedFiles(segments)

  if (mentionsNode) {
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i]!
      if (findNodeIndex(segment.argv) < 0) continue
      const payload = classifyNode(segment, created, segments[i - 1])
      if (payload.kind === "allow") continue
      const reason = scanNodeCode(payload.code)
      if (!reason) continue
      return {
        reason,
        runtime: "node",
        invocation: segment.raw || segment.argv.join(" "),
        excerpt: excerpt(payload.code),
        via: payload.via,
      }
    }
  }

  if (!mentionsPython) return null

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!
    if (findPythonIndex(segment.argv) < 0) continue
    const payload = classify(segment, created, segments[i - 1])
    if (payload.kind === "allow") continue
    const reason = scanCode(payload.code)
    if (!reason) continue
    return {
      reason,
      runtime: "python",
      invocation: segment.raw || segment.argv.join(" "),
      excerpt: excerpt(payload.code),
      via: payload.via,
    }
  }
  return null
}
