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
 */

export type Violation = {
  /** short human readable reason, shown in the error message */
  reason: string
  /** the interpreter invocation that triggered it */
  invocation: string
  /** the offending code, trimmed for the error message */
  excerpt: string
  /** how the code reached the interpreter */
  via: "inline-c" | "heredoc-stdin" | "pipe-stdin" | "here-string" | "generated-script"
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
])

export function findPythonIndex(argv: string[]): number {
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) continue
    if (!isPythonBinary(word)) continue
    // everything before the interpreter must be a benign prefix
    let ok = true
    for (let j = 0; j < i; j++) {
      const prev = argv[j]!
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(prev)) continue
      if (RUNNERS.has(basename(prev)) || RUNNERS.has(prev)) continue
      if (/^-(?:[a-z]*n)?\d+$/.test(prev)) continue
      if (prev === "--") continue
      ok = false
      break
    }
    if (ok) return i
  }
  return -1
}

type Payload =
  | { kind: "allow"; why: string }
  | { kind: "inline"; code: string; via: Violation["via"] }

/** .py files the shell part of the command creates, with their inline content */
function collectCreatedFiles(segments: Segment[]): Map<string, { content: string }> {
  const created = new Map<string, { content: string }>()
  const record = (path: string, content: string) => {
    const target = path.replace(/^["']|["']$/g, "").trim()
    if (!target || !/\.pyw?$/i.test(target)) return
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

function stripQuotes(word: string): string {
  const first = word[0]
  if ((first === '"' || first === "'") && word.length > 1 && word.endsWith(first)) {
    return word.slice(1, -1)
  }
  return word
}

const EDIT_INTENT: { name: string; re: RegExp }[] = [
  { name: "open() in a writing mode", re: /\bopen\s*\(\s*[^)]*?,\s*['"][^'"]*[waxb+][^'"]*['"]/ },
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
  if (!command || !/python|\bpy\b|pypy/i.test(command)) return null
  const segments = splitCommand(command)
  const created = collectCreatedFiles(segments)

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!
    if (findPythonIndex(segment.argv) < 0) continue
    const payload = classify(segment, created, segments[i - 1])
    if (payload.kind === "allow") continue
    const reason = scanCode(payload.code)
    if (!reason) continue
    return {
      reason,
      invocation: segment.raw || segment.argv.join(" "),
      excerpt: excerpt(payload.code),
      via: payload.via,
    }
  }
  return null
}
