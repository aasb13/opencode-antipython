import Antipython from "./dist/index.js"

const hooks = {}
const ctx = {
  location: { directory: "/test" },
  app: { version: "2.0.18" },
  tool: {
    hook: async (name, cb) => {
      hooks[name] = cb
      return { dispose: async () => {} }
    },
  },
}

await Antipython.setup(ctx)
console.log("hook registered:", Object.keys(hooks))
console.log("plugin id:", Antipython.id)

const fire = (tool, input) =>
  hooks["execute.before"]({ tool, input, sessionID: "ses_test", agent: "build" })

const cases = [
  ["shell", { command: `python3 -c "open('/tmp/x.txt','w').write('pwned')"` }, "BLOCK (inline -c write)"],
  ["shell", { command: `cat > f.py <<'EOF'\nopen('a.txt','w').write('x')\nEOF\npython3 f.py` }, "BLOCK (generated script)"],
  ["shell", { command: `node -e "require('fs').writeFileSync('a.txt','pwned')"` }, "BLOCK (node -e write)"],
  ["shell", { command: `node <<'JS'\nfs.writeFileSync('a.txt','pwned')\nJS` }, "BLOCK (node heredoc)"],
  ["shell", { command: `printf "fs.writeFileSync('a','x')" | node` }, "BLOCK (node pipe stdin)"],
  ["shell", { command: `node script.js` }, "ALLOW (real node script)"],
  ["shell", { command: `node -e "console.log(process.version)"` }, "ALLOW (node read only)"],
  ["shell", { command: `python3 -m pytest tests/` }, "ALLOW (module run)"],
  ["shell", { command: `python3 scripts/real.py` }, "ALLOW (real script)"],
  ["shell", { command: `python3 -c "print(open('f.txt').read())"` }, "ALLOW (read only)"],
  ["shell", { command: `ls -la && git status` }, "ALLOW (no python)"],
  ["shell", { command: `sed -i 's/a/b/' src/app.ts` }, "BLOCK (in-place sed)"],
  ["shell", { command: `sed -n '1,20p' src/app.ts` }, "ALLOW (sed read only)"],
  ["term_host_exec", { command: `python3 -c "import os; os.remove('z')"` }, "BLOCK (term host_exec)"],
  ["read", { filePath: "/etc/hosts" }, "ALLOW (unrelated tool)"],
]

let pass = 0,
  fail = 0
for (const [tool, input, label] of cases) {
  const expectBlock = label.startsWith("BLOCK")
  let blocked = false,
    msg = ""
  try {
    await fire(tool, input)
  } catch (e) {
    blocked = true
    msg = String(e.message || e).split("\n")[0]
  }
  const ok = blocked === expectBlock
  ok ? pass++ : fail++
  console.log(`${ok ? "PASS" : "FAIL"}  [${tool}] expect ${label} -> got ${blocked ? "BLOCKED" : "allowed"}`)
  if (ok && blocked) console.log(`        ${msg}`)
}

console.log(`\n${pass} pass, ${fail} fail`)
process.exit(fail === 0 ? 0 : 1)
