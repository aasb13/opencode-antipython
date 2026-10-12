import { describe, expect, test } from "bun:test"
import { detect, isInPlaceFlag, splitCommand } from "./detect.js"

const blocked: [string, string][] = [
  ["inline -c open for write", `python3 -c "open('a.txt','w').write('x')"`],
  ["inline -c attached", `python3 -c"open('a.txt','w').write('x')"`],
  ["write_text", `python3 -c "import pathlib; pathlib.Path('a.txt').write_text('x')"`],
  ["print to file", `python3 -c "print('hi', file=open('a.txt','a'))"`],
  ["os.remove", `python3 -c "import os; os.remove('a.txt')"`],
  ["shutil", `python -c "import shutil; shutil.rmtree('build')"`],
  ["subprocess sed -i", `python3 -c "import subprocess; subprocess.run(['sed','-i','s/a/b/','f.txt'])"`],
  ["os.system rm", `python3 -c "import os; os.system('rm -rf build')"`],
  [
    "heredoc stdin",
    "python3 <<'PY'\nimport os\nos.rename('a', 'b')\nPY",
  ],
  [
    "heredoc with open",
    "python3 - <<EOF\nwith open('src/app.ts','w') as f:\n    f.write(data)\nEOF",
  ],
  ["here string", `python3 <<< "open('x','w')"`],
  ["pipe stdin", `printf 'open("a.txt","w")' | python3`],
  [
    "generated script then run",
    "cat > fix.py <<'PY'\nimport os\nos.remove('tmp')\nPY\npython3 fix.py",
  ],
  [
    "generated script via tee",
    "tee gen.py >/dev/null <<'PY'\nfrom pathlib import Path\nPath('a').unlink()\nPY\npython3 ./gen.py",
  ],
  ["env wrapper", `env FOO=1 python3 -c "import shutil; shutil.copy('a','b')"`],
  ["exec wrapper", `python3.12 -c "open('a','w').close()"`],
  ["uv run", `uv run python -c "open('a.txt','w')"`],
  ["stdin heredoc multiline chain", `cd /tmp && python3 - <<'PY'\nimport os\nos.mkdir('x')\nPY`],
  [
    "write_bytes",
    `python3 -c "from pathlib import Path; Path('a.bin').write_bytes(b'x')"`,
  ],
  [
    "sudo wrapped",
    `sudo python3 - <<'PY'\nopen('/etc/hosts','a').write('x')\nPY`,
  ],
  [
    "python inside command substitution",
    `diff <(python3 -c "import os; os.remove('a')") <(python3 -c "print('b')")`,
  ],
  [
    "multiline command with heredoc in the middle",
    "set -e\npython3 - <<'PY'\nimport shutil\nshutil.rmtree('dist')\nPY\necho done",
  ],
  [
    "env prefix before interpreter",
    `PYTHONPATH=. python3 -c "import shutil; shutil.move('a','b')"`,
  ],
  ["sed -i", `sed -i 's/foo/bar/' src/app.ts`],
  ["sed -i with backup suffix", `sed -i.bak 's/foo/bar/' src/app.ts`],
  ["sed clustered flags", `sed -ni 's/foo/bar/p' src/app.ts`],
  ["sed --in-place", `sed --in-place 's/foo/bar/' src/app.ts`],
  ["sed via absolute path", `/usr/bin/sed -i 's/a/b/' f.txt`],
  ["sed under sudo", `sudo sed -i 's/a/b/' /etc/hosts`],
  ["sed under xargs", `printf 'a\\nb\\n' | xargs sed -i 's/a/b/'`],
  ["sed under find -exec", `find . -name '*.tmp' -exec sed -i '' 's/a/b/' {} +`],
  ["sed -i in a chained command", `cd app && sed -i 's/a/b/' f.txt && echo done`],
  ["sed -i inside command substitution", `diff <(sed -i 's/a/b/' f.txt) f.txt.orig`],
  ["sed -i in a subshell", `(sed -i 's/a/b/' f.txt)`],
  ["sed -i after a python script run", `python3 build.py && sed -i 's/a/b/' out.py`],
  ["sed -i in a for loop body", `for f in *.ts; do sed -i 's/a/b/' "$f"; done`],
  ["sed -i in an if branch", `if grep -q x f; then sed -i 's/a/b/' f; fi`],
  ["sed -i in a while body", `while read -r f; do sed -i 's/a/b/' "$f"; done < list.txt`],
  ["sed -i in a background job", `sed -i 's/a/b/' f.txt &`],
  ["python inside a loop body", `for f in *.py; do python3 -c "open('a','w')"; done`],
  ["binary write", `python3 -c "open('a.bin','wb').write(b'x')"`],
  ["mode kwarg", `python3 -c "open('a.txt', mode='w').write('x')"`],
  ["pathlib open for write", `python3 -c "import pathlib; pathlib.Path('a').open('w').write('x')"`],
  ["node -e writeFileSync", `node -e "require('fs').writeFileSync('a.txt','x')"`],
  ["node -e with fs require inline", `node -e "const fs = require('fs'); fs.writeFileSync('a.txt','x')"`],
  ["node --eval=", `node --eval="fs.writeFileSync('a.txt','x')"`],
  ["node -p print and write", `node -p "fs.writeFileSync('a.txt','x')"`],
  ["node attached -e", `node -e"fs.writeFileSync('a.txt','x')"`],
  ["node appendFileSync", `node -e "fs.appendFileSync('a.txt','x')"`],
  ["node createWriteStream", `node -e "fs.createWriteStream('a.txt').write('x')"`],
  ["node destructured writeFileSync", `node -e "const { writeFileSync } = require('fs'); writeFileSync('a.txt','x')"`],
  ["node rmSync", `node -e "fs.rmSync('build', { recursive: true })"`],
  ["node unlinkSync", `node -e "fs.unlinkSync('a.txt')"`],
  ["node copyFileSync", `node -e "fs.copyFileSync('a.txt','b.txt')"`],
  ["node renameSync", `node -e "fs.renameSync('a.txt','b.txt')"`],
  ["node mkdirSync", `node -e "fs.mkdirSync('x')"`],
  ["node chmodSync", `node -e "fs.chmodSync('a.txt', 0o755)"`],
  ["node openSync write mode", `node -e "fs.openSync('a.txt','w')"`],
  ["node fs.open write flag", `node -e "fs.open('a.txt', fs.constants.O_CREAT | fs.constants.O_WRONLY)"`],
  ["node fs.promises writeFile", `node -e "const fsp = require('fs/promises'); fsp.writeFile('a.txt','x')"`],
  [
    "node heredoc stdin",
    "node <<'JS'\nconst fs = require('fs')\nfs.writeFileSync('a.txt','x')\nJS",
  ],
  ["node heredoc with stdin dash", "node - <<'JS'\nfs.rmSync('build', { recursive: true })\nJS"],
  ["node here-string", `node <<< "fs.writeFileSync('a.txt','x')"`],
  ["node pipe stdin", `printf "fs.writeFileSync('a.txt','x')" | node`],
  [
    "node generated script then run",
    "cat > fix.js <<'JS'\nconst fs = require('fs')\nfs.rmSync('tmp', { recursive: true })\nJS\nnode fix.js",
  ],
  ["node generated .mjs script", "cat > patch.mjs <<'JS'\nfs.writeFileSync('a.txt','x')\nJS\nnode ./patch.mjs"],
  ["node execSync rm", `node -e "require('child_process').execSync('rm -rf build')"`],
  ["node execSync sed -i", `node -e "execSync('sed -i s/a/b/ src/app.ts')"`],  ["node spawnSync mv", `node -e "spawnSync('mv', ['a.txt','b.txt'])"`],
  ["node execSync redirect", `node -e "execSync('cat a.txt > b.txt')"`],
  ["node input-type module", `node --input-type=module -e "import fs from 'node:fs'; fs.writeFileSync('a.txt','x')"`],
  ["node require hook then eval", `node -r ./patch.js -e "fs.writeFileSync('a.txt','x')"`],
  ["bun -e writeFileSync", `bun -e "fs.writeFileSync('a.txt','x')"`],
  ["node under sudo", `sudo node -e "fs.writeFileSync('/etc/x.conf','x')"`],
  ["node under env prefix", `NODE_ENV=test node -e "fs.writeFileSync('a.txt','x')"`],
  ["node inside a loop body", `for f in *.ts; do node -e "fs.writeFileSync(process.argv[1],'x')" "$f"; done`],
  ["node inside command substitution", `diff <(node -e "fs.writeFileSync('a.txt','x')") <(node -e "console.log(1)")`],
  [
    "npm exec node -e",
    `npm exec -- node -e "fs.writeFileSync('a.txt','x')"`,
  ],
  ["deno eval writeTextFileSync", `deno eval "Deno.writeTextFileSync('a.txt','x')"`],
  ["deno eval await Deno.writeFile", `deno eval "await Deno.writeFile('a.txt', new Uint8Array([1]))"`],
  ["npx node -e", `npx node -e "fs.writeFileSync('a.txt','x')"`],
  ["sudo -u deploy node -e", `sudo -u deploy node -e "fs.writeFileSync('/srv/x','y')"`],
  ["timeout then node -e", `timeout 5 node -e "fs.writeFileSync('a.txt','x')"`],
  ["timeout with signal then node -e", `timeout -s KILL 5 node -e "fs.writeFileSync('a.txt','x')"`],
  ["sudo -u deploy python3", `sudo -u deploy python3 -c "import os; os.remove('a.txt')"`],
  ["timeout then python3", `timeout 5 python3 -c "import shutil; shutil.rmtree('build')"`],
  ["node bracket access writer", `node -e "fs['writeFileSync']('a.txt','x')"`],
  ["node aliased writer", `node -e "const w = fs.writeFileSync; w('a.txt','x')"`],
  ["bun run node -e", `bun run node -e "fs.writeFileSync('a.txt','x')"`],
  ["deno run node -e", `deno run node -e "fs.writeFileSync('a.txt','x')"`],
  ["uv run node -e", `uv run node -e "fs.writeFileSync('a.txt','x')"`],
  ["node spawn sh -c rm", `node -e "spawn('sh', ['-c', 'rm -rf build'])"`],
  ["node chmodSync", `node -e "fs.chmodSync('a.txt', 0o755)"`],
  ["node symlinkSync", `node -e "fs.symlinkSync('a.txt','b.txt')"`],
  ["node truncateSync", `node -e "fs.truncateSync('a.txt', 0)"`],
]

const allowed: string[] = [
  `python3 -c "print(1)"`,
  `python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))"`,
  `python3 script.py`,
  `python3 tests/test_thing.py --verbose`,
  `python -m pytest -q`,
  `python3 -m venv .venv && .venv/bin/pip install -e .`,
  `python3 -m build`,
  `python3 -m json.tool package.json`,
  `uv run pytest`,
  `poetry run python manage.py migrate`,
  `python3 -u -c "print('flags are fine')"`,
  `python3 -c "import sys; sys.stdout.write('to terminal')"`,
  `python3 -c "import sys; print('to terminal', file=sys.stdout)"`,
  `git show HEAD:app.py > old.py`,
  `python3 -m pip show ruff`,
  `python3 - <<'PY'\nimport sys\nprint(sum(int(x) for x in sys.stdin))\nPY`,
  `python3 -c "import json; d=json.load(open('a.json')); print(sum(d.values()))"`,
  `python3 read_config.py && python3 build_report.py --out r.html`,
  `echo "python3 -c \\"open('a','w')\\"" >> notes.md`,
  `python3 -c "import os; print(os.getcwd())"`,
  `which python3 && python3 --version`,
  `python3 -c "import configparser; c = configparser.ConfigParser(); print(sorted(c.sections()))"`,
  `python3 -c "import json; d = json.loads(open('a.json').read()); print(list(d))"`,
  `python3 -c "import sys; sys.stderr.write('warn\\n')"`,
  `cat notes.md | python3 -c "import sys; print(len(sys.stdin.read()))"`,
  `python3 analyze.py --report out.md`,
  `python3 -c "import pathlib; print(sorted(pathlib.Path('.').glob('*.py')))"`,
  `python3 -m mypy src`,
  `python3 -c "import os; print(os.listdir('.'))"`,
  `python3 - <<'PY'\nimport json\nprint(json.dumps({'a': 1}))\nPY`,
  `python3 -c "print(open('f.txt').read().upper())"`,
  `python3 -c "data = open('ConstantCipherTest.java','rb').read(); print(len(data))"`,
  `python3 -c "d = open('a.json', encoding='utf-8').read(); print(len(d))"`,
  `python3 -c "f = open('a.txt', mode='r'); print(f.read())"`,
  `python3 -c "import pathlib; print(pathlib.Path('a.txt').open('r').read())"`,
  `sed -n '1,20p' src/app.ts`,
  `sed -e 's/foo/bar/' f.txt | diff - f.txt`,
  `sed 's/foo/bar/g' README.md`,
  `sed -f cleanup.sed f.txt`,
  `grep -n 'foo' f.txt | sed 's/foo/bar/'`,
  `echo "run sed -i 's/a/b/' to edit in place" >> notes.md`,
  `sed --help`,
  `sed -n '/def main/,$p' src/detect.ts > head.ts`,
  `node script.js`,
  `node scripts/deploy.js --dry-run`,
  `node --version`,
  `node -v`,
  `node`,
  `node -e "console.log(process.version)"`,
  `node -e "console.log(process.argv.slice(2))"`,
  `node -e "const fs = require('fs'); console.log(fs.readFileSync('a.txt','utf8').length)"`,
  `node -e "console.log(require('os').cpus().length)"`,
  `node -p "1+1"`,
  `node -e "import('node:fs').then((m) => console.log(m.existsSync('a.txt')))"`,
  `node -e "const s = fs.readFileSync('a.txt'); console.log(s.toString().replace(/a/g,'b'))"`,
  `node --check script.js`,
  `node -r ./hook.js build.js`,
  `node --max-old-space-size=4096 script.js`,
  `node -e "console.log(JSON.parse(process.stdin.read()))"`,
  `node <<'JS'\nconsole.log(process.cwd())\nJS`,
  `cat notes.md | node -e "console.log(process.stdin.read().length)"`,
  `bun test`,
  `bun run build`,
  `bun install`,
  `bun x prettier --check .`,
  `npm run lint`,
  `npx tsc --noEmit`,
  `echo "node -e \\"fs.writeFileSync('a','x')\\"" >> notes.md`,
  `grep -rn "node" src/`,
  `node -e "console.log(path.basename(process.argv[1]))" script.js`,
  `cd app && node dist/main.js && echo done`,
  `deno run -A script.ts`,
  `deno test`,
  `deno check main.ts`,
  `deno eval "console.log(Deno.version.deno)"`,
  `deno eval "console.log(await Deno.readTextFile('a.txt').then((s) => s.length))"`,
  `npx prettier --write .`,
  `node -e "console.log(fs.readFileSync('a.txt','utf8').replace(/x/g,'y'))"`,
  `node -e "const { execSync } = require('child_process'); console.log(execSync('git status').toString())"`,
  `echo python3 -c "open('a','w')" >> notes.md`,
  `timeout 5 python3 script.py`,
  `sudo -u deploy python3 script.py`,
  `timeout -s KILL 5 bun test`,
  `sudo -u deploy bun run build`,
]

describe("blocked commands", () => {
  for (const [name, command] of blocked) {
    test(name, () => {
      const result = detect(command)
      expect(result, `expected a violation for: ${command}`).not.toBeNull()
      expect(result!.excerpt.length).toBeGreaterThan(0)
    })
  }
})

describe("allowed commands", () => {
  for (const command of allowed) {
    test(command, () => {
      expect(detect(command), `false positive for: ${command}`).toBeNull()
    })
  }
})

describe("splitCommand", () => {
  test("keeps quoted python code in one argv entry", () => {
    const segments = splitCommand(`python3 -c "import os; os.remove('a b.txt')"`)
    expect(segments).toHaveLength(1)
    expect(segments[0]!.argv).toEqual(['python3', "-c", `"import os; os.remove('a b.txt')"`])
  })

  test("separates on pipes and newline", () => {
    const segments = splitCommand("printf 'x' | python3\nls -la")
    expect(segments.map((s) => s.argv[0])).toEqual(["printf", "python3", "ls"])
    expect(segments[1]!.piped).toBe(true)
  })

  test("does not treat quoted separators as separators", () => {
    const segments = splitCommand(`grep "a && b" file.txt`)
    expect(segments).toHaveLength(1)
  })

  test("records redirect targets", () => {
    const segments = splitCommand("cat > out.py")
    expect(segments[0]!.redirects).toEqual([{ op: ">", target: "out.py" }])
  })

  test("does not treat >&1 as creating a file", () => {
    const segments = splitCommand("python3 script.py 2>&1")
    const created = detect("python3 script.py 2>&1")
    expect(created).toBeNull()
    expect(segments[0]!.redirects.map((r) => r.target)).toContain("1")
  })
})

describe("isInPlaceFlag", () => {
  test("accepts the in-place forms", () => {
    for (const flag of ["-i", "-i.bak", "-i''", "-ni", "-Ei", "--in-place", "--in-place=.bak"]) {
      expect(isInPlaceFlag(flag), flag).toBe(true)
    }
  })

  test("rejects flags that only look in-place", () => {
    for (const flag of ["-n", "-f", "-e", "-fsed.sed", "-eimport", "-I", "--quiet", "-", "--", "i"]) {
      expect(isInPlaceFlag(flag), flag).toBe(false)
    }
  })
})
