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
