# cpp — native C memory-safety target

A set of small, standalone **C command-line binaries**, one per planted bug. Unlike
the web targets (exploited over HTTP), these are exploited by feeding **crafted input**
to a binary and observing the result — a genuine, reproducible crash rather than a
synthetic snippet. It measures a SAST engine on the class of bug it finds hardest:
low-level memory safety.

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | C (C11), compiled with **GCC 13** |
| Base image | `gcc:13` (build), no runtime image — binaries run in the same container |
| Sanitizer | **AddressSanitizer** (`-fsanitize=address`) for exploit confirmation |
| Extra lib | `libsqlite3-dev` — used by the one in-process SQL-injection example |
| Exploit driver | Python 3 (`exploits/exploit_all.py`) via `docker exec` |

No web server, no framework — just libc + the compiler.

## How it is built — a deliberate double build

`Dockerfile` compiles **every** `src/*.c` twice:

```
bin/       gcc -g -O0 -fno-stack-protector            # plain build — real overflow behaviour
bin-asan/  gcc -g -O0 -fno-stack-protector -fsanitize=address   # ASAN build — turns a bug into a report
```

- `-fno-stack-protector` so a stack overflow actually corrupts (not caught by the canary).
- The **ASAN build is the exploit gate**: a successful exploit produces
  `ERROR: AddressSanitizer: <type>` on stderr, which the suite asserts. `ASAN_OPTIONS`
  is set to `abort_on_error=0:exitcode=99` so the process reports and exits cleanly.

## Structure

```
src/vulnNN_<name>.c    one bug per file, with a VULN:VULN-NN:CWE-nnn:class marker on the sink line
exploits/exploit_all.py  runs each binary in the container with a crafted input, asserts the effect
Dockerfile               dual build + a /app/secret.txt flag for the path-traversal case
docker-compose.yml       keeps the container alive (`sleep infinity`) so exploits can exec the binaries
```

## Vulnerability classes & taint sources

The 20 planted bugs are canonical and cover **every standard taint source**, so a
miss can't be blamed on an unrecognised entry point:

| Source | Sinks |
|--------|-------|
| `argv` | strcpy / sprintf stack overflow, memcpy heap overflow, int-overflow→OOB, OOB read/write, off-by-one, `alloca` overflow, `Class`-style reflection n/a, `system()` command injection, `fopen` path traversal, sqlite SQL injection, null-deref |
| `stdin` | unbounded `read()`, `scanf("%s")` |
| `getenv` | `strcat` overflow |
| file | length field drives an oversized `fread` heap copy |
| — (local) | use-after-free, double-free, format string |

See [`VULNERABILITIES.md`](VULNERABILITIES.md) for the id → CWE → file:line table.

## Run it

```bash
docker compose up -d --build          # builds both binary sets, keeps container up
python3 exploits/exploit_all.py       # "RESULT: 20/20 exploits succeeded"
python3 exploits/exploit_all.py --only 51,62   # subset
docker compose down
```

Each exploit either shows an ASAN report (memory bugs) or the observable effect —
command output (`uid=0`), the leaked `flag{…}` (path traversal), or the leaked
secret (SQL injection).

## What the benchmark shows here

PT AI's **taint engine barely detects C memory-safety** (1/19 = 5%) — it finds only
local *pattern* bugs (double-free, format string, leak). But its **PatternMatching
module catches 16/19** (84%) via dangerous-function signatures. So the tool *does*
find C bugs — through PM, not dataflow. Semgrep's engine is similarly weak (~5%).
See [`../../benchmark/README.md`](../../benchmark/README.md).
