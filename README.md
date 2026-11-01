# shelldev

An interactive assembler in the browser. Type assembly on the left and see the
machine code bytes on the right, or paste bytes on the right and see the
disassembly on the left.

Supports **x86 (32-bit)**, **x64** and **ARM64**.

## Features

- **Two-way editing.** Whichever pane you type in is the source; the other
  pane updates as you type.
- **Line by line.** Line N on the left always matches line N on the right, so
  an instruction and its bytes sit side by side.
- **Errors in place.** An invalid instruction or invalid bytes turn red, and the
  matching line on the other side shows `???`. The status bar names the first
  failing line and the reason. Other lines keep converting.
- **Addresses.** Set a base address at the top (0x1000 by default); each
  line's address is shown down the left, padded to the processor's pointer
  size (8 hex digits on x86, 16 on x64 and ARM64).
- **Labels.** `name:` defines a label, either on its own line or in front of
  an instruction. Labels can be referenced forwards or backwards by relative
  branches and PC-relative instructions: x86/x64 `jmp`, `jcc`, `call`,
  `loop`, `jecxz`, `[rip + label]`; ARM64 `b`, `bl`, `b.cond`, `cbz`/`cbnz`,
  `tbz`/`tbnz`, `adr`, `adrp`, `ldr` (literal). Used anywhere else (e.g.
  `mov rax, label`) a label stands for its absolute address. Branches pick the
  shortest encoding that reaches the target.
- **Label highlighting and auto-indent.** Label definitions are colored, as
  are references to them, and comments are dimmed. Indentation is automatic:
  after every edit, lines that start with a label are moved to the left edge
  and all other non-blank lines are indented by two spaces. Backspace inside
  an indent joins the line onto the previous one. Assembly generated from
  bytes is indented the same way.
- **Comments column.** A third column holds a free-form note for each line,
  aligned to the assembly. Your code and notes are saved in the browser and
  restored on reload. Notes are kept out of the assembler, but they travel
  with export and import: exporting writes each note next to that line in the
  file, and importing a file puts any per-line comments into the Comments
  column (leaving the assembly clean).

- **Byte highlighting.** The bar under the header takes a set of bytes to
  watch for (for example, bad characters for shellcode). Every occurrence in
  the bytes pane is shown in bold, underlined yellow, and the status bar
  counts them. Entries can be printable ASCII characters, `\xNN` or `0xNN`;
  spaces and commas separate entries, so use `\x20` for a space, `\x2c` for a
  comma and `\\` for a backslash. The parsed bytes are listed next to the
  bar, and the entry is remembered in the browser. It starts out as
  `\x00 \x0D \x0A` (NUL, CR, LF).

- **Export.** The Export menu in the header downloads the current program
  as:
  - **Raw binary** (`shellcode.bin`): just the bytes.
  - **Assembly source**: for x86/x64, a NASM file (`shellcode.asm`) with
    `BITS`, `section .text` and `global _start`, ready for
    `nasm -f elf64 shellcode.asm && ld -o shellcode shellcode.o`
    (`-f elf32` and `ld -m elf_i386` for x86). The server assembles the file
    with NASM and compares it line by line with the bytes shown in the app;
    any line NASM would encode differently (for example `mov rax, 1`, which
    NASM shortens), or that refers to an absolute address, is written as
    `db` bytes with the original instruction as a comment. The result
    always assembles to exactly the same bytes. NASM doesn't support ARM, so
    for ARM64 it's a GNU as file (`shellcode.s`) instead; branches with a
    numeric target are written as `.inst` words.
  - **Python** (`shellcode.py`) or **Ruby** (`shellcode.rb`): a `shellcode`
    byte string built one line at a time, with each line's assembly as a
    comment.

  Export is refused while any line has an error.
- **Import.** Import… opens a dialog that reads the same formats back, from a
  file or pasted text. You must pick the architecture (it is never guessed);
  the format is filled in from the file extension, and the base address
  defaults to the current one. Import replaces the assembly pane (Ctrl+Z
  brings the old code back).
  - **Raw binary** is disassembled, one instruction per line.
  - **Python / Ruby**: the bytes of every string literal are collected. If
    each line of bytes has a comment and those comments assemble to exactly
    the same bytes (as in files this app exports), the comments become the
    code, so labels and comments come back. Otherwise the bytes are
    disassembled (this is what happens with msfvenom output, for example).
  - **NASM** is translated to the editor's syntax (`dword [x]` →
    `dword ptr [x]`, `[rel x]` → `[rip + x]`, `db`/`dw`/`dd`/`dq` → bytes,
    small `times` counts expanded; `BITS`, `section`, `global` etc. are
    dropped). A `db` line whose comment is an instruction producing the same
    bytes becomes that instruction again. NASM itself is not run on imported
    files, since NASM can read other files on the server.
  - **GNU as** (ARM64) is taken mostly as-is; `.inst` words are decoded back
    into instructions.

  Anything that can't be translated stays in the editor as a red line.
- **Library.** The Library button opens a reference page of well-known
  shellcode and decoder stubs (`/library`). Search by name, and filter or sort
  by architecture, OS, function (exec, exit, reverse shell, decoder…) and type
  (payload or decoder). Each entry shows a preview and its assembled size;
  "Load in editor" sends it back to the editor with the right architecture and
  base address. There are two sources of entries:
  - A few **hand-written** reference implementations inspired by Metasploit
    (a reverse shell and a XOR decoder stub for x86 and x64); these load as
    editable assembly and use placeholder constants (127.0.0.1:4444, key 0xaa)
    meant to be edited.
  - The bulk are **pwntools-generated**, loaded as **raw bytes** (the editor
    disassembles them, so you see the tool's own disassembly of the real
    payload). This covers all of pwntools' complete standalone payloads per
    architecture — `sh`, `exit`, `dupsh`, `findpeersh`, reverse and bind
    shells, `bindsh`, `cat`, `cat2`, `readfile`, `echo`, `forkbomb`,
    `forkexit`, `killparent` — wherever pwntools provides them (so some are
    x86/x64 only). pwntools' ~500 one-per-syscall wrappers are left out, since
    they're primitives, not payloads. Also included are **decoder stubs** from
    pwntools' encoders — the i386 XOR, delta and ASCII (printable) decoders and
    the amd64 delta decoder, each wrapping a null-free execve("/bin/sh").
    (pwntools' remaining encoders target 32-bit ARM and MIPS, which the editor
    has no mode for.) These need pwntools and its assemblers in the image (see
    below); when those are missing they are simply left out.

### Syntax notes

- Comments start with `//` on every architecture.
- `;` separates multiple instructions on one line (`nop; ret`).
- Inline data: `db` emits raw bytes, `dw`/`dd`/`dq` emit 2/4/8-byte
  little-endian values. Operands are numbers and/or quoted strings separated
  by commas or spaces, so `db 0x41, 0x42`, `db 0x41 0x42` and
  `db "./flag.txt", 0x0a` all work. Strings are taken literally (as in NASM's
  `''`/`""` — there are no `\n`-style escapes, so write a newline as a byte:
  `db "line", 0x0a`). Keystone's own `.byte`/`.ascii`/`.asciz` work too.
- Bytes can be written as `55 48 89 e5`, `\x55\x48`, or `0x55, 0x48`.
- Label names start with a letter, `_`, `.` or `$`; numeric local labels
  (`1:`, `1b`, `1f`) are not supported.
- Editing the bytes side regenerates the assembly side, so labels and comments
  on the left are lost.

## How it works

A small [FastAPI](https://fastapi.tiangolo.com/) server, run by Uvicorn,
serves two static pages (the editor and the library) and these endpoints:

| Endpoint | Input | Output |
| --- | --- | --- |
| `POST /api/assemble` | `{arch, address, lines: [assembly...]}` | per line: `address`, `ok`, `bytes` or `error` |
| `POST /api/disassemble` | `{arch, address, lines: [hex...]}` | per line: `address`, `ok`, `text` or `error` |
| `POST /api/export` | `{arch, address, lines: [assembly...], format}` | the file as a download; `format` is `bin`, `asm`, `python` or `ruby` |
| `POST /api/import` | `{arch, address, format, text}` or `{..., data_base64}` | `{lines, notes}`; `format` is `bin`, `nasm`, `gas`, `python` or `ruby` |
| `GET /api/library` | — | `{entries}`: the reference shellcode catalog, each with its assembled size |

`arch` is `x86`, `x64` or `arm64`. Assembly uses
[Keystone](https://www.keystone-engine.org/); disassembly uses
[Capstone](https://www.capstone-engine.org/).

```
app/
  main.py            web routes
  engine.py          line-by-line assemble/disassemble
  export.py          export formats, including the NASM check
  importer.py        import formats
  library.py         hand-written shellcode catalog
  pwn_catalog.py     pwntools-generated entries (raw bytes)
  static/library.html the library page
  static/index.html  the whole frontend (no build step)
Dockerfile
docker-compose.yml
requirements.txt
```

## Running it

### With Docker (recommended)

Needs Docker with the Compose plugin. Your user must be able to talk to the
Docker daemon (be in the `docker` group, or use `sudo`).

```sh
git clone git@github.com:pusscat/shelldev.git
cd shelldev
docker compose up -d --build
```

Open <http://localhost:8000>.

Day-to-day commands:

```sh
docker compose up -d --build   # start, or rebuild after changes
docker compose logs -f         # follow server logs
docker compose down            # stop
```

To serve on a different port, change the left side of the mapping in
`docker-compose.yml` (for example `"8080:8000"`).

### Without Docker

Needs Python 3.12. Keystone and Capstone install from prebuilt wheels on
x86-64 Linux; on other platforms Keystone may need `cmake` and a C++ compiler
to build from source. Install `nasm` too (e.g. `apt install nasm`) so NASM
exports can be checked; without it they're exported unchecked, with a note in
the file. The pwntools library entries need pwntools (in `requirements.txt`)
plus the assemblers it calls — `binutils`, `binutils-aarch64-linux-gnu` and
`cpp` (the Docker image installs these); any entry whose assembler is missing
is skipped, and the rest of the app is unaffected.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload --port 8000
```

## Deploying to a server

The container runs as a non-root user and listens on port 8000 over plain
HTTP. It has no authentication and keeps no state, so the usual setup is:

1. Install Docker on the server, clone the repo, and run
   `docker compose up -d --build`. The compose file sets
   `restart: unless-stopped`, so it comes back after a reboot.
2. Put a reverse proxy in front for HTTPS. For example, with
   [Caddy](https://caddyserver.com/), which gets certificates automatically:

   ```
   asm.example.com {
       reverse_proxy localhost:8000
   }
   ```

3. Bind the app to localhost only, so it is reachable only through the proxy:
   in `docker-compose.yml` change the port mapping to `"127.0.0.1:8000:8000"`.
4. If it should not be public, add access control at the proxy (for example
   Caddy's `basic_auth`), since the app has none of its own.

To update a running deployment:

```sh
git pull
docker compose up -d --build
```

## License

MIT; see [LICENSE](LICENSE).
