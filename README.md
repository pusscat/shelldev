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
- **Addresses.** Set a base address at the top; each line's address is shown
  down the left, padded to the processor's pointer size (8 hex digits on x86,
  16 on x64 and ARM64).
- **Labels.** `name:` defines a label, which can be used forwards or
  backwards (`jmp done`, `b loop`).

### Syntax notes

- Comments start with `//` on every architecture.
- `;` separates multiple instructions on one line (`nop; ret`).
- Bytes can be written as `55 48 89 e5`, `\x55\x48`, or `0x55, 0x48`.
- Label references inside memory operands (`lea rax, [rip+label]`) are not
  supported: labels are replaced by their absolute address.
- Editing the bytes side regenerates the assembly side, so labels and comments
  on the left are lost.

## How it works

A small [FastAPI](https://fastapi.tiangolo.com/) server, run by Uvicorn,
serves a single static page and two JSON endpoints:

| Endpoint | Input | Output |
| --- | --- | --- |
| `POST /api/assemble` | `{arch, address, lines: [assembly...]}` | per line: `address`, `ok`, `bytes` or `error` |
| `POST /api/disassemble` | `{arch, address, lines: [hex...]}` | per line: `address`, `ok`, `text` or `error` |

`arch` is `x86`, `x64` or `arm64`. Assembly uses
[Keystone](https://www.keystone-engine.org/); disassembly uses
[Capstone](https://www.capstone-engine.org/).

```
app/
  main.py            API and line-by-line assemble/disassemble
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
to build from source.

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
