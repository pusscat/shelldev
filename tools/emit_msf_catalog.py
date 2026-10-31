#!/usr/bin/env python3
"""Emit app/msf_catalog.py from the generator's JSON output.

Usage:
    python3 tools/emit_msf_catalog.py <in.json> [out.py]

Default out.py is app/msf_catalog.py next to this tools/ directory. The JSON is
cleaned (the two "generic" pseudo-encoders are dropped) and vendored verbatim
into the module; the disassembly / faithful-asm work happens at app runtime.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, os.pardir, "app", "msf_catalog.py")

# The module body, with __BLOB__ replaced by the vendored JSON. The disassembly
# and faithful-asm logic run at import time against the app's own engine.
TEMPLATE = r'''"""Library entries vendored from Metasploit Framework payloads, encoders and egghunters.

The bytes here were generated once, offline, through the Metasploit Framework's
own API (the same path msfvenom uses) by tools/gen_msf_catalog.rb:

  - every single (stageless) native x86/x64/arm64 payload across all supported
    OSes (Linux, Windows, BSD, macOS, Solaris, iOS),
  - every x86/x64 encoder's real decoder stub (shikata_ga_nai excluded on
    request; alphanumeric encoders use BufferRegister ECX/RCX),
  - the x86 egghunter stubs (Linux and Windows; tag 'w00t').

Network payloads were generated with a dummy LHOST 127.0.0.1 / LPORT 4444, exec
payloads with a dummy command, and egghunters with the tag 'w00t'; those
immediates are flagged inline in the assembly so they're easy to retarget.

Nothing here runs Metasploit at runtime: the bytes are static and vendored in
``_DATA`` below. Every entry loads as *editable assembly*. The assembly is built
so it reassembles to the exact original bytes: any instruction that doesn't
re-encode to its own bytes (inline data such as a command string or a decoder's
encoded tail, or an odd encoding) is emitted as a ``.byte`` directive instead.
That keeps the bytes faithful and stops linear-disassembly misalignment in a
data region from cascading into the real instructions that follow.
"""

import functools
import json
import logging

from .engine import assemble_lines, disassemble_detail

log = logging.getLogger("shelldev.msf")

# Vendored generator output. Each item: {kind, refname, os, arch, name, desc, hex}.
_DATA = json.loads(r"""__BLOB__""")


def _category(refname: str, kind: str) -> str:
    if kind == "decoder":
        return "decoder"
    if kind == "egghunter":
        return "egghunter"
    r = refname.lower()
    if "reverse" in r:
        return "reverse shell"
    if "bind" in r:
        return "bind shell"
    if "exec" in r:
        return "exec"
    if "adduser" in r:
        return "add user"
    if "read_file" in r or r.endswith("cat"):
        return "read file"
    if "shell" in r:
        return "shell"
    if "exit" in r:
        return "exit"
    return "misc"


def _dummy_note(refname: str, kind: str) -> str:
    if kind == "egghunter":
        return "Default tag 'w00t' (w00tw00t) baked in — edit to match your payload's tag."
    r = refname.lower()
    if "reverse" in r:
        return "Dummy LHOST 127.0.0.1 / LPORT 4444 baked in — edit to retarget."
    if "bind" in r:
        return "Dummy LPORT 4444 baked in — edit to change."
    if "exec" in r:
        return "Dummy command baked in — edit to change."
    return ""


def _annotate(refname: str, kind: str, text: str) -> str:
    """Flag the dummy LHOST/LPORT/egg-tag immediates inline."""
    compact = text.replace(" ", "").lower()
    if kind == "egghunter" and "74303077" in compact:
        return text + "   // egg tag 'w00t' (dummy)"
    net = ("reverse" in refname) or ("bind" in refname)
    if net and "reverse" in refname and "100007f" in compact:
        return text + "   // LHOST 127.0.0.1 (dummy)"
    if net and ("5c11" in compact or "115c" in compact):
        return text + "   // LPORT 4444 (dummy)"
    return text


def _db(raw: bytes) -> str:
    return ".byte " + ", ".join("0x%02x" % b for b in raw)


def _faithful_asm(arch: str, detail: list, data: bytes) -> list[str]:
    """Assembly that reassembles to exactly ``data``. Instructions that don't
    re-encode to their own bytes become ``.byte`` of those bytes (same length),
    which preserves every downstream address, so one bad decode can't cascade.
    Falls back to an all-``.byte`` listing, which always round-trips."""
    raws = [bytes.fromhex(h.replace(" ", "")) for h, _ in detail]
    lines = [t for _, t in detail]

    def matches(result, raw):
        try:
            return bool(result.get("ok")) and bytes.fromhex(result["bytes"]) == raw
        except Exception:
            return False

    for _ in range(3):
        try:
            results = assemble_lines(arch, lines, 0x1000)
        except Exception:
            break
        if len(results) != len(lines):
            break
        changed = False
        for i, r in enumerate(results):
            if not matches(r, raws[i]) and not lines[i].startswith(".byte"):
                lines[i] = _db(raws[i])
                changed = True
        if not changed:
            try:
                whole = b"".join(bytes.fromhex(r["bytes"]) for r in results)
            except Exception:
                whole = None
            if whole == data:
                return lines
            break
    return [_db(r) for r in raws]


def _entry(item: dict) -> dict:
    arch = item["arch"]
    kind = item["kind"]
    refname = item["refname"]
    data = bytes.fromhex(item["hex"])
    detail = disassemble_detail(arch, data, 0x1000)
    lines = _faithful_asm(arch, detail, data)
    asm = "\n".join("  " + _annotate(refname, kind, ln) for ln in lines)

    desc = item.get("desc", "") or ""
    note = _dummy_note(refname, kind)
    if note:
        desc = (desc + "  " + note).strip()

    prefix = {"decoder": "msf-dec-", "egghunter": "msf-egg-"}.get(kind, "msf-")
    return {
        "id": prefix + refname.replace("/", "-"),
        "name": item.get("name") or refname,
        "arch": arch, "os": item["os"],
        "category": _category(refname, kind), "kind": kind, "source": "Metasploit",
        "description": desc, "address": 0x1000, "size": len(data),
        "load": "asm", "asm": asm, "preview": asm,
    }


def _build() -> list[dict]:
    out = []
    for item in _DATA:
        try:
            out.append(_entry(item))
        except Exception as e:  # one bad entry shouldn't drop the rest
            log.warning("msf entry %s failed: %s", item.get("refname"), e)
    return out


@functools.lru_cache(maxsize=1)
def entries() -> list[dict]:
    """Vendored Metasploit entries, built once. Empty if the engine is
    unavailable."""
    try:
        return _build()
    except Exception as e:
        log.warning("msf catalog unavailable: %s", e)
        return []
'''


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.normpath(DEFAULT_OUT)

    data = json.load(open(src))
    # Drop the two "generic" pseudo-encoders: eicar is the AV test string and
    # "none" is a pass-through; neither is a real decoder stub.
    cleaned = [e for e in data
               if not (e["kind"] == "decoder" and e["refname"].startswith("generic/"))]
    cleaned.sort(key=lambda e: (e["kind"], e["os"], e["arch"], e["refname"]))
    blob = json.dumps(cleaned, separators=(",", ":"), ensure_ascii=True)

    with open(dst, "w") as f:
        f.write(TEMPLATE.replace("__BLOB__", blob))

    kinds = {}
    for e in cleaned:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"wrote {dst}: {len(cleaned)} entries {kinds}, blob {len(blob)} bytes")


if __name__ == "__main__":
    main()
