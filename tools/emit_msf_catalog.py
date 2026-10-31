#!/usr/bin/env python3
"""Emit app/msf_catalog.py from the generator's JSON output.

Usage:
    python3 tools/emit_msf_catalog.py <in.json> [out.py]

Default out.py is app/msf_catalog.py next to this tools/ directory. The JSON is
cleaned (the two "generic" pseudo-encoders are dropped) and vendored verbatim
into the module; the disassembly, faithful-asm and comment-alignment work all
happen at app runtime against its own engine.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, os.pardir, "app", "msf_catalog.py")

# The module body, with __BLOB__ replaced by the vendored JSON.
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
``_DATA`` below. Every entry loads as *editable assembly* built by
``engine.faithful_asm`` so it reassembles to the exact original bytes (inline
data becomes ``.byte`` directives, which stops linear-disassembly misalignment
from cascading). Each entry also carries the original per-instruction comments
from the Metasploit source where they can be aligned onto the disassembly; they
ride along as inline ``//`` comments, which the library page drops into the
editor's Comments column.
"""

import functools
import json
import logging

from .engine import align_comments, disassemble_detail, faithful_asm

log = logging.getLogger("shelldev.msf")

# Vendored generator output. Each item:
# {kind, refname, os, arch, name, desc, hex, comments:[[mnemonic, comment], ...]}.
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


def _dummy_tag(refname: str, kind: str, text: str) -> str:
    """Short label for a dummy immediate on this line, or ''."""
    compact = text.replace(" ", "").lower()
    if kind == "egghunter" and "74303077" in compact:
        return "egg tag 'w00t'"
    net = ("reverse" in refname) or ("bind" in refname)
    if net and "reverse" in refname and "100007f" in compact:
        return "LHOST 127.0.0.1"
    if net and ("5c11" in compact or "115c" in compact):
        return "LPORT 4444"
    return ""


def _compose(refname: str, kind: str, text: str, src_comment) -> str:
    """One asm line with its inline comment: the source comment if we have one,
    plus a note on any dummy immediate."""
    tag = _dummy_tag(refname, kind, text)
    comment = src_comment or ""
    if tag:
        comment = (comment + " — " if comment else "") + tag + " (dummy)"
    return "  " + text + (f"   // {comment}" if comment else "")


def _entry(item: dict) -> dict:
    arch = item["arch"]
    kind = item["kind"]
    refname = item["refname"]
    data = bytes.fromhex(item["hex"])
    lines = faithful_asm(arch, data, 0x1000)
    src = align_comments(lines, item.get("comments") or [])
    asm = "\n".join(_compose(refname, kind, ln, src[i]) for i, ln in enumerate(lines))

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
