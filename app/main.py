"""Interactive assembler: assemble with Keystone, disassemble with Capstone.

Both directions work line by line, so line N on the assembly side always
corresponds to line N on the bytes side.
"""

import re
from pathlib import Path
from typing import Literal

import capstone
import keystone
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

Arch = Literal["x86", "x64", "arm64"]

KS_MODES = {
    "x86": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
    "x64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
    "arm64": (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
}
CS_MODES = {
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
}

MAX_LINES = 2000
MAX_PASSES = 10
STATIC = Path(__file__).parent / "static"

app = FastAPI(title="shelldev")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class AssembleRequest(BaseModel):
    arch: Arch
    lines: list[str] = Field(max_length=MAX_LINES)
    address: int = Field(0, ge=0, lt=2**64)


class DisassembleRequest(BaseModel):
    arch: Arch
    lines: list[str] = Field(max_length=MAX_LINES)
    address: int = Field(0, ge=0, lt=2**64)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


# --- assembly -> bytes ------------------------------------------------------

LABEL = re.compile(r"^\s*([A-Za-z_.$][\w.$]*)\s*:(?!:)")


def _split_line(line: str) -> tuple[list[str], str]:
    """Strip a `//` comment and leading `label:` definitions."""
    code = line.split("//", 1)[0]
    labels = []
    while m := LABEL.match(code):
        labels.append(m.group(1))
        code = code[m.end():]
    return labels, code.strip()


def _substitute_labels(code: str, symbols: dict[str, int]) -> str:
    """Replace label references with their numeric addresses.

    Lines are assembled one at a time, so Keystone never sees the label
    definitions. Its symbol-resolver hook would cover that, but it encodes
    x86 relative jumps off by a few bytes, whereas numeric targets are
    encoded correctly. The first word of each `;`-separated statement is the
    mnemonic and is left alone, so a label named e.g. `loop` still works.
    """
    if not symbols:
        return code
    names = re.compile(
        r"(?<![\w.$])(" + "|".join(map(re.escape, sorted(symbols, key=len, reverse=True))) + r")(?![\w.$])"
    )
    statements = []
    for stmt in code.split(";"):
        m = re.match(r"\s*\S+", stmt)
        head, rest = (stmt[: m.end()], stmt[m.end():]) if m else ("", stmt)
        statements.append(head + names.sub(lambda n: hex(symbols[n.group(1)]), rest))
    return ";".join(statements)


def _assemble_pass(arch: Arch, parsed, address: int, symbols: dict[str, int]):
    """Assemble each line at its running address, using the given label
    addresses. Returns per-line results and where each label landed."""
    ks = keystone.Ks(*KS_MODES[arch])
    current = address
    results, seen = [], {}
    for labels, code in parsed:
        for name in labels:
            seen[name] = current
        line = {"address": current if labels or code else None}
        if not code:
            results.append({**line, "ok": True, "bytes": ""})
            continue
        try:
            encoding, _ = ks.asm(_substitute_labels(code, symbols), current)
        except keystone.KsError as e:
            results.append({**line, "ok": False, "error": str(e)})
            continue
        data = bytes(encoding or [])
        results.append({**line, "ok": True, "bytes": data.hex(" ")})
        current += len(data)
    return results, seen


@app.post("/api/assemble")
def assemble(req: AssembleRequest):
    parsed = [_split_line(line) for line in req.lines]
    # Start every label at the base address, then repeat: instruction sizes
    # depend on label addresses (short vs. near jumps), which in turn move
    # the labels. Stop once the addresses settle.
    symbols = {name: req.address for labels, _ in parsed for name in labels}
    for _ in range(MAX_PASSES):
        results, seen = _assemble_pass(req.arch, parsed, req.address, symbols)
        if seen == symbols:
            break
        symbols = seen
    return {"lines": results}


# --- bytes -> assembly ------------------------------------------------------

HEX_PREFIX = re.compile(r"0x|\\x", re.IGNORECASE)
HEX_LINE = re.compile(r"[0-9a-fA-F\s,]*")


@app.post("/api/disassemble")
def disassemble(req: DisassembleRequest):
    md = capstone.Cs(*CS_MODES[req.arch])
    results = []
    current = req.address
    for raw in req.lines:
        text = HEX_PREFIX.sub("", raw.split("//", 1)[0])
        line = {"address": current if text.strip() else None}
        if not HEX_LINE.fullmatch(text):
            results.append({**line, "ok": False, "error": "Not hex"})
            continue
        digits = re.sub(r"[\s,]", "", text)
        if len(digits) % 2:
            results.append({**line, "ok": False, "error": "Odd number of hex digits"})
            continue
        data = bytes.fromhex(digits)
        if not data:
            results.append({**line, "ok": True, "text": ""})
            continue
        insns = list(md.disasm(data, current))
        used = sum(i.size for i in insns)
        current += len(data)
        if used != len(data):
            results.append({**line, "ok": False, "error": "Invalid or incomplete instruction"})
            continue
        text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
        results.append({**line, "ok": True, "text": text})
    return {"lines": results}
