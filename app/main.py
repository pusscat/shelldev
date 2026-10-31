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
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import export

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


# Lines are assembled one statement at a time, so Keystone never sees label
# definitions. Label references are replaced with numbers before assembling.
# (Keystone's symbol-resolver hook would avoid that, but it encodes x86
# relative jumps a few bytes off.) Most instructions take the label's
# absolute address and Keystone works out the relative offset itself; the
# exceptions are handled in _assemble_statement.


def _label_pattern(symbols: dict[str, int]) -> re.Pattern | None:
    if not symbols:
        return None
    names = "|".join(map(re.escape, sorted(symbols, key=len, reverse=True)))
    return re.compile(rf"(?<![\w.$])({names})(?![\w.$])")


def _num(value: int) -> str:
    return hex(value) if value >= 0 else f"-{hex(-value)}"


def _assemble_statement(ks, arch: Arch, stmt: str, pc: int, symbols, pattern) -> bytes:
    # The mnemonic is left alone, so a label named e.g. `loop` still works.
    m = re.match(r"\s*(\S+)", stmt)
    head, operands = stmt[: m.end()], stmt[m.end():]
    mnemonic = m.group(1).lower()

    def asm(text: str, address: int) -> bytes:
        encoding, _ = ks.asm(text, address)
        return bytes(encoding or [])

    def with_labels(value_of) -> str:
        return head + pattern.sub(lambda n: _num(value_of(symbols[n.group(1)])), operands)

    if not pattern or not pattern.search(operands):
        return asm(stmt, pc)

    if arch == "arm64" and mnemonic in ("adr", "adrp"):
        # Keystone mis-encodes numeric adr/adrp targets at non-zero addresses.
        # At address 0 an offset and an absolute target are the same number,
        # so assemble there with the label replaced by its offset from pc.
        if mnemonic == "adr":
            return asm(with_labels(lambda t: t - pc), 0)
        return asm(with_labels(lambda t: (t & ~0xFFF) - (pc & ~0xFFF)), 0)

    if arch == "x64" and re.search(r"\brip\b", operands, re.IGNORECASE):
        # [rip + label] needs the offset from the next instruction. The
        # displacement is always 32-bit, so the size doesn't depend on it.
        size = len(asm(with_labels(lambda t: 0), pc))
        return asm(with_labels(lambda t: t - (pc + size)), pc)

    return asm(with_labels(lambda t: t), pc)


def _assemble_pass(arch: Arch, parsed, address: int, symbols: dict[str, int]):
    """Assemble each line at its running address, using the given label
    addresses. Returns per-line results and where each label landed."""
    ks = keystone.Ks(*KS_MODES[arch])
    pattern = _label_pattern(symbols)
    current = address
    results, seen = [], {}
    for labels, code in parsed:
        for name in labels:
            seen[name] = current
        line = {"address": current if labels or code else None}
        data, parts = b"", []
        try:
            for stmt in filter(str.strip, code.split(";")):
                encoded = _assemble_statement(ks, arch, stmt, current + len(data), symbols, pattern)
                parts.append((stmt.strip(), encoded))
                data += encoded
        except keystone.KsError as e:
            results.append({**line, "ok": False, "error": str(e)})
            continue
        # "parts" (each statement and its bytes) is used by export, not sent.
        results.append({**line, "ok": True, "bytes": data.hex(" "), "parts": parts})
        current += len(data)
    return results, seen


def assemble_lines(arch: Arch, lines: list[str], address: int) -> list[dict]:
    parsed = [_split_line(line) for line in lines]
    # Start every label at the base address, then repeat: instruction sizes
    # depend on label addresses (short vs. near jumps), which in turn move
    # the labels. Stop once the addresses settle.
    symbols = {name: address for labels, _ in parsed for name in labels}
    for _ in range(MAX_PASSES):
        results, seen = _assemble_pass(arch, parsed, address, symbols)
        if seen == symbols:
            break
        symbols = seen
    return results


@app.post("/api/assemble")
def assemble(req: AssembleRequest):
    results = assemble_lines(req.arch, req.lines, req.address)
    return {"lines": [{k: v for k, v in r.items() if k != "parts"} for r in results]}


# --- export ------------------------------------------------------------------


class ExportRequest(AssembleRequest):
    format: Literal["bin", "asm", "python", "ruby"]


@app.post("/api/export")
def export_code(req: ExportRequest):
    results = assemble_lines(req.arch, req.lines, req.address)
    for n, r in enumerate(results, 1):
        if not r["ok"]:
            return JSONResponse({"error": f"Line {n}: {r['error']}"}, status_code=422)

    rows = []
    for line, r in zip(req.lines, results):
        labels, _ = _split_line(line)
        _, _, comment = line.partition("//")
        rows.append({
            "source": line.strip(),
            "labels": labels,
            "parts": r["parts"],
            "comment": comment.strip(),
        })

    if req.format == "bin":
        body, name, media = export.to_bin(rows), "shellcode.bin", "application/octet-stream"
    elif req.format == "python":
        body, name, media = export.to_python(req.arch, req.address, rows), "shellcode.py", "text/x-python"
    elif req.format == "ruby":
        body, name, media = export.to_ruby(req.arch, req.address, rows), "shellcode.rb", "text/x-ruby"
    elif req.arch == "arm64":
        body, name, media = export.to_gas(req.arch, req.address, rows), "shellcode.s", "text/plain"
    else:
        body, name, media = export.to_nasm(req.arch, req.address, rows), "shellcode.asm", "text/plain"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


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
