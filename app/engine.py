"""Assembling and disassembling, line by line.

Assembly uses Keystone and disassembly Capstone. Both work line by line, so
line N of assembly always corresponds to line N of bytes.
"""

import re
from typing import Literal

import capstone
import keystone

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


# --- assembly -> bytes ------------------------------------------------------

LABEL = re.compile(r"^\s*([A-Za-z_.$][\w.$]*)\s*:(?!:)")


def split_line(line: str) -> tuple[list[str], str]:
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

    has_label = bool(pattern and pattern.search(operands))

    if arch == "arm64" and mnemonic in ("adr", "adrp"):
        # Keystone mis-encodes adr/adrp targets at non-zero addresses. At
        # address 0 an offset and an absolute target are the same number, so
        # assemble there with the target (a label, or an absolute address as
        # Capstone prints it) replaced by its offset from pc.
        def offset(target: int) -> int:
            return target - pc if mnemonic == "adr" else (target & ~0xFFF) - (pc & ~0xFFF)

        if has_label:
            return asm(with_labels(offset), 0)
        m = re.match(r"^(.*,\s*)#?\s*(0x[0-9a-f]+|\d+)\s*$", operands, re.IGNORECASE)
        if m:
            return asm(f"{head}{m.group(1)}#{_num(offset(int(m.group(2), 0)))}", 0)
        return asm(stmt, pc)

    if not has_label:
        return asm(stmt, pc)

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
    parsed = [split_line(line) for line in lines]
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



# --- bytes -> assembly ------------------------------------------------------

HEX_PREFIX = re.compile(r"0x|\\x", re.IGNORECASE)
HEX_LINE = re.compile(r"[0-9a-fA-F\s,]*")


def disassemble_lines(arch: Arch, lines: list[str], address: int) -> list[dict]:
    """Disassemble each line of hex on its own, at its running address."""
    md = capstone.Cs(*CS_MODES[arch])
    results = []
    current = address
    for raw in lines:
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
    return results


def disassemble_blob(arch: Arch, data: bytes, address: int) -> list[str]:
    """Disassemble a run of bytes into one instruction per line. Bytes that
    don't decode become `.byte` lines."""
    md = capstone.Cs(*CS_MODES[arch])
    md.skipdata = True
    return [f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(data, address)]


def disassemble_detail(arch: Arch, data: bytes, address: int) -> list[tuple[str, str]]:
    """Disassemble a blob into (hex bytes, instruction text) per instruction.
    Undecodable bytes become `.byte` lines (one per byte)."""
    md = capstone.Cs(*CS_MODES[arch])
    md.skipdata = True
    return [(i.bytes.hex(" "), f"{i.mnemonic} {i.op_str}".strip()) for i in md.disasm(data, address)]


def _db(raw: bytes) -> str:
    return ".byte " + ", ".join(f"0x{b:02x}" for b in raw)


def faithful_asm(arch: Arch, data: bytes, address: int = 0x1000) -> list[str]:
    """Disassembly that reassembles to exactly `data`. Any instruction that
    doesn't re-encode to its own bytes (inline data such as a command string or
    an encoder's encoded tail, or an odd encoding) becomes a `.byte` directive
    of those same bytes. Substituting `.byte` keeps each line's byte length, so
    every downstream address is preserved and one bad decode in a data region
    can't cascade into the real instructions after it. Falls back to an
    all-`.byte` listing, which is always byte-exact."""
    detail = disassemble_detail(arch, data, address)
    raws = [bytes.fromhex(h.replace(" ", "")) for h, _ in detail]
    lines = [t for _, t in detail]

    def matches(result, raw):
        try:
            return bool(result.get("ok")) and bytes.fromhex(result["bytes"]) == raw
        except Exception:
            return False

    for _ in range(3):
        try:
            results = assemble_lines(arch, lines, address)
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


def align_comments(lines: list[str], anchors: list) -> list[str | None]:
    """Best-effort attach of source comments to disassembled lines.

    `anchors` is an ordered list of (mnemonic, comment) pulled from the original
    source. We walk the disassembly in order and match each line's mnemonic to
    the next unused anchor with the same mnemonic (within a small lookahead), so
    inserted instructions with no source comment are skipped cleanly. Returns a
    comment (or None) per line; returns all-None when too few anchors line up,
    to avoid showing misaligned comments."""
    result: list[str | None] = [None] * len(lines)
    if not anchors:
        return result
    mnems = [(ln.split(" ", 1)[0].lstrip(".").lower() if ln.strip() else "") for ln in lines]
    anchor_mn = [(a[0] or "").lstrip(".").lower() for a in anchors]
    j = 0
    matched = 0
    window = 4
    for i, m in enumerate(mnems):
        if j >= len(anchors):
            break
        if not m:
            continue
        for k in range(j, min(j + window, len(anchors))):
            if anchor_mn[k] == m:
                result[i] = anchors[k][1]
                j = k + 1
                matched += 1
                break
    # Require at least half the anchors to land, or drop the whole overlay.
    if matched < max(1, len(anchors) // 2):
        return [None] * len(lines)
    return result
