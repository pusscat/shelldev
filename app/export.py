"""Export assembled code as a raw binary, an assembler source file, or a
Python/Ruby string.

Each export takes `rows`, one per editor line:
    {"source": str,          # the line as typed, trimmed
     "labels": [str],        # labels defined on the line
     "parts": [(str, bytes)],  # each `;`-separated statement and its bytes
     "comment": str}         # text after `//`, if any
"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ARCH_NAMES = {"x86": "x86 (32-bit)", "x64": "x64", "arm64": "ARM64"}


def _header(arch: str, address: int, rows, prefix: str) -> str:
    total = sum(len(data) for row in rows for _, data in row["parts"])
    return f"{prefix} {ARCH_NAMES[arch]}, {total} bytes, base address {address:#x} (exported from shelldev)"


def _row_bytes(row) -> bytes:
    return b"".join(data for _, data in row["parts"])


def to_bin(rows) -> bytes:
    return b"".join(_row_bytes(row) for row in rows)


# --- Python / Ruby -----------------------------------------------------------


def _escaped(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def _comment_for(row) -> str:
    """The comment shown next to a line's bytes: the source line itself."""
    source = row["source"]
    return source[2:].strip() if source.startswith("//") else source


def _string_rows(rows):
    """(string literal or None, comment) for each non-blank line."""
    for row in rows:
        if row["source"]:
            data = _row_bytes(row)
            yield (f'"{_escaped(data)}"' if data else None), _comment_for(row)


def to_python(arch: str, address: int, rows) -> str:
    items = list(_string_rows(rows))
    header = _header(arch, address, rows, "#")
    if not any(literal for literal, _ in items):
        return f'{header}\nshellcode = b""\n'
    width = max(len(literal) + 1 for literal, _ in items if literal)
    body = [
        f"    {('b' + literal).ljust(width)}  # {comment}" if literal else f"    # {comment}"
        for literal, comment in items
    ]
    return f"{header}\nshellcode = (\n" + "\n".join(body) + "\n)\n"


def to_ruby(arch: str, address: int, rows) -> str:
    items = list(_string_rows(rows))
    header = _header(arch, address, rows, "#")
    width = max((len(literal) for literal, _ in items if literal), default=0)
    body = [
        f"shellcode << {literal.ljust(width)}  # {comment}" if literal else f"# {comment}"
        for literal, comment in items
    ]
    return f'{header}\nshellcode = +""\n' + "".join(line + "\n" for line in body)


# --- NASM (x86 / x64) ----------------------------------------------------------

NASM_SIZES = {"xmmword": "oword", "ymmword": "yword", "zmmword": "zword", "tbyte": "tword"}
NASM_TIMEOUT = 10
NASM_MAX_RUNS = 50


def _nasm_statement(stmt: str) -> str | None:
    """Translate a Keystone (Intel/LLVM) statement to NASM syntax, or None
    if it should be emitted as raw bytes instead."""
    # Directives differ between assemblers, and quotes, % and \ could reach
    # NASM's preprocessor (e.g. %include), so those always become bytes.
    if stmt.startswith(".") or re.search(r"[%\"'`\\]", stmt):
        return None
    s = re.sub(
        r"\b(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\b",
        lambda m: NASM_SIZES.get(m.group(1).lower(), m.group(1)),
        stmt,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"\[\s*rip\s*\+\s*([A-Za-z_.$][\w.$]*)\s*\]", r"[rel \1]", s, flags=re.IGNORECASE)
    if re.search(r"\brip\b", s, re.IGNORECASE):
        return None  # a numeric rip offset; NASM has no direct equivalent
    return s


def _db(data: bytes) -> str:
    return "db " + ", ".join(f"0x{b:02x}" for b in data)


def _nasm_entries(rows):
    """Flatten rows into NASM source entries."""
    entries = []
    for row in rows:
        if not row["source"]:
            entries.append({"kind": "blank"})
            continue
        if not row["labels"] and not row["parts"]:
            entries.append({"kind": "comment", "text": row["comment"]})
            continue
        for name in row["labels"]:
            entries.append({"kind": "label", "name": name})
        for i, (stmt, data) in enumerate(row["parts"]):
            last = i == len(row["parts"]) - 1
            entries.append({
                "kind": "stmt",
                "nasm": _nasm_statement(stmt),
                "source": stmt,
                "data": data,
                "comment": row["comment"] if last else "",
            })
        if not row["parts"] and row["comment"]:
            entries[-1]["comment"] = row["comment"]
    return entries


def _render_nasm(arch: str, address: int, rows, entries, note: str) -> tuple[str, dict[int, dict]]:
    """Render the file; also return which entry is on each line number."""
    bits = 32 if arch == "x86" else 64
    fmt = "elf32" if arch == "x86" else "elf64"
    lines = [
        _header(arch, address, rows, ";"),
        f"; Build: nasm -f {fmt} shellcode.asm && ld{' -m elf_i386' if bits == 32 else ''} -o shellcode shellcode.o",
    ]
    if note:
        lines.append(f"; {note}")
    lines += ["", f"BITS {bits}", "section .text", "global _start", ""]
    if not any(e["kind"] == "label" and e["name"] == "_start" for e in entries):
        lines.append("_start:")

    by_line = {}
    for entry in entries:
        kind = entry["kind"]
        if kind == "blank":
            text = ""
        elif kind == "comment":
            text = f"  ; {entry['text']}"
        elif kind == "label":
            text = f"{entry['name']}:"
        elif entry["nasm"] is not None:
            text = f"  {entry['nasm']}"
        else:
            # Bytes NASM couldn't reproduce, with the instruction alongside.
            text = f"  {_db(entry['data'])}" if entry["data"] else ""
            entry_comment = entry["source"]
            if entry["comment"]:
                entry_comment += f"  ({entry['comment']})"
            text = f"{text}  ; {entry_comment}" if text else f"  ; {entry_comment}"
            lines.append(text)
            by_line[len(lines)] = entry
            continue
        if kind in ("label", "stmt") and entry.get("comment"):
            text += f"  ; {entry['comment']}"
        lines.append(text)
        by_line[len(lines)] = entry
    return "\n".join(lines) + "\n", by_line


LISTING_LINE = re.compile(r"^\s*(\d+)\s+[0-9A-F]{8}\s+(\S+)")
ERROR_LINE = re.compile(r"^[^:]*:(\d+): error:")


def _run_nasm(arch: str, source: str) -> tuple[dict[int, str], set[int]] | None:
    """Assemble with NASM. Returns (bytes listed per line, lines with errors),
    or None if NASM isn't available."""
    nasm = shutil.which("nasm")
    if not nasm:
        return None
    fmt = "elf32" if arch == "x86" else "elf64"
    with tempfile.TemporaryDirectory() as tmp:
        src, lst, obj = (Path(tmp) / name for name in ("in.asm", "out.lst", "out.o"))
        src.write_text(source)
        proc = subprocess.run(
            [nasm, "-f", fmt, "-l", str(lst), "-o", str(obj), str(src)],
            capture_output=True, text=True, timeout=NASM_TIMEOUT, cwd=tmp,
        )
        errors = {int(m.group(1)) for m in map(ERROR_LINE.match, proc.stderr.splitlines()) if m}
        listed: dict[int, str] = {}
        if lst.exists():
            for line in lst.read_text().splitlines():
                if m := LISTING_LINE.match(line):
                    n = int(m.group(1))
                    listed[n] = listed.get(n, "") + m.group(2).rstrip("-")
        if proc.returncode and not errors:
            errors = {0}  # failed without naming a line
        return listed, errors


def to_nasm(arch: str, address: int, rows) -> str:
    """NASM source that assembles to exactly the same bytes.

    Statements are translated to NASM syntax, then the file is assembled with
    NASM and compared line by line. Any statement NASM encodes differently
    (or rejects) is replaced with `db` bytes and the original as a comment,
    and the check repeats until everything matches.
    """
    entries = _nasm_entries(rows)
    for _ in range(NASM_MAX_RUNS):
        source, by_line = _render_nasm(arch, address, rows, entries, "")
        result = _run_nasm(arch, source)
        if result is None:
            return _render_nasm(arch, address, rows, entries, "Not checked: NASM was not available.")[0]
        listed, errors = result
        if 0 in errors:
            break

        # Lines NASM rejected can't stay.
        changed = False
        for n in sorted(errors):
            entry = by_line.get(n)
            if entry and entry["kind"] == "label":
                # e.g. a label name NASM reserves; keep it as a comment.
                entry.update(kind="comment", text=f"{entry['name']}:")
                changed = True
            elif entry and entry["kind"] == "stmt" and entry["nasm"] is not None:
                entry["nasm"] = None
                changed = True
        if changed:
            continue

        checked = [
            (entry, listed.get(n, ""), entry["data"].hex().upper())
            for n, entry in by_line.items()
            if entry["kind"] == "stmt" and entry["nasm"] is not None
        ]
        # A different size shifts every later address, so later lines can
        # mismatch only because of it. Fix the first size mismatch and re-run.
        resized = next((entry for entry, got, want in checked if len(got) != len(want)), None)
        if resized:
            resized["nasm"] = None
            continue
        # Sizes all agree, so addresses match and any remaining difference is
        # real (another encoding, or an absolute address left to the linker).
        mismatched = [entry for entry, got, want in checked if got != want]
        if not mismatched:
            return source
        for entry in mismatched:
            entry["nasm"] = None
    # Couldn't converge: fall back to bytes for everything.
    for entry in entries:
        if entry["kind"] == "stmt":
            entry["nasm"] = None
    return _render_nasm(arch, address, rows, entries, "")[0]


# --- GNU as (ARM64) --------------------------------------------------------------

ARM64_PC_RELATIVE = re.compile(r"^(b|bl|b\.\w+|cbn?z|tbn?z|adrp?|ldr\w*|prfm)$", re.IGNORECASE)


def to_gas(arch: str, address: int, rows) -> str:
    """GNU as source for ARM64 (NASM doesn't support ARM).

    Branches and other PC-relative instructions with a numeric target (as
    produced by disassembly) are emitted as `.inst` words, since GNU as
    would read the number as an absolute address.
    """
    lines = [
        _header(arch, address, rows, "//"),
        "// Build: as -o shellcode.o shellcode.s && ld -o shellcode shellcode.o",
        "",
        ".text",
        ".global _start",
        "",
    ]
    if not any("_start" in row["labels"] for row in rows):
        lines.append("_start:")
    for row in rows:
        if not row["source"]:
            lines.append("")
            continue
        if not row["labels"] and not row["parts"]:
            lines.append(f"  // {row['comment']}")
            continue
        lines += [f"{name}:" for name in row["labels"]]
        for i, (stmt, data) in enumerate(row["parts"]):
            mnemonic, _, operands = stmt.partition(" ")
            numeric_target = re.search(r"(^|,)\s*#?-?(0x[0-9a-f]+|\d+)\s*$", operands, re.IGNORECASE)
            if ARM64_PC_RELATIVE.match(mnemonic) and numeric_target and len(data) == 4:
                text = f"  .inst 0x{int.from_bytes(data, 'little'):08x}  // {stmt}"
            else:
                text = f"  {stmt}"
            if i == len(row["parts"]) - 1 and row["comment"]:
                text += f"  // {row['comment']}"
            lines.append(text)
    return "\n".join(lines) + "\n"
