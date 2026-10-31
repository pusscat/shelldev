"""Import code from the formats export writes, and similar files from other
tools: raw binary, NASM, GNU as, Python and Ruby.

Every importer produces lines for the assembly pane. Where a file carries
assembly alongside its bytes (comments in Python/Ruby output, or a `db` line
with the instruction as a comment), that assembly is used only if it
assembles to exactly the same bytes; otherwise the bytes are disassembled.

NASM files are translated, never run through NASM: NASM can read other files
on the server (%include, incbin, and macros that build those), and uploaded
files can't be checked reliably for that.
"""

import re

from .engine import LABEL, MAX_LINES, Arch, assemble_lines, disassemble_blob, split_line

INDENT = "  "
MAX_BINARY = 64 * 1024
MAX_TIMES = 256


class ImportFailed(ValueError):
    pass


def _indent(lines: list[str]) -> list[str]:
    """Same layout as the editor: labels at the left edge, the rest indented."""
    out = []
    for line in lines:
        body = line.strip()
        out.append(body if not body or LABEL.match(body) else INDENT + body)
    # Drop blank lines left at either end by skipped headers or directives.
    while out and not out[0]:
        out.pop(0)
    while out and not out[-1]:
        out.pop()
    return out


def _matches(arch: Arch, lines: list[str], expected: list[bytes | None], address: int) -> list[bool]:
    """For each line, whether it assembles to the expected bytes (None means
    no expectation, only that it assembles)."""
    results = assemble_lines(arch, lines, address)
    return [
        r["ok"] and (want is None or bytes.fromhex(r["bytes"]) == want)
        for r, want in zip(results, expected)
    ]


def from_bytes(arch: Arch, data: bytes, address: int) -> list[str]:
    if len(data) > MAX_BINARY:
        raise ImportFailed(f"File is larger than {MAX_BINARY // 1024} KB")
    lines = disassemble_blob(arch, data, address)
    if len(lines) > MAX_LINES:
        raise ImportFailed(f"More than {MAX_LINES} instructions")
    return _indent(lines)


# --- Python / Ruby -------------------------------------------------------------

ESCAPES = {
    "n": 0x0A, "r": 0x0D, "t": 0x09, "0": 0x00, "a": 0x07, "b": 0x08, "f": 0x0C,
    "v": 0x0B, "e": 0x1B, "\\": 0x5C, "'": 0x27, '"': 0x22,
}
OUR_HEADER = re.compile(r"\(exported from shelldev\)\s*$|^Build: |^Not checked: ")


def _scan_string_line(line: str, ruby: bool) -> tuple[bytes | None, str | None]:
    """Collect the bytes of every string literal on a line, and the comment
    after `#`. Returns (bytes, or None if the line has no literal; comment)."""
    data, found, i = bytearray(), False, 0
    while i < len(line):
        c = line[i]
        if c == "#":
            return (bytes(data) if found else None), line[i + 1:].strip()
        if c not in "\"'":
            i += 1
            continue
        quote, found = c, True
        # Ruby single-quoted strings only understand \\ and \'.
        raw = ruby and quote == "'"
        i += 1
        while True:
            if i >= len(line):
                raise ImportFailed(f"Unterminated string: {line.strip()}")
            c = line[i]
            if c == quote:
                i += 1
                break
            if c == "\\" and i + 1 < len(line):
                e = line[i + 1]
                if raw and e not in "\\'":
                    data += b"\\"
                    i += 1
                    continue
                if e in "xX" and not raw:
                    m = re.match(r"[0-9a-fA-F]{1,2}", line[i + 2:i + 4])
                    if not m:
                        raise ImportFailed(f"Bad \\x escape: {line.strip()}")
                    data.append(int(m.group(), 16))
                    i += 2 + len(m.group())
                    continue
                if e in "01234567" and not raw:
                    m = re.match(r"[0-7]{1,3}", line[i + 1:i + 4])
                    data.append(int(m.group(), 8) & 0xFF)
                    i += 1 + len(m.group())
                    continue
                data.append(ESCAPES.get(e, ord(e)) if ord(e) < 0x80 else 0)
                i += 2
                continue
            data += c.encode("utf-8")
            i += 1
    return (bytes(data) if found else None), None


def from_strings(arch: Arch, text: str, address: int, ruby: bool) -> tuple[list[str], list[str]]:
    rows = [_scan_string_line(line, ruby) for line in text.splitlines()]
    if not any(data is not None for data, _ in rows):
        raise ImportFailed("No string literals found")
    data = b"".join(d for d, _ in rows if d)

    # If every line with bytes has a comment, try the comments as the source.
    lines, expected = [], []
    for chunk, comment in rows:
        if chunk:
            if not comment:
                break
            lines.append(comment)
            expected.append(chunk)
        elif comment and chunk is None and not OUR_HEADER.search(comment):
            labels, code = split_line(comment)
            lines.append(comment if labels and not code else f"// {comment}")
            expected.append(b"")
    else:
        if lines and all(_matches(arch, lines, expected, address)):
            return _indent(lines), []

    note = "Disassembled the bytes (the comments don't assemble to the same bytes)."
    if not any(comment for chunk, comment in rows if chunk):
        note = "Disassembled the bytes."
    return from_bytes(arch, data, address), [note]


# --- NASM / GNU as --------------------------------------------------------------

def _split_comment(line: str, markers: tuple[str, ...]) -> tuple[str, str]:
    """Split off a comment, ignoring markers inside quotes."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif any(line.startswith(m, i) for m in markers):
            marker = next(m for m in markers if line.startswith(m, i))
            return line[:i], line[i + len(marker):].strip()
    return line, ""


def _nasm_number(token: str) -> int | None:
    t = token.strip().lower().replace("_", "")
    try:
        if re.fullmatch(r"-?(0x|\$)[0-9a-f]+", t):
            return int(t.replace("$", "0x"), 16)
        if re.fullmatch(r"-?[0-9][0-9a-f]*h", t):
            return int(t[:-1], 16)
        if re.fullmatch(r"-?(0b[01]+|[01]+b)", t):
            return int(t.replace("0b", "").rstrip("b"), 2)
        if re.fullmatch(r"-?(0o[0-7]+|[0-7]+[oq])", t):
            return int(t.replace("0o", "").rstrip("oq"), 8)
        if re.fullmatch(r"-?\d+", t):
            return int(t)
    except ValueError:
        pass
    return None


DATA_SIZES = {"db": 1, "dw": 2, "dd": 4, "dq": 8}


def _nasm_data(size: int, operands: str) -> bytes | None:
    """Bytes for `db`/`dw`/`dd`/`dq` operands (numbers and quoted strings)."""
    out = bytearray()
    for item in re.findall(r"""'[^']*'|"[^"]*"|`[^`]*`|[^,]+""", operands):
        item = item.strip()
        if item[:1] in "'\"`" and len(item) >= 2:
            raw = item[1:-1].encode("utf-8")
            out += raw + b"\0" * (-len(raw) % size)
            continue
        n = _nasm_number(item)
        if n is None:
            return None
        out += (n % (1 << (8 * size))).to_bytes(size, "little")
    return bytes(out)


NASM_SIZES = {"tword": "tbyte", "oword": "xmmword", "yword": "ymmword", "zword": "zmmword"}
NASM_SKIP = re.compile(r"^\[?\s*(bits\s|use16|use32|use64|section\s|segment\s|global\s|extern\s|default\s|org\s)", re.I)


def _from_nasm_instruction(code: str) -> str:
    s = re.sub(r"\bstrict\s+", "", code, flags=re.I)
    s = re.sub(
        r"\b(byte|word|dword|qword|tword|oword|yword|zword)\s+(?=\[)",
        lambda m: NASM_SIZES.get(m.group(1).lower(), m.group(1).lower()) + " ptr ",
        s, flags=re.I,
    )
    return re.sub(r"\[\s*rel\s+", "[rip + ", s, flags=re.I)


def _bytes_directive(data: bytes) -> str:
    return ".byte " + ", ".join(f"0x{b:02x}" for b in data)


def _comment_candidates(comment: str) -> list[str]:
    """Instruction text a `db`/`.inst` comment might hold. Export writes
    `; mov rax, 1  (user comment)`, so also try without a trailing (...)."""
    out = [comment]
    m = re.match(r"^(.*?)\s*\(([^()]*)\)\s*$", comment)
    if m and m.group(1):
        out.append(f"{m.group(1)}  // {m.group(2)}")
    return out


def _restore_from_comments(arch: Arch, lines: list[str], swaps: dict[int, tuple], address: int) -> list[str]:
    """Replace raw-bytes lines with the instruction from their comment, or for
    `.inst` with the decoded instruction, where that assembles to exactly the
    same bytes. `swaps` maps line index to (bytes, candidates, decode, comment)."""
    lines = list(lines)
    if any(decode for _, _, decode, _ in swaps.values()):
        placed = assemble_lines(arch, lines, address)
        for n, (data, candidates, decode, comment) in swaps.items():
            decoded = disassemble_blob(arch, data, placed[n]["address"])
            if decode and decoded and not any(d.startswith(".byte") for d in decoded):
                text = "; ".join(decoded)
                candidates.append(f"{text}  // {comment}" if comment else text)
    for attempt in range(4):
        trial = list(lines)
        chosen = {}
        for n, (data, candidates, _, _) in swaps.items():
            if attempt < len(candidates):
                trial[n] = INDENT + candidates[attempt]
                chosen[n] = data
        if not chosen:
            break
        expected = [chosen.get(n) for n in range(len(trial))]
        ok = _matches(arch, trial, expected, address)
        for n in list(chosen):
            if ok[n]:
                lines[n] = trial[n]
                del swaps[n]
    return lines


def from_nasm(arch: Arch, text: str, address: int) -> tuple[list[str], list[str]]:
    lines, swaps, notes = [], {}, []
    for raw in text.splitlines():
        code, comment = _split_comment(raw, (";",))
        code = code.strip()
        if not code:
            if comment and not OUR_HEADER.search(comment):
                lines.append(f"// {comment}")
            elif not comment:
                lines.append("")
            continue
        if NASM_SKIP.match(code):
            if re.match(r"^default\s+rel", code, re.I):
                notes.append("`default rel` isn't supported: plain [label] operands use absolute addresses.")
            continue

        labels, rest = [], code
        while m := LABEL.match(rest):
            labels.append(m.group(1))
            rest = rest[m.end():].strip()
        label_text = "".join(f"{name}: " for name in labels)

        # `times N x` repeats x; expanded when N is small.
        count = 1
        if mt := re.match(r"times\s+(0x[0-9a-f]+|\d+)\s+(.*)$", rest, re.I):
            if int(mt.group(1), 0) <= MAX_TIMES:
                count, rest = int(mt.group(1), 0), mt.group(2)

        m = re.match(r"(d[bwdq])\s+(.*)$", rest, re.I)
        data = _nasm_data(DATA_SIZES[m.group(1).lower()], m.group(2)) if m else None
        if data is not None:
            data *= count
            line = label_text + _bytes_directive(data)
            if comment and not labels:
                swaps[len(lines)] = (data, _comment_candidates(comment), False, "")
        elif rest:
            line = label_text + "; ".join([_from_nasm_instruction(rest)] * count)
        else:
            line = label_text.strip()
        if comment:
            line += f"  // {comment}"
        lines.append(line)

    lines = _restore_from_comments(arch, _indent(lines), _reindex(lines, swaps), address)
    return lines, notes


def _reindex(lines: list[str], swaps: dict[int, tuple]) -> dict[int, tuple]:
    """Map swap positions from the raw line list onto the list after
    _indent trims leading blank lines."""
    lead = 0
    while lead < len(lines) and not lines[lead].strip():
        lead += 1
    return {n - lead: v for n, v in swaps.items()}


GAS_SKIP = re.compile(r"^\.(text|data|bss|section|globl|global|type|size|arch|cpu|file|ident)\b", re.I)


def from_gas(arch: Arch, text: str, address: int) -> tuple[list[str], list[str]]:
    lines, swaps = [], {}
    for raw in text.splitlines():
        code, comment = _split_comment(raw, ("//",))
        code = code.strip()
        if not code:
            if comment and not OUR_HEADER.search(comment):
                lines.append(f"// {comment}")
            elif not comment:
                lines.append("")
            continue
        if GAS_SKIP.match(code):
            continue
        m = re.match(r"^\.inst\s+(0x[0-9a-f]+|\d+)$", code, re.I)
        if m:
            data = (int(m.group(1), 0) & 0xFFFFFFFF).to_bytes(4, "little")
            line = _bytes_directive(data)
            swaps[len(lines)] = (data, _comment_candidates(comment) if comment else [], True, comment)
        else:
            line = code
        if comment:
            line += f"  // {comment}"
        lines.append(line)
    return _restore_from_comments(arch, _indent(lines), _reindex(lines, swaps), address), []


def import_file(arch: Arch, fmt: str, address: int, text: str | None, data: bytes | None):
    if fmt == "bin":
        if data is None:
            raise ImportFailed("Raw binary needs a file")
        return from_bytes(arch, data, address), []
    if text is None:
        raise ImportFailed("Expected a text file")
    if fmt in ("python", "ruby"):
        lines, notes = from_strings(arch, text, address, ruby=fmt == "ruby")
    elif fmt == "nasm":
        lines, notes = from_nasm(arch, text, address)
    else:
        lines, notes = from_gas(arch, text, address)
    if len(lines) > MAX_LINES:
        raise ImportFailed(f"More than {MAX_LINES} lines")
    return lines, notes
