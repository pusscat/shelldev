"""shelldev web app: an interactive assembler for x86, x64 and ARM64."""

from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import base64
import binascii

from . import export, importer
from .engine import MAX_LINES, Arch, assemble_lines, disassemble_lines, split_line

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="shelldev")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class LinesRequest(BaseModel):
    arch: Arch
    lines: list[str] = Field(max_length=MAX_LINES)
    address: int = Field(0, ge=0, lt=2**64)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/assemble")
def assemble(req: LinesRequest):
    results = assemble_lines(req.arch, req.lines, req.address)
    return {"lines": [{k: v for k, v in r.items() if k != "parts"} for r in results]}


@app.post("/api/disassemble")
def disassemble(req: LinesRequest):
    return {"lines": disassemble_lines(req.arch, req.lines, req.address)}


class ExportRequest(LinesRequest):
    format: Literal["bin", "asm", "python", "ruby"]


@app.post("/api/export")
def export_code(req: ExportRequest):
    results = assemble_lines(req.arch, req.lines, req.address)
    for n, r in enumerate(results, 1):
        if not r["ok"]:
            return JSONResponse({"error": f"Line {n}: {r['error']}"}, status_code=422)

    rows = []
    for line, r in zip(req.lines, results):
        labels, _ = split_line(line)
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


class ImportRequest(BaseModel):
    arch: Arch
    address: int = Field(0, ge=0, lt=2**64)
    format: Literal["bin", "nasm", "gas", "python", "ruby"]
    text: str | None = Field(None, max_length=512 * 1024)
    data_base64: str | None = Field(None, max_length=(importer.MAX_BINARY * 4) // 3 + 4)


@app.post("/api/import")
def import_code(req: ImportRequest):
    try:
        data = base64.b64decode(req.data_base64, validate=True) if req.data_base64 is not None else None
        lines, notes = importer.import_file(req.arch, req.format, req.address, req.text, data)
    except (importer.ImportFailed, binascii.Error) as e:
        return JSONResponse({"error": str(e)}, status_code=422)
    return {"lines": lines, "notes": notes}
