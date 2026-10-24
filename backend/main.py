"""AutoDoc AI HTTP API: local, stateless and deterministic."""
import asyncio
import io
import zipfile
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool
from analyzer import AnalysisError, MAX_UPLOAD, analyze

app = FastAPI(title="AutoDoc AI", version="1.0.0")
gate = asyncio.Semaphore(2)

def demo_zip():
    buffer = io.BytesIO()
    folder = Path(__file__).resolve().parent.parent / "sample"
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*.py")):
            archive.write(path, path.relative_to(folder).as_posix())
    return buffer.getvalue()

@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "static-ast"}

@app.post("/api/analyze")
async def upload(request: Request, filename: str = "repository.zip"):
    """Accept a raw ZIP body; streaming limit is checked before parsing."""
    if request.headers.get("content-type", "").split(";")[0] not in {"application/zip", "application/octet-stream", "application/x-zip-compressed"}:
        raise HTTPException(415, "Upload a ZIP file with application/zip content type.")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_UPLOAD:
            raise HTTPException(413, "ZIP exceeds the 10 MB upload limit.")
        data.extend(chunk)
    async with gate:
        try:
            return await run_in_threadpool(analyze, bytes(data), filename)
        except AnalysisError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (RecursionError, MemoryError):
            raise HTTPException(422, "Source exceeds static analysis complexity limits.")

@app.get("/api/demo")
async def demo():
    async with gate:
        return await run_in_threadpool(analyze, demo_zip(), "atlas-api.zip")

@app.get("/api/demo/download")
def sample_download():
    return Response(demo_zip(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="atlas-api.zip"'})

# Serve the built frontend from the same origin for a one-process demo.
from fastapi.staticfiles import StaticFiles
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
