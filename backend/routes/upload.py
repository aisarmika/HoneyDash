"""HD_UC_05 — Static log file upload: parse Cowrie JSON log files uploaded by the analyst."""
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ..auth import get_current_user
from ..services.log_collector import process_line

router = APIRouter()

_ALLOWED_EXT = {".json", ".log", ".txt"}
_MAX_BYTES = 50 * 1024 * 1024  # 50 MB


@router.post("/logs")
async def upload_logs(
    file: UploadFile = File(...),
    _user: str = Depends(get_current_user),
):
    # Validate extension
    fname = file.filename or ""
    ext = ("." + fname.rsplit(".", 1)[-1].lower()) if "." in fname else ""
    if ext not in _ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Accepted: .json, .log, .txt",
        )

    content = await file.read()
    if len(content) > _MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail="File too large. Maximum size is 50 MB",
        )

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Cannot decode file: {exc}")

    lines = text.splitlines()
    total = len(lines)
    processed = 0
    skipped = 0
    errors = 0
    error_samples: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            skipped += 1
            continue
        try:
            await process_line(line)
            processed += 1
        except Exception as exc:
            errors += 1
            if len(error_samples) < 5:
                error_samples.append(str(exc))

    return {
        "filename": fname,
        "total_lines": total,
        "processed": processed,
        "skipped": skipped,
        "errors": errors,
        "error_samples": error_samples,
        "message": (
            f"Import complete: {processed} events processed, "
            f"{skipped} blank lines skipped, {errors} errors"
        ),
    }
