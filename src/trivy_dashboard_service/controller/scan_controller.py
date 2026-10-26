from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from trivy_dashboard_service.rendering import templates
from trivy_dashboard_service.repository import scan_repository
from trivy_dashboard_service.service import scan_service

router = APIRouter(prefix="/scans")


def _duration(scan: dict) -> str:
    started = datetime.fromisoformat(scan["started_at"])
    finished = datetime.fromisoformat(scan["finished_at"]) if scan["finished_at"] else datetime.now(timezone.utc)
    minutes, seconds = divmod(int((finished - started).total_seconds()), 60)
    return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"


def _with_duration(scan: dict) -> dict:
    return {**scan, "duration": _duration(scan)}


@router.get("", response_class=HTMLResponse)
def list_scans(request: Request) -> HTMLResponse:
    scans = [_with_duration(scan) for scan in scan_repository.list_scans()]
    return templates.TemplateResponse(
        request,
        "scans.html",
        {"scans": scans, "running": any(scan["status"] == "running" for scan in scans)},
    )


@router.post("")
async def start_scan() -> RedirectResponse:
    try:
        scan_id = await scan_service.start_scan()
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach the Docker API: {exc}") from exc
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@router.get("/{scan_id}", response_class=HTMLResponse)
def scan_results(request: Request, scan_id: int) -> HTMLResponse:
    scan = scan_repository.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return templates.TemplateResponse(
        request,
        "scan_results.html",
        {
            "scan": _with_duration(scan),
            "containers": scan_repository.list_scan_containers(scan_id),
            "running": scan["status"] == "running",
        },
    )
