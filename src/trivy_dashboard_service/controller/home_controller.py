from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from trivy_dashboard_service.rendering import templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "container_count": 0,
            "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "cves": [],
            "scanned_since": None,
        },
    )
