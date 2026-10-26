import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from trivy_dashboard_service import database
from trivy_dashboard_service.controller.home_controller import router as home_router
from trivy_dashboard_service.controller.scan_controller import router as scan_router
from trivy_dashboard_service.repository import scan_repository


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    database.init_db()
    scan_repository.mark_interrupted()
    yield


app = FastAPI(title="Trivy Dashboard Service", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
app.include_router(home_router)
app.include_router(scan_router)


def main() -> None:
    uvicorn.run(
        "trivy_dashboard_service.app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8085")),
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
