import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from trivy_dashboard_service.controller.home_controller import router as home_router

app = FastAPI(title="Trivy Dashboard Service")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
app.include_router(home_router)


def main() -> None:
    uvicorn.run(
        "trivy_dashboard_service.app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
