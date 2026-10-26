import os

import uvicorn
from fastapi import FastAPI

app = FastAPI(title="Trivy Dashboard Service")


def main() -> None:
    uvicorn.run(
        "trivy_dashboard_service.app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
