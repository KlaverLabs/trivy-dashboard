import os

DB_PATH = os.getenv("DB_PATH", "data/trivy_dashboard.db")
DOCKER_SOCKET = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")
TRIVY_BIN = os.getenv("TRIVY_BIN", "trivy")
TRIVY_TIMEOUT = int(os.getenv("TRIVY_TIMEOUT", "600"))
