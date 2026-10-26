import httpx

from trivy_dashboard_service import settings
from trivy_dashboard_service.model import ContainerInfo


async def list_running_containers() -> list[ContainerInfo]:
    transport = httpx.AsyncHTTPTransport(uds=settings.DOCKER_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker") as client:
        response = await client.get("/containers/json")
        response.raise_for_status()
        containers = []
        for item in response.json():
            image = await client.get(f"/images/{item['ImageID']}/json")
            image.raise_for_status()
            containers.append(
                ContainerInfo(
                    container_id=item["Id"],
                    name=item["Names"][0].lstrip("/"),
                    image=item["Image"],
                    image_id=item["ImageID"],
                    repo_digests=image.json().get("RepoDigests") or [],
                )
            )
    return containers
