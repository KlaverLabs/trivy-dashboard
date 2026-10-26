import asyncio
import logging
from collections import defaultdict

from trivy_dashboard_service.model import ContainerInfo
from trivy_dashboard_service.repository import scan_repository
from trivy_dashboard_service.service.docker_client import list_running_containers
from trivy_dashboard_service.service.trivy_scanner import ScanError, scan_image
from trivy_dashboard_service.service.version_checker import check_version

logger = logging.getLogger(__name__)

_tasks: set[asyncio.Task] = set()


async def start_scan() -> int:
    """Start a scan of all running containers and return its id.

    Only one scan runs at a time (Trivy's cache doesn't tolerate parallel runs), so an
    already running scan is returned instead of starting another.
    """
    running = scan_repository.get_running_scan_id()
    if running is not None:
        return running

    containers = await list_running_containers()
    scan_id, row_ids = scan_repository.create_scan(containers)
    task = asyncio.create_task(_run_scan(scan_id, list(zip(row_ids, containers))))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return scan_id


async def _run_scan(scan_id: int, items: list[tuple[int, ContainerInfo]]) -> None:
    try:
        # Containers sharing an image only need that image scanned once.
        by_image: dict[str, list[tuple[int, ContainerInfo]]] = defaultdict(list)
        for row_id, container in items:
            by_image[container.image_id].append((row_id, container))

        for image_id, group in by_image.items():
            scan_repository.mark_containers_scanning([row_id for row_id, _ in group])
            try:
                vulnerabilities, error = await scan_image(image_id), None
            except ScanError as exc:
                vulnerabilities, error = [], str(exc)

            for row_id, container in group:
                version = await check_version(container.image, container.repo_digests)
                if error:
                    scan_repository.fail_container(row_id, error, version)
                else:
                    scan_repository.complete_container(row_id, version, vulnerabilities)
        scan_repository.finish_scan(scan_id, "completed")
    except Exception:
        logger.exception("Scan %s failed", scan_id)
        scan_repository.mark_interrupted()
