import asyncio
import json

from trivy_dashboard_service import settings
from trivy_dashboard_service.model import Vulnerability


class ScanError(Exception):
    pass


async def scan_image(target: str) -> list[Vulnerability]:
    try:
        process = await asyncio.create_subprocess_exec(
            settings.TRIVY_BIN,
            "image",
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "vuln",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise ScanError(f"Trivy binary not found: {settings.TRIVY_BIN}") from None

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), settings.TRIVY_TIMEOUT)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise ScanError(f"Trivy timed out after {settings.TRIVY_TIMEOUT}s") from None

    if process.returncode != 0:
        raise ScanError(stderr.decode(errors="replace").strip()[-500:] or "Trivy failed")

    report = json.loads(stdout)
    return [
        Vulnerability(
            cve_id=item["VulnerabilityID"],
            severity=item.get("Severity", "UNKNOWN"),
            package=item["PkgName"],
            installed_version=item.get("InstalledVersion", ""),
            fixed_version=item.get("FixedVersion"),
            title=item.get("Title"),
        )
        for result in report.get("Results") or []
        for item in result.get("Vulnerabilities") or []
    ]
