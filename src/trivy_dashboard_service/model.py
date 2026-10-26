from dataclasses import dataclass


@dataclass
class ContainerInfo:
    container_id: str
    name: str
    image: str
    image_id: str
    repo_digests: list[str]


@dataclass
class Vulnerability:
    cve_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: str | None
    title: str | None


@dataclass
class VersionInfo:
    current: str
    latest: str | None
    update_available: bool | None
