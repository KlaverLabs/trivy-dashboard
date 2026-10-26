import re
from urllib.parse import urljoin

import httpx

from trivy_dashboard_service.model import VersionInfo

DOCKER_HUB_REGISTRIES = {"docker.io", "index.docker.io", "registry-1.docker.io"}
DOCKER_HUB_REGISTRY = "registry-1.docker.io"
MAX_TAG_PAGES = 20
MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
# e.g. "1.25.3", "v2.1", "3.19-alpine"
VERSION_TAG = re.compile(r"^(?P<prefix>v?)(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>(?:-[A-Za-z][\w.]*)?)$")
IMAGE_ID = re.compile(r"^(sha256:)?[0-9a-f]{12,64}$")


class VersionCheckError(Exception):
    pass


def parse_reference(image: str) -> tuple[str, str, str] | None:
    """Split an image reference into (registry, repository, tag), or None if it isn't a named image."""
    name = image.partition("@")[0]
    if not name or IMAGE_ID.match(name):
        return None

    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, name = first, rest
    else:
        registry = DOCKER_HUB_REGISTRY
    if registry in DOCKER_HUB_REGISTRIES:
        registry = DOCKER_HUB_REGISTRY

    last_segment = name.rsplit("/", 1)[-1]
    if ":" in last_segment:
        repository, tag = name.rsplit(":", 1)
    else:
        repository, tag = name, "latest"
    if registry == DOCKER_HUB_REGISTRY and "/" not in repository:
        repository = f"library/{repository}"
    return registry, repository, tag


def _version_key(numbers: str) -> tuple[int, ...]:
    parts = [int(part) for part in numbers.split(".")]
    return tuple(parts + [0] * (8 - len(parts)))


async def _auth_headers(client: httpx.AsyncClient, registry: str, repository: str) -> dict[str, str]:
    response = await client.get(f"https://{registry}/v2/")
    if response.status_code != 401:
        return {}
    params = dict(re.findall(r'(\w+)="([^"]*)"', response.headers.get("www-authenticate", "")))
    if "realm" not in params:
        raise VersionCheckError("Registry requires unsupported authentication")
    token_response = await client.get(
        params["realm"],
        params={"service": params.get("service", ""), "scope": f"repository:{repository}:pull"},
    )
    token_response.raise_for_status()
    body = token_response.json()
    return {"Authorization": f"Bearer {body.get('token') or body.get('access_token')}"}


async def _list_tags(
    client: httpx.AsyncClient, registry: str, repository: str, headers: dict[str, str]
) -> list[str]:
    tags: list[str] = []
    url = f"https://{registry}/v2/{repository}/tags/list?n=1000"
    for _ in range(MAX_TAG_PAGES):
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        tags.extend(response.json().get("tags") or [])
        next_link = response.links.get("next")
        if not next_link:
            break
        url = urljoin(str(response.url), next_link["url"])
    return tags


async def _remote_digest(
    client: httpx.AsyncClient, registry: str, repository: str, tag: str, headers: dict[str, str]
) -> str:
    response = await client.head(
        f"https://{registry}/v2/{repository}/manifests/{tag}",
        headers={**headers, "Accept": MANIFEST_TYPES},
    )
    response.raise_for_status()
    return response.headers["docker-content-digest"]


def _short(digest: str) -> str:
    return digest.removeprefix("sha256:")[:12]


async def _check_numbered_tag(
    client: httpx.AsyncClient, registry: str, repository: str, tag: str, headers: dict[str, str]
) -> VersionInfo:
    current = VERSION_TAG.match(tag)
    current_parts = current["numbers"].count(".")
    candidates = []
    for candidate in await _list_tags(client, registry, repository, headers):
        match = VERSION_TAG.match(candidate)
        if (
            match
            and match["prefix"] == current["prefix"]
            and match["suffix"] == current["suffix"]
            and match["numbers"].count(".") == current_parts
        ):
            candidates.append((_version_key(match["numbers"]), candidate))
    latest_key, latest = max(candidates, default=(_version_key(current["numbers"]), tag))
    return VersionInfo(
        current=tag,
        latest=latest,
        update_available=latest_key > _version_key(current["numbers"]),
    )


async def _check_floating_tag(
    client: httpx.AsyncClient,
    registry: str,
    repository: str,
    tag: str,
    headers: dict[str, str],
    repo_digests: list[str],
) -> VersionInfo:
    remote = await _remote_digest(client, registry, repository, tag, headers)
    local = [digest.partition("@")[2] for digest in repo_digests if "@" in digest]
    if not local:
        return VersionInfo(current=tag, latest=f"{tag} ({_short(remote)})", update_available=None)
    return VersionInfo(
        current=f"{tag} ({_short(local[0])})",
        latest=f"{tag} ({_short(remote)})",
        update_available=remote not in local,
    )


async def check_version(image: str, repo_digests: list[str]) -> VersionInfo:
    """Compare the running image against what its registry currently offers.

    Numbered tags (1.25.3) are compared with the newest tag of the same shape; floating tags
    (latest, stable) are compared by digest. Anything that can't be checked has latest=None.
    """
    reference = parse_reference(image)
    if reference is None:
        return VersionInfo(current=image.removeprefix("sha256:")[:12], latest=None, update_available=None)
    registry, repository, tag = reference

    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            headers = await _auth_headers(client, registry, repository)
            if VERSION_TAG.match(tag):
                return await _check_numbered_tag(client, registry, repository, tag, headers)
            return await _check_floating_tag(client, registry, repository, tag, headers, repo_digests)
    except (httpx.HTTPError, VersionCheckError, KeyError):
        return VersionInfo(current=tag, latest=None, update_available=None)
