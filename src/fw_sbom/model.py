"""Shared inventory with stable, content-derived identifiers."""

from dataclasses import dataclass, field, replace
import hashlib
import json
import re
from urllib.parse import quote, urlparse

from .licenses import normalize_license


def exact_version(value: object) -> str | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    text = str(value).strip()
    # Only exact release versions/commit hashes; constraints and branch names
    # cannot establish which version was installed.
    if re.fullmatch(r"v?\d+(?:\.\d+)+(?:[-+][\w.+-]+)?|[0-9a-fA-F]{7,40}", text):
        return text
    return None


def metadata_version(value: object) -> str | None:
    """An installed manifest is authoritative, including non-semver releases."""
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
        if text and text.casefold() not in {"unknown", "noassertion", "*", "latest"}:
            if not re.search(r"[<>=~^$]|\s", text):
                return text
    return None


def github_parts(source: str) -> tuple[str, str] | None:
    source = re.sub(r"^git\+", "", source)
    source = re.sub(r"^git@github\.com:", "https://github.com/", source)
    parsed = urlparse(source)
    if parsed.hostname and parsed.hostname.casefold() == "github.com":
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[0].lower(), parts[1].removesuffix(".git").lower()
    return None


def purl(name: str, version: str | None, source: str) -> str:
    github = github_parts(source)
    base = "pkg:github/" + "/".join(quote(x, safe="") for x in github) if github else (
        "pkg:generic/" + quote(name, safe="")
    )
    if version:
        base += "@" + quote(version, safe="")
    if source and not github:
        base += "?download_url=" + quote(source, safe="")
    return base


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None = None
    license: str = "NOASSERTION"
    source: str = ""
    kind: str = "library"
    contexts: tuple[str, ...] = ()

    @property
    def purl(self) -> str:
        return purl(self.name, self.version, self.source)

    @property
    def id(self) -> str:
        identity = json.dumps([self.name, self.version, self.license, self.source, self.kind])
        return "SPDXRef-" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def component(name: str, metadata: dict, *, source: str = "", kind: str = "library",
              context: str = "", version: str | None = None) -> Component:
    repository = metadata.get("repository", metadata.get("url", ""))
    if isinstance(repository, dict):
        repository = repository.get("url", "")
    return Component(
        str(metadata.get("name") or name),
        metadata_version(metadata.get("version")) or version,
        normalize_license(metadata.get("license", metadata.get("licence"))),
        str(repository or source), kind, (context,) if context else (),
    )


@dataclass
class Inventory:
    components: dict[str, Component] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add(self, item: Component) -> None:
        previous = self.components.get(item.id)
        contexts = set(item.contexts) | set(previous.contexts if previous else ())
        self.components[item.id] = replace(item, contexts=tuple(sorted(contexts)))

    def sorted_components(self) -> list[Component]:
        return sorted(self.components.values(), key=lambda c: (c.name.casefold(), c.version or "", c.id))

    def unknowns(self) -> list[str]:
        result = []
        for item in self.sorted_components():
            fields = []
            if item.version is None:
                fields.append("version")
            if item.license == "NOASSERTION":
                fields.append("licence")
            if fields:
                result.append(f"{item.name}: unknown {' and '.join(fields)}")
        return result
