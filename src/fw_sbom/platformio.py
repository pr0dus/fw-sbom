"""Read PlatformIO configuration and locally installed package manifests."""

import configparser
import os
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlparse

from .model import Inventory, component, exact_version, github_parts
from .readers import child_dirs, library_metadata, read_json


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines()
            if line.strip() and not line.lstrip().startswith((";", "#"))]


class Configuration:
    def __init__(self, path: Path):
        self.parser = configparser.ConfigParser(interpolation=None, strict=True,
                                                 inline_comment_prefixes=(";",))
        with path.open(encoding="utf-8-sig") as handle:
            self.parser.read_file(handle)

    def options(self, section: str, stack: tuple[str, ...] = ()) -> dict[str, str]:
        if section in stack:
            raise ValueError(f"Cyclic PlatformIO inheritance: {' -> '.join((*stack, section))}")
        if not self.parser.has_section(section):
            raise ValueError(f"Missing PlatformIO section [{section}]")
        result = {}
        if section.startswith("env:") and self.parser.has_section("env"):
            result.update(self.options("env", (*stack, section)))
        own = dict(self.parser.items(section))
        for parent in re.split(r"[,\s]+", own.get("extends", "")):
            if parent:
                result.update(self.options(parent, (*stack, section)))
        result.update(own)
        return result

    def expand(self, value: str, section: str, stack: tuple[str, ...] = ()) -> str:
        def substitute(match: re.Match) -> str:
            ref = match.group(1)
            if ref in stack:
                raise ValueError(f"Cyclic PlatformIO interpolation: {ref}")
            if ref.startswith("sysenv."):
                key = ref[len("sysenv."):]
                if key not in os.environ:
                    raise ValueError(f"Missing environment variable: {key}")
                return os.environ[key]
            if "." in ref:
                target, option = ref.rsplit(".", 1)
            else:
                target, option = section, ref
            options = self.options(target)
            if option not in options:
                raise ValueError(f"Unresolved PlatformIO interpolation: {ref}")
            return self.expand(options[option], target, (*stack, ref))

        return re.sub(r"\$\{([^}]+)\}", substitute, value)

    def get(self, section: str) -> dict[str, str]:
        return {key: self.expand(value, section) for key, value in self.options(section).items()}


def _dependency(spec: str, root: Path) -> tuple[str, str | None, str, Path | None]:
    # PlatformIO permits an explicit package name before a source URL.
    alias = ""
    named_source = re.fullmatch(r"(.+?)\s*[@=]\s*((?:https?://|git\+|git@|ssh://|file://|symlink://).+)", spec)
    if named_source:
        alias, spec = named_source[1].strip(), named_source[2].strip()
    local = None
    if spec.startswith(("file://", "symlink://")):
        local = root / unquote(spec.split("://", 1)[1])
    elif spec.startswith((".", "/", "lib/")) or (root / spec).is_dir():
        local = root / spec
    if local is not None:
        # A relative URI avoids leaking machine-specific project paths.
        relative = Path(os.path.relpath(local, root)).as_posix()
        return alias or local.name, None, f"file:{relative}", local
    if re.match(r"(?:https?://|git\+|git@|ssh://)", spec):
        github = github_parts(spec)
        name = github[1] if github else Path(urlparse(spec).path).name.removesuffix(".git")
        ref = spec.partition("#")[2]
        return alias or name, exact_version(ref), spec, None
    name, sep, version = spec.partition("@")
    name = name.strip()
    source = "https://registry.platformio.org/libraries/" + quote(name, safe="/")
    return alias or name.rsplit("/", 1)[-1], exact_version(version.strip()) if sep else None, source, None


def _matches(name: str, source: str, directory: Path, metadata: dict) -> bool:
    identities = {name.casefold(), name.rsplit("/", 1)[-1].casefold()}
    if directory.name.casefold() in identities or str(metadata.get("name", "")).casefold() in identities:
        return True
    repository = metadata.get("repository", metadata.get("url", ""))
    if isinstance(repository, dict):
        repository = repository.get("url", "")
    return bool(github_parts(source) and github_parts(source) == github_parts(str(repository)))


def _package_spec(spec: str) -> tuple[str, str | None, str]:
    if "://" in spec or spec.startswith("git@"):
        name, version, source, _ = _dependency(spec, Path("."))
        return name, version, source
    name, _, version = spec.partition("@")
    return name.strip().rsplit("/", 1)[-1], exact_version(version.strip()), (
        "https://registry.platformio.org/platforms/" + quote(name.strip(), safe="/")
    )


def _platform_packages(options: dict[str, str], home: Path, context: str, inventory: Inventory) -> None:
    platform_spec = options.get("platform", "").strip()
    platform_metadata = {}
    if platform_spec:
        name, version, source = _package_spec(platform_spec)
        candidates = [(directory, directory / "platform.json") for directory in child_dirs(home / "platforms")]
        candidates += [(directory, directory / "package.json") for directory in child_dirs(home / "packages")]
        for directory, manifest in candidates:
            if manifest.is_file():
                metadata = read_json(manifest)
                if _matches(name, source, directory, metadata):
                    # Do not substitute a different installed release for an exact pin.
                    if version and str(metadata.get("version")) != version:
                        continue
                    platform_metadata = metadata
                    break
        inventory.add(component(name, platform_metadata, source=source, version=version,
                                kind="platform", context=context))

    installed = [(directory, read_json(directory / "package.json"))
                 for directory in child_dirs(home / "packages")
                 if (directory / "package.json").is_file()]
    overrides = {}
    for spec in _lines(options.get("platform_packages", "")):
        name, version, source = _package_spec(spec)
        overrides[name] = (version, source.replace("/platforms/", "/tools/"))

    frameworks = re.split(r"[,\s]+", options.get("framework", "").strip())
    package_names = set(overrides)
    framework_map = platform_metadata.get("frameworks", {})
    for framework in filter(None, frameworks):
        entry = framework_map.get(framework, {}) if isinstance(framework_map, dict) else {}
        package = entry.get("package") if isinstance(entry, dict) else None
        if package:
            package_names.add(package)
        else:
            # Names encode framework and target, e.g. framework-arduinoespressif32.
            prefix = "framework-" + framework
            matches = {str(metadata.get("name", directory.name)) for directory, metadata in installed
                       if str(metadata.get("name", directory.name)).startswith(prefix)}
            # Avoid choosing a framework for a different platform when possible.
            platform_name = _package_spec(platform_spec)[0] if platform_spec else ""
            targeted = {name for name in matches if platform_name and platform_name in name}
            exact = {name for name in matches if name == prefix}
            package_names.update(targeted or exact or {prefix})
            if matches and not targeted and not exact:
                inventory.warnings.append(f"{context}: cannot associate cached framework {framework} packages with the selected platform")

    package_metadata = platform_metadata.get("packages", {})
    for name in sorted(package_names):
        version, source = overrides.get(name, (None, "https://registry.platformio.org/tools/" + name))
        declaration = package_metadata.get(name, {}) if isinstance(package_metadata, dict) else {}
        if version is None and isinstance(declaration, dict):
            version = exact_version(declaration.get("version"))
        metadata = {}
        for directory, candidate in installed:
            if _matches(name, source, directory, candidate):
                if version and str(candidate.get("version")) != version:
                    continue
                metadata = candidate
                break
        inventory.add(component(name, metadata, source=source, version=version,
                                kind="framework" if name.startswith("framework-") else "library",
                                context=context))


def collect(root: Path, envs: list[str] | None = None, home: Path | None = None) -> Inventory:
    config = Configuration(root / "platformio.ini")
    available = sorted(section[4:] for section in config.parser.sections() if section.startswith("env:"))
    selected = sorted(set(envs)) if envs else available
    if not selected:
        raise ValueError("platformio.ini contains no [env:<name>] sections")
    if set(selected) - set(available):
        raise ValueError("Unknown PlatformIO environment(s): " + ", ".join(sorted(set(selected) - set(available))))
    inventory = Inventory()
    if home is None:
        core_dir = config.get("platformio").get("core_dir") if config.parser.has_section("platformio") else None
        home = Path(core_dir or os.environ.get("PLATFORMIO_CORE_DIR", "~/.platformio")).expanduser()
        if not home.is_absolute():
            home = root / home
    for env in selected:
        context = "env:" + env
        options = config.get(context)
        libdeps_dir = root / ".pio" / "libdeps"
        if config.parser.has_section("platformio"):
            configured = config.get("platformio").get("libdeps_dir")
            if configured:
                libdeps_dir = root / configured
        installed = [(directory, library_metadata(directory))
                     for directory in child_dirs(libdeps_dir / env)]
        used = set()
        for spec in _lines(options.get("lib_deps", "")):
            name, version, source, local = _dependency(spec, root)
            metadata = library_metadata(local) if local else {}
            if local is None:
                for directory, candidate in installed:
                    if _matches(name, source, directory, candidate):
                        metadata = candidate
                        used.add(directory)
                        break
            inventory.add(component(name, metadata, source=source, version=version, context=context))
        # Installed extras include transitive libraries; preserve them in the inventory.
        for directory, metadata in installed:
            if directory not in used:
                inventory.add(component(directory.name, metadata,
                                        source=f"file:.pio/libdeps/{env}/{directory.name}", context=context))
        # PlatformIO also compiles project-private libraries under lib/.
        lib_dir = root / options.get("lib_dir", "lib")
        for directory in child_dirs(lib_dir):
            metadata = library_metadata(directory)
            item = component(directory.name, metadata,
                             source=f"file:{lib_dir.name}/{directory.name}", context=context)
            # A declared local library may already have been added with the same URI.
            inventory.add(item)
        _platform_packages(options, home, context, inventory)
    return inventory
