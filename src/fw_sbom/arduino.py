"""Read Arduino CLI sketch profiles, optionally supplementing local metadata."""

from pathlib import Path
import re
import shutil
import subprocess

import json
import yaml

from .model import Inventory, component, exact_version
from .readers import library_metadata, properties


def _sequence(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _list(executable: str, kind: str, inventory: Inventory) -> list[dict]:
    try:
        result = subprocess.run([executable, kind, "list", "--format", "json"],
                                capture_output=True, text=True, timeout=30, check=True)
        data = json.loads(result.stdout)
        # CLI versions have returned both a top-level array and an object.
        if isinstance(data, dict):
            data = data.get("installed_libraries" if kind == "lib" else "platforms", [])
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError("expected a list of installed packages")
        return data
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        inventory.warnings.append(f"arduino-cli {kind} list unavailable: {exc}")
        return []


def _library_entry(entry: dict) -> dict:
    library = entry.get("library", entry)
    if not isinstance(library, dict):
        raise ValueError("arduino-cli library entry must be an object")
    metadata = dict(library)
    install_dir = metadata.get("install_dir")
    if install_dir:
        metadata.update(library_metadata(Path(install_dir)))
    return metadata


def _platform_entry(entry: dict) -> dict:
    release = entry.get("release", {})
    if not isinstance(release, dict):
        release = {}
    metadata = dict(entry)
    metadata["version"] = entry.get("installed_version", entry.get("version", release.get("version")))
    install_dir = entry.get("install_dir", release.get("install_dir"))
    if install_dir and (Path(install_dir) / "platform.txt").is_file():
        local = properties(Path(install_dir) / "platform.txt")
        # Keep the platform ID as the package name; the display name is descriptive.
        metadata.update({key: value for key, value in local.items() if key in {"version", "license", "url"}})
    return metadata


def _declared_library(value: object) -> tuple[str, str | None]:
    if isinstance(value, str):
        match = re.fullmatch(r"(.+?)\s*\(([^()]+)\)", value.strip())
        return (match[1].strip(), exact_version(match[2])) if match else (value.strip(), None)
    if isinstance(value, dict) and "name" in value:
        return str(value["name"]), exact_version(value.get("version"))
    raise ValueError(f"Invalid sketch library declaration: {value!r}")


def collect(root: Path, profiles: list[str] | None = None, executable: str | None = None,
            use_cli: bool = True) -> Inventory:
    data = yaml.safe_load((root / "sketch.yaml").read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("sketch.yaml must contain a mapping")
    declared_profiles = data.get("profiles", {})
    if not isinstance(declared_profiles, dict):
        raise ValueError("sketch.yaml profiles must be a mapping")
    if any(not isinstance(name, str) for name in declared_profiles):
        raise ValueError("sketch.yaml profile names must be strings")
    selected = sorted(set(profiles)) if profiles else sorted(declared_profiles)
    if set(selected) - set(declared_profiles):
        raise ValueError("Unknown Arduino profile(s): " + ", ".join(sorted(set(selected) - set(declared_profiles))))
    inventory = Inventory()
    cli = (executable or shutil.which("arduino-cli")) if use_cli else None
    libraries, platforms = [], []
    if cli:
        for kind, reader, target in (("lib", _library_entry, libraries), ("core", _platform_entry, platforms)):
            for entry in _list(cli, kind, inventory):
                try:
                    target.append(reader(entry))
                except (OSError, ValueError, TypeError) as exc:
                    inventory.warnings.append(f"arduino-cli {kind} metadata unavailable: {exc}")
    for profile in selected:
        declaration = declared_profiles[profile]
        if not isinstance(declaration, dict):
            raise ValueError(f"Profile {profile} must contain a mapping")
        context = "profile:" + profile
        for value in _sequence(declaration.get("libraries", []), f"Profile {profile} libraries"):
            name, version = _declared_library(value)
            metadata = next((item for item in libraries if item.get("name") == name
                             and (version is None or str(item.get("version")) == version)), {})
            inventory.add(component(name, metadata, source=("https://www.arduino.cc/reference/en/libraries/"
                                                           + name.lower().replace(" ", "-") + "/"),
                                    version=version, context=context))
        for value in _sequence(declaration.get("platforms", []), f"Profile {profile} platforms"):
            if not isinstance(value, dict) or "platform" not in value:
                raise ValueError(f"Invalid sketch platform declaration: {value!r}")
            name, version = _declared_library(value["platform"])
            metadata = next((item for item in platforms if item.get("id") == name
                             and (version is None or str(item.get("version")) == version)), {})
            metadata = {**metadata, "name": name}
            source = str(value.get("platform_index_url") or metadata.get("website")
                         or "https://www.arduino.cc/en/Guide/Cores")
            inventory.add(component(name, metadata, source=source, version=version,
                                    kind="framework", context=context))
    # Without profiles, installed metadata is the only available inventory.
    if not selected:
        for metadata in libraries:
            inventory.add(component(str(metadata.get("name", "unknown-library")), metadata,
                                    source="https://www.arduino.cc/reference/en/libraries/", context="installed"))
        for metadata in platforms:
            name = str(metadata.get("id", metadata.get("name", "unknown-core")))
            inventory.add(component(name, {**metadata, "name": name},
                                    source=str(metadata.get("website", "https://www.arduino.cc/en/Guide/Cores")),
                                    kind="framework", context="installed"))
        if not inventory.components:
            raise ValueError("No sketch profiles or installed Arduino libraries/cores were found")
    return inventory
