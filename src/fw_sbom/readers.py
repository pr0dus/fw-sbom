"""Local metadata readers. Nothing in this module fetches resources."""

import json
from pathlib import Path


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def properties(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def library_metadata(path: Path) -> dict:
    for filename in ("library.json", "library.properties"):
        manifest = path / filename
        if manifest.is_file():
            return read_json(manifest) if filename.endswith("json") else properties(manifest)
    return {}


def child_dirs(path: Path) -> list[Path]:
    return sorted((p for p in path.iterdir() if p.is_dir() and not p.name.startswith(".")),
                  key=lambda p: p.name) if path.is_dir() else []
