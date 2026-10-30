"""Command-line entry point; all discovery is local."""

import argparse
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid

import yaml

from . import __version__, arduino, platformio, render
from .model import Component


def _timestamp(value: str | None) -> str:
    if value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("--timestamp must include a timezone")
    elif "SOURCE_DATE_EPOCH" in os.environ:
        parsed = datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), timezone.utc)
    else:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Generate offline SBOMs for PlatformIO or Arduino CLI projects.")
    result.add_argument("project", nargs="?", type=Path, default=Path("."))
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--ecosystem", choices=("platformio", "arduino"), help="Required only if both manifests exist")
    result.add_argument("--env", action="append", help="PlatformIO environment; repeat to select several (default: all)")
    result.add_argument("--profile", action="append", help="Arduino profile; repeat to select several (default: all)")
    result.add_argument("--format", choices=("spdx", "cyclonedx", "both"), default="both")
    result.add_argument("--output-dir", type=Path, default=Path("sbom"))
    result.add_argument("--product-name")
    result.add_argument("--product-version")
    result.add_argument("--supplier", help="Product supplier name (optionally Organization: or Person:)")
    result.add_argument("--fail-on-unknown", action="store_true", help="Write files, then exit 1 for unknown dependency versions/licences")
    result.add_argument("--platformio-home", type=Path, help="Override ~/.platformio for installed packages")
    result.add_argument("--no-arduino-cli", action="store_true", help="Use sketch.yaml only")
    result.add_argument("--arduino-cli", help="Path to an arduino-cli executable used only for lib/core list")
    result.add_argument("--timestamp", help="Override UTC creation time; SOURCE_DATE_EPOCH is also supported")
    result.add_argument("--serial-number", help="Override CycloneDX serial with a urn:uuid: value")
    return result


def main(argv: list[str] | None = None) -> int:
    arg_parser = parser()
    args = arg_parser.parse_args(argv)
    try:
        root = args.project.expanduser().resolve()
        ecosystems = [name for name, manifest in (("platformio", "platformio.ini"), ("arduino", "sketch.yaml"))
                      if (root / manifest).is_file()]
        ecosystem = args.ecosystem
        if ecosystem is None:
            if len(ecosystems) != 1:
                raise ValueError("Expected one platformio.ini or sketch.yaml; use --ecosystem if both exist")
            ecosystem = ecosystems[0]
        if args.env and ecosystem != "platformio":
            raise ValueError("--env applies only to PlatformIO")
        if args.profile and ecosystem != "arduino":
            raise ValueError("--profile applies only to Arduino")
        timestamp = _timestamp(args.timestamp)
        if args.serial_number:
            if not args.serial_number.startswith("urn:uuid:"):
                raise ValueError("--serial-number must be urn:uuid:<UUID>")
            parsed_serial = uuid.UUID(args.serial_number[9:])
            args.serial_number = "urn:uuid:" + str(parsed_serial)
        if ecosystem == "platformio":
            inventory = platformio.collect(root, args.env, args.platformio_home)
        else:
            inventory = arduino.collect(root, args.profile, args.arduino_cli, not args.no_arduino_cli)
        product = Component(args.product_name or root.name, args.product_version, kind="firmware")
        documents = {}
        if args.format in {"spdx", "both"}:
            documents["sbom.spdx.json"] = render.spdx(product, inventory, timestamp, args.supplier)
        if args.format in {"cyclonedx", "both"}:
            documents["sbom.cyclonedx.json"] = render.cyclonedx(product, inventory, timestamp, args.supplier, args.serial_number)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for filename, document in documents.items():
            target = args.output_dir / filename
            target.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
            print(target)
        for warning in sorted(set(inventory.warnings)):
            print("warning: " + warning, file=sys.stderr)
        unknowns = inventory.unknowns()
        for unknown in unknowns:
            print(unknown, file=sys.stderr)
        return 1 if args.fail_on_unknown and unknowns else 0
    except (OSError, ValueError, configparser.Error, yaml.YAMLError, OverflowError) as exc:
        print(f"fw-sbom: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
