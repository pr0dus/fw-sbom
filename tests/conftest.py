"""All tests are offline; every rendered output goes through an official schema."""

import json
from pathlib import Path
import shutil
import socket

import pytest
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

from fw_sbom import render

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = Path(__file__).parent / "schemas"


def _no_remote(uri):
    raise AssertionError(f"Tests may not retrieve a schema from the network: {uri}")


def validators():
    registry = Registry(retrieve=_no_remote)
    schemas = {}
    for path in sorted(SCHEMAS.rglob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        schemas[path.name] = schema
    return {name: Draft7Validator(schemas[filename], registry=registry, format_checker=FormatChecker())
            for name, filename in (("spdx", "spdx-schema.json"), ("cyclonedx", "bom-1.6.schema.json"))}


VALIDATORS = validators()


@pytest.fixture(autouse=True)
def offline_and_validate(monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise AssertionError("Network access is forbidden during tests")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setenv("PLATFORMIO_CORE_DIR", str(tmp_path / "platformio-home"))
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    for name, validator in VALIDATORS.items():
        original = getattr(render, name)

        def checked(*args, _original=original, _validator=validator, **kwargs):
            document = _original(*args, **kwargs)
            _validator.validate(document)
            return document

        monkeypatch.setattr(render, name, checked)


@pytest.fixture
def fixture_project(tmp_path):
    def copy(name):
        target = tmp_path / name
        shutil.copytree(FIXTURES / name, target)
        return target

    return copy
