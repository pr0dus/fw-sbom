import json
from pathlib import Path
import subprocess
import sys

import pytest

from fw_sbom import arduino, platformio, render
from fw_sbom.cli import main
from fw_sbom.licenses import normalize_license
from fw_sbom.model import Component, Inventory, exact_version, purl
from conftest import FIXTURES, VALIDATORS

STAMP = "2026-01-02T03:04:05Z"
SERIAL = "urn:uuid:01234567-89ab-4cde-8fab-0123456789ab"
HOME = FIXTURES / "platformio-home"


def run_cli(root, output, *args):
    return main([str(root), "--output-dir", str(output), "--timestamp", STAMP,
                 "--product-name", "Test firmware", "--product-version", "1.0.0",
                 "--supplier", "Example Maker", "--platformio-home", str(HOME), *args])


def read_pair(path):
    return (json.loads((path / "sbom.spdx.json").read_text()),
            json.loads((path / "sbom.cyclonedx.json").read_text()))


@pytest.mark.parametrize("ecosystem", ["platformio", "arduino", "unknown"])
def test_fixture_outputs_validate_and_have_product_root(ecosystem, fixture_project, tmp_path):
    output = tmp_path / "out"
    assert run_cli(fixture_project(ecosystem), output, "--no-arduino-cli") == 0
    spdx, cdx = read_pair(output)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert cdx["specVersion"] == "1.6"
    assert spdx["packages"][0]["name"] == cdx["metadata"]["component"]["name"] == "Test firmware"
    assert spdx["packages"][0]["supplier"] == "Organization: Example Maker"
    assert cdx["metadata"]["component"]["supplier"]["name"] == "Example Maker"
    ids = {item["SPDXID"] for item in spdx["packages"][1:]}
    assert ids == {item["bom-ref"] for item in cdx["components"]}
    assert len(ids) == len(spdx["packages"]) - 1
    assert set(cdx["dependencies"][0]["dependsOn"]) == ids
    assert {r["relatedSpdxElement"] for r in spdx["relationships"] if r["relationshipType"] == "DEPENDS_ON"} == ids
    assert all(item["externalRefs"][0]["referenceLocator"].startswith("pkg:") for item in spdx["packages"])


def test_platformio_all_envs_and_installed_metadata():
    inventory = platformio.collect(FIXTURES / "platformio", home=HOME)
    entries = inventory.sorted_components()
    assert {(item.name, item.version) for item in entries} == {
        ("RegistrySensor", "1.2.7"), ("RegistrySensor", "1.3.0"), ("GitDisplay", "2.0.0"),
        ("LocalControl", "0.4.0"), ("DebugLog", "3.1.0"), ("Transitive", "0.9.0"),
        ("espressif32", "6.8.1"), ("framework-arduinoespressif32", "3.20017.241212"),
    }
    assert inventory.unknowns() == []
    git = next(item for item in entries if item.name == "GitDisplay")
    assert git.contexts == ("env:debug", "env:esp32")
    assert git.purl == "pkg:github/example/gitdisplay@2.0.0"
    local = next(item for item in entries if item.name == "LocalControl")
    assert local.purl == "pkg:generic/LocalControl@0.4.0?download_url=https%3A%2F%2Fexample.org%2Flocal-control.tar.gz"


def test_env_filter_and_strict_success(tmp_path):
    assert run_cli(FIXTURES / "platformio", tmp_path, "--env", "esp32", "--fail-on-unknown") == 0
    spdx, _ = read_pair(tmp_path)
    assert "DebugLog" not in {item["name"] for item in spdx["packages"]}
    assert next(item["versionInfo"] for item in spdx["packages"] if item["name"] == "RegistrySensor") == "1.2.7"


def test_unknown_versions_licences_and_ci_exit(tmp_path, capsys):
    assert run_cli(FIXTURES / "unknown", tmp_path, "--fail-on-unknown") == 1
    spdx, cdx = read_pair(tmp_path)
    entries = {item["name"]: item for item in spdx["packages"][1:]}
    assert entries["Unlicensed"]["versionInfo"] == "1.0.0"
    assert all(item["licenseDeclared"] == "NOASSERTION" for item in entries.values())
    assert entries["Unresolved"]["versionInfo"] == entries["branchonly"]["versionInfo"] == "NOASSERTION"
    for item in cdx["components"]:
        assert item["licenses"] == [{"license": {"name": "NOASSERTION"}}]
        if item["name"] != "Unlicensed":
            assert "version" not in item
            assert {"name": "fw-sbom:version", "value": "NOASSERTION"} in item["properties"]
    assert "Unresolved: unknown version and licence" in capsys.readouterr().err


@pytest.mark.parametrize("name, expected", [("spdx", "sbom.spdx.json"), ("cyclonedx", "sbom.cyclonedx.json")])
def test_format_selects_one_file(name, expected, tmp_path):
    assert run_cli(FIXTURES / "arduino", tmp_path, "--format", name, "--no-arduino-cli") == 0
    assert [p.name for p in tmp_path.iterdir()] == [expected]


def test_output_reproducible_across_paths_and_order(fixture_project, tmp_path):
    project = fixture_project("platformio")
    a, b = tmp_path / "a", tmp_path / "b"
    assert run_cli(project, a, "--env", "debug", "--env", "esp32") == 0
    # Stable IDs, namespace, serial and complete bytes, regardless of checkout path.
    assert run_cli(FIXTURES / "platformio", b, "--env", "esp32", "--env", "debug") == 0
    for filename in ("sbom.spdx.json", "sbom.cyclonedx.json"):
        assert (a / filename).read_bytes() == (b / filename).read_bytes()


def test_timestamp_epoch_and_serial_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert main([str(FIXTURES / "unknown"), "--output-dir", str(tmp_path), "--serial-number", SERIAL]) == 0
    spdx, cdx = read_pair(tmp_path)
    assert spdx["creationInfo"]["created"] == cdx["metadata"]["timestamp"] == "1970-01-01T00:00:00Z"
    assert cdx["serialNumber"] == SERIAL
    assert run_cli(FIXTURES / "unknown", tmp_path, "--timestamp", "2026-01-02T04:04:05+01:00") == 0
    assert read_pair(tmp_path)[0]["creationInfo"]["created"] == STAMP


def test_profile_filter_and_no_invented_licences():
    entries = arduino.collect(FIXTURES / "arduino", ["esp32"], use_cli=False).sorted_components()
    assert {(item.name, item.version) for item in entries} == {
        ("ArduinoJson", "7.2.0"), ("LocalSensor", "1.0.0"), ("esp32:esp32", "3.0.7")}
    assert all(item.license == "NOASSERTION" for item in entries)


def test_optional_arduino_cli_supplements_only_matching_versions(tmp_path, monkeypatch):
    library = tmp_path / "installed-library"
    library.mkdir()
    (library / "library.properties").write_text("name=ArduinoJson\nversion=7.2.0\nlicense=MIT\nurl=https://github.com/bblanchon/ArduinoJson\n")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "lib":
            data = {"installed_libraries": [{"library": {"name": "ArduinoJson", "version": "7.2.0", "install_dir": str(library)}},
                                             {"library": {"name": "LocalSensor", "version": "9.9.9", "license": "MIT"}},
                                             {"library": {"name": "Unrelated", "version": "1.0.0", "license": "MIT"}}]}
        else:
            data = {"platforms": [{"id": "esp32:esp32", "name": "ESP32", "installed_version": "3.0.7", "license": "LGPL-2.1-or-later"}]}
        return subprocess.CompletedProcess(command, 0, json.dumps(data), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    inv = arduino.collect(FIXTURES / "arduino", ["esp32"], executable="local-arduino-cli")
    assert calls == [["local-arduino-cli", kind, "list", "--format", "json"] for kind in ("lib", "core")]
    entries = {item.name: item for item in inv.sorted_components()}
    assert entries["ArduinoJson"].license == "MIT"
    assert entries["ArduinoJson"].purl == "pkg:github/bblanchon/arduinojson@7.2.0"
    assert entries["LocalSensor"].version == "1.0.0" and entries["LocalSensor"].license == "NOASSERTION"
    assert entries["esp32:esp32"].version == "3.0.7"
    assert "Unrelated" not in entries
    render.spdx(Component("test"), inv, STAMP)
    render.cyclonedx(Component("test", kind="firmware"), inv, STAMP)


@pytest.mark.parametrize("mode", ["missing", "failed", "timeout", "invalid"])
def test_optional_cli_failure_preserves_profiles(mode, monkeypatch):
    def fake_run(command, **kwargs):
        if mode == "missing":
            raise FileNotFoundError("not found")
        if mode == "failed":
            raise subprocess.CalledProcessError(1, command)
        if mode == "timeout":
            raise subprocess.TimeoutExpired(command, 30)
        return subprocess.CompletedProcess(command, 0, "not JSON", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    inv = arduino.collect(FIXTURES / "arduino", executable="cli")
    assert len(inv.components) == 5
    assert len(inv.warnings) == 2


def test_installed_only_sketch_supports_legacy_cli_arrays(tmp_path, monkeypatch):
    (tmp_path / "sketch.yaml").write_text("{}\n")

    def fake_run(command, **kwargs):
        data = ([{"name": "Installed", "version": "2.0.0", "license": "MIT"}] if command[1] == "lib" else
                [{"id": "arduino:avr", "installed_version": "1.8.6", "name": "Arduino AVR", "license": "GPL-2.0-only"}])
        return subprocess.CompletedProcess(command, 0, json.dumps(data), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    inventory = arduino.collect(tmp_path, executable="cli")
    assert {(item.name, item.version) for item in inventory.sorted_components()} == {("Installed", "2.0.0"), ("arduino:avr", "1.8.6")}
    render.spdx(Component("installed"), inventory, STAMP)
    render.cyclonedx(Component("installed"), inventory, STAMP)


def test_platform_packages_overrides_and_framework_fallback(tmp_path):
    (tmp_path / "platformio.ini").write_text("[env:test]\nplatform=espressif32\nframework=arduino\nplatform_packages=framework-arduinoespressif32@3.20017.241212\n")
    inventory = platformio.collect(tmp_path, home=HOME)
    assert {(item.name, item.version) for item in inventory.sorted_components()} == {("espressif32", "6.8.1"), ("framework-arduinoespressif32", "3.20017.241212")}
    # With only a package.json, a matching framework can still be resolved.
    alternative = tmp_path / "home"
    (alternative / "packages").mkdir(parents=True)
    import shutil
    shutil.copytree(HOME / "packages" / "framework-arduinoespressif32", alternative / "packages" / "framework-arduinoespressif32")
    inventory = platformio.collect(tmp_path, home=alternative)
    assert next(item.version for item in inventory.sorted_components() if item.name == "framework-arduinoespressif32") == "3.20017.241212"


def test_project_exact_platform_pin_does_not_use_different_installed_version(tmp_path):
    (tmp_path / "platformio.ini").write_text("[env:test]\nplatform=espressif32@5.0.0\n")
    inventory = platformio.collect(tmp_path, home=HOME)
    item = inventory.sorted_components()[0]
    assert item.version == "5.0.0" and item.license == "NOASSERTION"


def test_local_library_and_registry_purls_with_missing_metadata(tmp_path):
    (tmp_path / "platformio.ini").write_text("[env:test]\nlib_deps=\n  owner/Pinned@1.2.3\n  symlink://external/MyLib\n")
    (tmp_path / "external" / "MyLib").mkdir(parents=True)
    inventory = platformio.collect(tmp_path, home=tmp_path / "empty")
    items = {item.name: item for item in inventory.sorted_components()}
    assert items["Pinned"].purl == "pkg:generic/Pinned@1.2.3?download_url=https%3A%2F%2Fregistry.platformio.org%2Flibraries%2Fowner%2FPinned"
    assert items["MyLib"].source == "file:external/MyLib"
    assert items["MyLib"].version is None
    render.spdx(Component("local"), inventory, STAMP)
    render.cyclonedx(Component("local"), inventory, STAMP)


@pytest.mark.parametrize("declaration, normalized", [(None, "NOASSERTION"), ("private", "NOASSERTION"),
    ("mit", "MIT"), ("Apache License, Version 2.0", "Apache-2.0"), ("BSD-3-Clause", "BSD-3-Clause"),
    ("MIT OR Apache-2.0", "MIT OR Apache-2.0"), (["MIT", "BSD-2-Clause"], "MIT AND BSD-2-Clause"),
    ("(MIT OR Apache-2.0) AND BSD-2-Clause", "(MIT OR Apache-2.0) AND BSD-2-Clause"),
    ("MIT OR imaginary", "NOASSERTION"), ("MIT AND", "NOASSERTION")])
def test_licence_normalization(declaration, normalized):
    assert normalize_license(declaration) == normalized
    inventory = Inventory()
    inventory.add(Component("licensed", "1.0", normalized))
    render.spdx(Component("test"), inventory, STAMP)
    render.cyclonedx(Component("test"), inventory, STAMP)


@pytest.mark.parametrize("value", ["^1.0.0", "~2.0.0", ">=1.0.0", "1.*", "main", "latest", None])
def test_version_constraints_are_not_versions(value):
    assert exact_version(value) is None


def test_github_and_generic_package_url_encoding():
    assert purl("anything", "1.0+test", "git@github.com:Owner/Repo.git#main") == "pkg:github/owner/repo@1.0%2Btest"
    assert purl("A B", None, "https://example.org/a.zip?a=1&b=2") == "pkg:generic/A%20B?download_url=https%3A%2F%2Fexample.org%2Fa.zip%3Fa%3D1%26b%3D2"


def test_named_git_dependencies_and_packages(tmp_path):
    (tmp_path / "platformio.ini").write_text(
        "[env:test]\nlib_deps=\n  Alias @ https://github.com/owner/library.git#v1.2.3\n"
        "  Other=https://example.org/library.zip#2.0.0\n"
        "platform_packages=framework-custom @ https://github.com/owner/framework.git#abcdef1234\n")
    inventory = platformio.collect(tmp_path, home=tmp_path / "empty")
    entries = {item.name: item for item in inventory.sorted_components()}
    assert entries["Alias"].purl == "pkg:github/owner/library@v1.2.3"
    assert entries["Other"].version == "2.0.0"
    assert entries["framework-custom"].purl == "pkg:github/owner/framework@abcdef1234"
    render.spdx(Component("aliases"), inventory, STAMP)
    render.cyclonedx(Component("aliases"), inventory, STAMP)


def test_unrelated_cached_framework_is_not_selected(tmp_path):
    (tmp_path / "platformio.ini").write_text("[env:test]\nplatform=ststm32\nframework=arduino\n")
    inventory = platformio.collect(tmp_path, home=HOME)
    assert {(item.name, item.version) for item in inventory.sorted_components()} == {
        ("ststm32", None), ("framework-arduino", None)}
    assert inventory.warnings


def test_platform_metadata_in_packages_directory(tmp_path):
    (tmp_path / "platformio.ini").write_text("[env:test]\nplatform=customboard\n")
    manifest = tmp_path / "home" / "packages" / "customboard" / "package.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"name":"customboard","version":"1.0.0","license":"MIT"}')
    inventory = platformio.collect(tmp_path, home=tmp_path / "home")
    assert inventory.unknowns() == []
    assert inventory.sorted_components()[0].version == "1.0.0"


@pytest.mark.parametrize("profile", ["profiles: {test: {libraries: null}}", "profiles: {test: {platforms: wrong}}", "profiles: {1: {}}"])
def test_malformed_sketch_produces_input_error(profile, tmp_path, capsys):
    (tmp_path / "sketch.yaml").write_text(profile)
    assert main([str(tmp_path), "--no-arduino-cli"]) == 2
    assert "fw-sbom:" in capsys.readouterr().err


def test_supplier_changes_document_identity():
    root = Component("test", "1.0")
    inventory = Inventory()
    assert render.spdx(root, inventory, STAMP, "Supplier A")["documentNamespace"] != render.spdx(root, inventory, STAMP, "Supplier B")["documentNamespace"]


@pytest.mark.parametrize("args", [["--env", "absent"], ["--timestamp", "bad"], ["--timestamp", "2026-01-01"],
    ["--serial-number", "urn:uuid:bad"], ["--serial-number", "bad"], ["--profile", "esp32"]])
def test_cli_errors_are_actionable_and_do_not_write(args, tmp_path, capsys):
    assert run_cli(FIXTURES / "platformio", tmp_path / "out", *args) == 2
    assert "fw-sbom:" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_missing_ambiguous_malformed_and_cyclic_projects(tmp_path, capsys):
    assert main([str(tmp_path)]) == 2
    (tmp_path / "platformio.ini").write_text("[env:a]\nextends=env:b\n[env:b]\nextends=env:a\n")
    assert main([str(tmp_path)]) == 2
    assert "Cyclic" in capsys.readouterr().err
    (tmp_path / "sketch.yaml").write_text("profiles: [not-a-mapping]\n")
    assert main([str(tmp_path)]) == 2
    assert main([str(tmp_path), "--ecosystem", "arduino", "--no-arduino-cli"]) == 2
    (tmp_path / "platformio.ini").write_text("[env:a]\nlib_deps=${missing.value}\n")
    assert main([str(tmp_path), "--ecosystem", "platformio"]) == 2


def test_schema_registry_rejects_invalid_outputs():
    from jsonschema import ValidationError
    with pytest.raises(ValidationError):
        VALIDATORS["cyclonedx"].validate({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "made-up", "name": "bad"}]})
    with pytest.raises(ValidationError):
        VALIDATORS["spdx"].validate({"spdxVersion": "SPDX-2.3"})


def test_module_entry_point_help():
    result = subprocess.run([sys.executable, "-m", "fw_sbom", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "--fail-on-unknown" in result.stdout
