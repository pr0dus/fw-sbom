"""Exercise the actual composite generation script without invoking remote Actions."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from conftest import FIXTURES, VALIDATORS

ACTION = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())


@pytest.mark.parametrize("strict, fixture, expected", [(False, "arduino", 0), (True, "unknown", 1)])
def test_composite_generation_script_and_artifact_on_failure(strict, fixture, expected, tmp_path):
    step = next(item for item in ACTION["runs"]["steps"] if item.get("id") == "generate")
    output = tmp_path / "with spaces"
    github_output = tmp_path / "github-output"
    # Metacharacters are data: the wrapper passes inputs via environment and arrays.
    product = 'Sensor $(touch should-not-exist) `touch also-not` "quoted"'
    environment = {**os.environ, "FW_SBOM_PYTHON": sys.executable, "GITHUB_OUTPUT": str(github_output),
                   "INPUT_PROJECT": str(FIXTURES / fixture), "INPUT_ECOSYSTEM": "",
                   "INPUT_ENV": "", "INPUT_PROFILE": "", "INPUT_FORMAT": "both",
                   "INPUT_PRODUCT_NAME": product, "INPUT_PRODUCT_VERSION": "1.0.0",
                   "INPUT_SUPPLIER": "Example Maker", "INPUT_FAIL_ON_UNKNOWN": str(strict).lower(),
                   "INPUT_OUTPUT_DIR": str(output), "SOURCE_DATE_EPOCH": "0"}
    result = subprocess.run(["bash", "-e", "-c", step["run"]], env=environment,
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == expected, result.stderr
    assert github_output.read_text().strip() == f"directory={output}"
    for kind in ("spdx", "cyclonedx"):
        document = json.loads((output / f"sbom.{kind}.json").read_text())
        VALIDATORS[kind].validate(document)
    assert json.loads((output / "sbom.spdx.json").read_text())["packages"][0]["name"] == product
    assert not (tmp_path / "should-not-exist").exists()
    assert not (tmp_path / "also-not").exists()
    upload = next(item for item in ACTION["runs"]["steps"] if item.get("uses", "").startswith("actions/upload-artifact@"))
    assert "always()" in upload["if"]
