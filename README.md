# fw-sbom

Generate SPDX 2.3 JSON and CycloneDX 1.6 JSON for PlatformIO and Arduino CLI
firmware projects. Python 3.10+, MIT licensed. Generation reads local files and
never downloads libraries, resolves dependencies online, or runs a build.

PlatformIO quick start (from this checkout, with an existing project):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
fw-sbom /path/to/platformio-project --product-name Sensor --product-version 1.0 --supplier 'Example Maker' --format both
ls sbom/sbom.spdx.json sbom/sbom.cyclonedx.json
```

Arduino CLI quick start (with an existing sketch containing `sketch.yaml`):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
fw-sbom /path/to/sketch --product-name Sensor --product-version 1.0 --supplier 'Example Maker' --format both
ls sbom/sbom.spdx.json sbom/sbom.cyclonedx.json
```

Install dependencies once before using the tool offline. There is no runtime
network option. An available `arduino-cli` is used only for `lib list --format json`
and `core list --format json`; `--no-arduino-cli` disables those calls.

## Inputs and resolution

- **PlatformIO:** reads every `[env:*]` in `platformio.ini`, including `[env]`
  defaults, `extends` and `${section.option}` / `${sysenv.VARIABLE}` references.
  Select environments with repeated `--env NAME`. `default_envs` does not restrict
  an inventory. Reads registry, Git URL and local (`file://`, `symlink://` or path)
  `lib_deps`, project `lib/`, and all installed libraries in `.pio/libdeps/<env>/`.
  `library.json` and `library.properties` supply names, versions, licences and
  repository URLs. Installed extras are included as potentially transitive
  dependencies. Install/build your selected environments with your usual tooling
  beforehand for a more complete inventory.
- **Platform/framework packages:** reads explicit platform and `platform_packages`
  pins, installed `platform.json` under `~/.platformio/platforms/`, and applicable
  `package.json` files under `~/.platformio/packages/`. Platform metadata identifies
  framework package names. `--platformio-home PATH`, `PLATFORMIO_CORE_DIR`, or
  `[platformio] core_dir` selects another installation. Unknown versions stay unknown;
  unrelated cached toolchains are excluded.
- **Arduino:** reads all `sketch.yaml` profiles, their `platforms` and `libraries`
  pins (e.g. `ArduinoJson (7.2.0)`). Select profiles with repeated `--profile NAME`.
  Optional installed CLI metadata and local `library.properties` / `platform.txt`
  supplement only matching names and versions. A sketch without profiles can use
  installed CLI inventory; this includes everything installed, so review it for
  unrelated libraries/cores. A missing or failing CLI does not discard profiles.
  `--arduino-cli PATH` selects an executable.

If both manifests exist, choose `--ecosystem platformio|arduino`. Standard inline
PlatformIO configuration is supported; external `extra_configs`, dynamic platform
Python scripts and build-time dependency resolution are outside v1. This is a
manifest/installation inventory, not a binary or source-code analyser.

## Output and CI

`--format spdx|cyclonedx|both` defaults to `both`. Files are `sbom.spdx.json` and
`sbom.cyclonedx.json` in `--output-dir` (default `./sbom`, relative to your working
directory). `--product-name` defaults to the project directory name;
`--product-version` and `--supplier` are optional. The product is the root, with
dependency relationships to all discovered components. Relationships form a flat
inventory: no unobserved dependency-to-dependency edges are asserted. Environment
and profile provenance is recorded on each dependency; different versions remain
separate components.

Installed versions take precedence over library declarations. Exact declared pins
are used when metadata is missing; ranges (`^`, `~`, `>=`), branch names, and absent
versions are unknown. Git release tags and commit hashes are retained when given
explicitly. Unknown versions are `NOASSERTION` in SPDX; CycloneDX omits `version`
and adds `fw-sbom:version=NOASSERTION`. No version is inferred from a package name.

Known SPDX licence IDs, common unambiguous aliases, and `AND`/`OR` expressions are
normalized. Missing, custom or unsupported declarations become `NOASSERTION`
(a named licence in CycloneDX). A manifest licence array is treated as `AND`.
The tool records declarations, not a legal conclusion about licensing. The
product licence is `NOASSERTION` because v1 has no product licence input.

GitHub sources produce `pkg:github` PURLs. Other components use `pkg:generic`,
with a percent-encoded `download_url` qualifier when a source is known. Registry
landing/index URLs are source locators when no direct archive URL is available;
local paths are relative `file:` URIs. Product PURLs have no source qualifier.
No URLs are retrieved during generation.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | SBOMs written successfully |
| 1 | `--fail-on-unknown`: a dependency has an unknown version or licence; SBOMs still written |
| 2 | Input, argument or output error |

Unknowns are also printed to stderr without strict mode. The CI check covers
dependencies, excluding the user-supplied product. For example:

```sh
fw-sbom firmware --env release --fail-on-unknown --output-dir artifacts
```

Output keys/components/relationships are sorted with stable content-derived IDs,
SPDX namespaces and CycloneDX serial numbers. Only the default creation timestamp
changes. Set `--timestamp 2026-01-02T03:04:05Z` or `SOURCE_DATE_EPOCH` for byte-for-byte
reproducibility. `--serial-number urn:uuid:...` overrides the deterministic serial.
For reproducibility, use the same product metadata, project files, selected
environments/profiles and installed packages.

## GitHub Action

The local composite Action installs the CLI and uploads the generated SBOMs.
It can be used from this checkout on a Linux/macOS runner. No remote repository
or published package is needed. A firmware build or dependency installation step
should precede it if installed metadata is wanted.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ./
    with:
      project: tests/fixtures/platformio
      env: esp32
      product-name: Sensor
      product-version: '1.0'
      supplier: Example Maker
      format: both
      fail-on-unknown: 'false'
      artifact-name: firmware-sbom
```

Other inputs are `ecosystem`, `profile` and `output-dir`. The `directory` output is
the absolute output path. Artifacts are uploaded even when the unknown check
fails, while the job still fails. The wrapper needs the usual runner access to
install Python dependencies and upload artifacts; SBOM discovery itself stays
local. An offline installation can invoke the CLI directly.

## What the CRA asks for

The EU Cyber Resilience Act calls for a machine-readable SBOM in the technical
documentation for products with digital elements. Its main requirements apply
from 11 December 2027. An SBOM is only part of a technical file and does not by
itself establish compliance. This is not legal advice.

## Development

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests block network connections and validate every generated document against
vendored official schemas, resolving references locally. Fixtures cover ESP32
registry/Git/local libraries, installed platform/framework packages, Arduino
profiles and an unknown-licence project. See [schema provenance](tests/schemas/README.md)
for upstream URLs, versions, checksums and the runtime licence-ID list source.
