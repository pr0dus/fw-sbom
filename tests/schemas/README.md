# Vendored official JSON schemas

Downloaded 2026-10-30. Files are unmodified upstream bytes. Tests use only these
local files, including all external `$ref` targets; remote retrieval is forbidden.

SPDX schema: official SPDX specification tag `v2.3`.
CycloneDX schemas: official specification tag `1.6`; the BOM schema declares
Apache-2.0 licensing. The companion SPDX ID enumeration is version `v1.0-3.23`.
The root MIT licence applies to fw-sbom code, not the upstream schema files.

| File | Official source | SHA-256 |
| --- | --- | --- |
| `spdx/spdx-schema.json` | [upstream](https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json) | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` |
| `cyclonedx/bom-1.6.schema.json` | [upstream](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json) | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `cyclonedx/spdx.schema.json` | [upstream](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json) | `baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e` |
| `cyclonedx/jsf-0.82.schema.json` | [upstream](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/jsf-0.82.schema.json) | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

The runtime file `src/fw_sbom/data/spdx-ids.json` is the unchanged `enum` array
from `cyclonedx/spdx.schema.json`, reserialized as indented JSON. This keeps
licence recognition offline and aligned with the official CycloneDX 1.6 validator.
No runtime schema validator or access to the tests directory is required.

To refresh, download only the official schemas above and any new referenced
schemas, update these checksums and the derived ID list, then run the offline tests.
