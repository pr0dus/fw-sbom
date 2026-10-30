"""SPDX 2.3 and CycloneDX 1.6 serialization of the same inventory."""

import hashlib
import json
import uuid

from . import __version__
from .licenses import IDS
from .model import Component, Inventory


def identity(root: Component, inventory: Inventory, supplier: str | None = None) -> str:
    payload = [__version__, root.__dict__, supplier, [item.__dict__ for item in inventory.sorted_components()]]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def spdx(root: Component, inventory: Inventory, timestamp: str, supplier: str | None = None) -> dict:
    def package(item: Component, product: bool = False) -> dict:
        result = {
            "SPDXID": "SPDXRef-Product" if product else item.id,
            "name": item.name,
            "versionInfo": item.version or "NOASSERTION",
            "downloadLocation": item.source or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": item.license,
            "copyrightText": "NOASSERTION",
            "supplier": (supplier if supplier.startswith(("Person: ", "Organization: "))
                         else "Organization: " + supplier) if product and supplier else "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION" if product else "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": item.purl}],
        }
        if item.contexts:
            result["comment"] = "Observed in " + ", ".join(item.contexts)
        return result

    dependencies = inventory.sorted_components()
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": "SPDXRef-Product"}]
    relationships.extend({"spdxElementId": "SPDXRef-Product", "relationshipType": "DEPENDS_ON",
                          "relatedSpdxElement": item.id} for item in dependencies)
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": root.name + " SBOM",
        "documentNamespace": "https://fw-sbom.local/spdx/" + identity(root, inventory, supplier),
        "creationInfo": {"created": timestamp, "creators": [f"Tool: fw-sbom-{__version__}"]},
        "documentDescribes": ["SPDXRef-Product"],
        "packages": [package(root, True)] + [package(item) for item in dependencies],
        "relationships": sorted(relationships, key=lambda row: (row["spdxElementId"], row["relatedSpdxElement"])),
    }


def cyclonedx(root: Component, inventory: Inventory, timestamp: str,
              supplier: str | None = None, serial: str | None = None) -> dict:
    def package(item: Component, product: bool = False) -> dict:
        result = {"type": item.kind, "bom-ref": "SPDXRef-Product" if product else item.id,
                  "name": item.name, "purl": item.purl}
        if item.version:
            result["version"] = item.version
        else:
            result["properties"] = [{"name": "fw-sbom:version", "value": "NOASSERTION"}]
        if item.license in IDS:
            result["licenses"] = [{"license": {"id": item.license}}]
        elif item.license == "NOASSERTION":
            result["licenses"] = [{"license": {"name": "NOASSERTION"}}]
        else:
            result["licenses"] = [{"expression": item.license}]
        if item.contexts:
            result.setdefault("properties", []).append({"name": "fw-sbom:contexts", "value": ",".join(item.contexts)})
        if item.source:
            result["externalReferences"] = [{"type": "distribution", "url": item.source}]
        if product and supplier:
            result["supplier"] = {"name": supplier.removeprefix("Organization: ").removeprefix("Person: ")}
        return result

    dependencies = inventory.sorted_components()
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": serial or "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, identity(root, inventory, supplier))),
        "metadata": {"timestamp": timestamp, "tools": [{"vendor": "fw-sbom", "name": "fw-sbom", "version": __version__}],
                     "component": package(root, True)},
        "components": [package(item) for item in dependencies],
        "dependencies": [{"ref": "SPDXRef-Product", "dependsOn": sorted(item.id for item in dependencies)}],
    }
