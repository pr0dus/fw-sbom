"""Conservative normalization using the IDs shipped with the official CDX schema."""

import json
import re
from importlib.resources import files

IDS = frozenset(json.loads(files("fw_sbom").joinpath("data/spdx-ids.json").read_text()))
_IDS_BY_CASE = {value.casefold(): value for value in IDS}
_ALIASES = {
    "mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "gplv2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
}


def normalize_license(value: object) -> str:
    """Unknown/custom declarations stay NOASSERTION; do not infer from prose."""
    if isinstance(value, list):
        values = [normalize_license(item) for item in value]
        if not values or "NOASSERTION" in values:
            return "NOASSERTION"
        return " AND ".join(f"({item})" if " " in item else item for item in values)
    if not isinstance(value, str) or not value.strip():
        return "NOASSERTION"
    value = value.strip()
    direct = _IDS_BY_CASE.get(value.casefold()) or _ALIASES.get(value.casefold())
    if direct:
        return direct
    # Small expression parser: parentheses, AND and OR. WITH is conservative:
    # exception identifiers are not part of the vendored license-ID enumeration.
    tokens = re.findall(r"\(|\)|[^\s()]+", value)
    position = 0

    def atom() -> str:
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token == "(":
            result = expression()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
            return f"({result})"
        if token.casefold() not in _IDS_BY_CASE:
            raise ValueError
        return _IDS_BY_CASE[token.casefold()]

    def expression() -> str:
        nonlocal position
        result = atom()
        while position < len(tokens) and tokens[position] in {"AND", "OR"}:
            op = tokens[position]
            position += 1
            result += f" {op} {atom()}"
        return result

    try:
        result = expression()
        return result if position == len(tokens) else "NOASSERTION"
    except ValueError:
        return "NOASSERTION"
