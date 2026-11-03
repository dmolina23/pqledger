#!/usr/bin/env python3
"""Validate a CycloneDX 1.6 document against the official JSON schema.

Usage: validate_cbom.py cbom.json

The schema files are downloaded from the CycloneDX specification repository
(or read from $CYCLONEDX_SCHEMA_DIR if set). Requires: jsonschema, referencing.
"""
import json
import os
import pathlib
import sys
import tempfile
import urllib.request

from jsonschema import Draft7Validator
from referencing import Registry, Resource

BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/"
FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


def load(name: str, cache: pathlib.Path) -> dict:
    path = cache / name
    if not path.exists():
        with urllib.request.urlopen(BASE + name, timeout=30) as resp:
            path.write_bytes(resp.read())
    return json.loads(path.read_text())


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    cache = pathlib.Path(os.environ.get("CYCLONEDX_SCHEMA_DIR") or tempfile.mkdtemp(prefix="cdx-"))
    cache.mkdir(parents=True, exist_ok=True)
    bom_schema, spdx, jsf = (load(n, cache) for n in FILES)

    registry = Registry().with_resources(
        (doc["$id"], Resource.from_contents(doc)) for doc in (spdx, jsf)
    )
    validator = Draft7Validator(bom_schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)

    with open(sys.argv[1], encoding="utf-8") as fh:
        document = json.load(fh)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    for err in errors:
        where = "/".join(str(p) for p in err.absolute_path) or "(root)"
        print(f"INVALID {where}: {err.message[:200]}")
    if errors:
        return 1
    print(f"OK: valid CycloneDX {document.get('specVersion')} ({len(document.get('components', []))} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
