#!/usr/bin/env python3
"""Validate checked-in cake-gate/1 fixtures against the schema copy.

The gate binary is standard-library only; this optional check covers the
machine-readable schema when the `jsonschema` module is installed. Without it,
the Go fixture tests still enforce the same required fields and conditional
rules, so the skip is not a silent pass of the contract.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "docs" / "cake-gate-1.schema.json"
FIXTURES = ROOT / "tests" / "fixtures"


def main() -> int:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        print("schema-check skipped: python module 'jsonschema' is not installed")
        print("install it with: python3 -m pip install --user jsonschema")
        return 0

    schema = json.loads(SCHEMA_PATH.read_text())
    fixtures = [
        "describe.json",
        "init.json",
        "check.json",
        "decision_block.json",
        "decision_allow.json",
        "error.json",
        "ready.json",
        "shutdown.json",
    ]
    failed = False
    for name in fixtures:
        instance = json.loads((FIXTURES / name).read_text())
        try:
            jsonschema.validate(instance, schema)
        except jsonschema.ValidationError as error:
            failed = True
            print(f"{name}: {error.message}")
        else:
            print(f"{name}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
