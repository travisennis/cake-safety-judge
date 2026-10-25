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
    targets = {
        "describe.json": schema["$defs"]["describe"],
        "init.json": schema["$defs"]["frame"],
        "check.json": schema["$defs"]["frame"],
        "decision_block.json": schema["$defs"]["frame"],
        "decision_allow.json": schema["$defs"]["frame"],
        "error.json": schema["$defs"]["frame"],
        "ready.json": schema["$defs"]["frame"],
        "shutdown.json": schema["$defs"]["frame"],
    }
    failed = False
    for name, target in sorted(targets.items()):
        instance = json.loads((FIXTURES / name).read_text())
        try:
            jsonschema.validate(instance, target)
        except jsonschema.ValidationError as error:
            failed = True
            print(f"{name}: {error.message}")
        else:
            print(f"{name}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
