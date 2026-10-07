#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export the public identity-only source package with exact file digests.

The consumer supplies Cargo dependency pins and may not edit the exported source.
This exports verification code only; it grants no trust or contract acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ("identity-core/lib.rs", "src/encoding.rs", "src/principal.rs", "src/policy.rs", "LICENSE", "NOTICE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        parser.error("export destination must be outside the source repository")
    records = {}
    for name in FILES:
        raw = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        records[name] = hashlib.sha256(raw).hexdigest()
    (destination / "source-lock.json").write_text(json.dumps({
        "schema_version": 1,
        "repository": "https://github.com/iokaio/munarium-warden",
        "source": "content-addressed workspace export; not a release",
        "files": records,
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
