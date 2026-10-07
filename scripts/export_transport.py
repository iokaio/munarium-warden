#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export the owner-maintained Stage 1 mTLS adapter without identity or broker code."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("destination", type=Path)
destination = parser.parse_args().destination.resolve()
if destination == ROOT or ROOT in destination.parents:
    parser.error("destination must be outside the source repository")
destination.mkdir(parents=True, exist_ok=True)
records = {}
for source in ("src/service_transport.rs", "LICENSE", "NOTICE"):
    name = Path(source).name
    raw = (ROOT / source).read_bytes().replace(b"\r\n", b"\n")
    (destination / name).write_bytes(raw)
    records[name] = hashlib.sha256(raw).hexdigest()
(destination / "source-lock.json").write_text(json.dumps({"schema_version": 1,
    "repository": "https://github.com/iokaio/munarium-warden",
    "source": "content-addressed workspace export; not a release", "files": records}, indent=2) + "\n", encoding="utf-8")
