#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run bounded local gates and retain actual command output and exit codes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openbao", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commands = [
        ["rustc", "--version"],
        ["cargo", "fmt", "--all", "--check"],
        ["cargo", "build", "--offline", "--locked"],
        ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--", "-D", "warnings"],
        ["cargo", "test", "--offline", "--locked", "--", "--nocapture"],
        ["cargo", "doc", "--offline", "--locked", "--no-deps"],
    ]
    if args.openbao:
        commands.append([
            "cargo", "test", "--offline", "--locked", "--test", "broker",
            "openbao_live_broker_flow", "--", "--ignored", "--exact", "--nocapture",
        ])
    commands.extend([
        [sys.executable, "check_license.py"],
        [sys.executable, "scripts/private_material_scan.py"],
        [sys.executable, "scripts/docs_linkcheck.py"],
        ["gitleaks", "dir", ".", "--config", ".gitleaks.toml", "--no-banner", "--redact", "--exit-code", "1"],
        ["git", "diff", "--check"],
    ])
    env = dict(os.environ, RUSTDOCFLAGS="-D warnings", NO_COLOR="1")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    failed = False
    with args.output.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"Local Warden verification, {datetime.now(timezone.utc).isoformat()}; no remote CI or qualification claim.\n")
        source = hashlib.sha256()
        paths = [root / "Cargo.toml", root / "Cargo.lock", Path(__file__).resolve()]
        paths += list((root / "src").rglob("*.rs")) + list((root / "tests").rglob("*.rs"))
        paths += list((root / "tests/fixtures").glob("*.json"))
        for path in sorted(paths):
            source.update(path.relative_to(root).as_posix().encode() + b"\0")
            source.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
        log.write(f"Source input SHA-256 (sorted paths, NUL, LF-normalized bytes, NUL): {source.hexdigest()}\n")
        log.write("Initial development failures: time-helper type mismatch; four-edge fixture registration names; collapsible-match lint. Corrected before this retained run; golden vectors unchanged.\n")
        log.flush()
        for command in commands:
            label = " ".join(["python" if command[0] == sys.executable else command[0], *command[1:]])
            print(f"Running: {label}", flush=True)
            try:
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)
                output = result.stdout + result.stderr
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                output = f"Unavailable or timed out: {type(exc).__name__}\n"
                code = 125
            output = output.replace(str(root), "<repository>").replace(str(Path.home()), "<home>")
            log.write(f"\n$ {label}\n{output}\nexit: {code}\n")
            log.flush()
            print(f"Exit: {code}", flush=True)
            failed |= code != 0
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
