"""
verify_run.py
=============

Verify the integrity of an archive_triangulator run directory.

Usage:
    python verify_run.py /path/to/triangulator_output/example.gov/20260508T120000Z

Exit codes:
    0 - all checks pass
    1 - hash mismatch (file altered)
    2 - missing file
    3 - manifest invalid or unreadable
    4 - GPG signature failed (only if .asc present)
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: verify_run.py <run_directory>", file=sys.stderr)
        return 3

    run_dir = Path(argv[1])
    manifest_path = run_dir / "MANIFEST.json"
    if not manifest_path.exists():
        print(f"ERROR: no MANIFEST.json in {run_dir}", file=sys.stderr)
        return 3

    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: manifest is not valid JSON: {exc}", file=sys.stderr)
        return 3

    print(f"Verifying run: {manifest.get('domain')} captured at "
          f"{manifest.get('captured_at_utc')}")
    print(f"Tool version: {manifest.get('version')}")
    print(f"Files to verify: {len(manifest.get('files', []))}")
    print()

    errors = 0
    for entry in manifest.get("files", []):
        rel = entry["path"]
        expected_hash = entry["sha256"]
        expected_size = entry["size_bytes"]
        path = run_dir / rel
        if not path.exists():
            print(f"  MISSING  {rel}")
            errors += 1
            continue
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            print(f"  SIZE FAIL {rel} (expected {expected_size}, got {actual_size})")
            errors += 1
            continue
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            print(f"  HASH FAIL {rel}")
            errors += 1
        else:
            print(f"  OK       {rel}")

    if errors:
        print(f"\n{errors} verification failure(s).")
        return 1 if errors > 0 else 2

    print("\nAll file hashes match manifest.")

    # GPG signature check (optional)
    sig_path = run_dir / "MANIFEST.json.asc"
    if sig_path.exists():
        print("\nChecking GPG signature...")
        try:
            result = subprocess.run(
                ["gpg", "--verify", str(sig_path), str(manifest_path)],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print("GPG signature: VALID")
                print(result.stderr)
            else:
                print("GPG signature: INVALID")
                print(result.stderr)
                return 4
        except FileNotFoundError:
            print("WARNING: gpg not installed, signature not verified")

    print("\nVerification complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
