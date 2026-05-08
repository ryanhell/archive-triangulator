"""
diff_runs.py
============

Compare two archive_triangulator runs for the same domain captured at
different times. The critical output is any (timestamp, url) pair from
the Wayback CDX whose `digest` field changed between the two runs —
this is the mathematical signature of a post-hoc alteration to a
historical snapshot.

Usage:
    python diff_runs.py <run_dir_1> <run_dir_2>
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def load_wayback(run_dir: Path) -> dict[tuple[str, str], dict]:
    """Load wayback CDX into a dict keyed by (timestamp, url)."""
    path = run_dir / "wayback_cdx.jsonl"
    out: dict[tuple[str, str], dict] = {}
    if not path.exists():
        return out
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            key = (row["timestamp"], row["original_url"])
            out[key] = row
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("Usage: diff_runs.py <run_dir_1> <run_dir_2>", file=sys.stderr)
        return 2

    a = Path(argv[1])
    b = Path(argv[2])
    wb_a = load_wayback(a)
    wb_b = load_wayback(b)

    keys_a = set(wb_a.keys())
    keys_b = set(wb_b.keys())

    appeared = keys_b - keys_a       # in newer, not in older
    disappeared = keys_a - keys_b    # in older, not in newer
    common = keys_a & keys_b

    digest_changes = []
    for k in common:
        if wb_a[k]["digest"] != wb_b[k]["digest"]:
            digest_changes.append({
                "timestamp": k[0],
                "url": k[1],
                "old_digest": wb_a[k]["digest"],
                "new_digest": wb_b[k]["digest"],
                "old_status": wb_a[k]["statuscode"],
                "new_status": wb_b[k]["statuscode"],
            })

    print(f"Run A: {a}")
    print(f"  Wayback entries: {len(wb_a)}")
    print(f"Run B: {b}")
    print(f"  Wayback entries: {len(wb_b)}")
    print()
    print(f"Common (timestamp, url) pairs:   {len(common)}")
    print(f"Captures appeared in B not A:    {len(appeared)}")
    print(f"Captures disappeared from A->B:  {len(disappeared)}")
    print(f"DIGEST CHANGES on common pairs:  {len(digest_changes)}")
    print()

    if digest_changes:
        print("=" * 70)
        print("DIGEST CHANGES — historical snapshot content reportedly altered")
        print("=" * 70)
        for change in digest_changes[:50]:
            print(json.dumps(change, indent=2))
            print()
        if len(digest_changes) > 50:
            print(f"... and {len(digest_changes) - 50} more")

    if appeared:
        print()
        print("Sample of new captures (in B, not in A):")
        for k in list(appeared)[:10]:
            print(f"  {k[0]}  {k[1]}")

    if disappeared:
        print()
        print("Sample of vanished captures (in A, not in B):")
        for k in list(disappeared)[:10]:
            print(f"  {k[0]}  {k[1]}")

    # Write a structured diff report
    out_path = b / "diff_against_previous.json"
    out_path.write_text(json.dumps({
        "run_a": str(a),
        "run_b": str(b),
        "summary": {
            "common": len(common),
            "appeared_in_b": len(appeared),
            "disappeared_from_a": len(disappeared),
            "digest_changes": len(digest_changes),
        },
        "digest_changes": digest_changes,
        "appeared": [{"timestamp": k[0], "url": k[1]} for k in sorted(appeared)],
        "disappeared": [{"timestamp": k[0], "url": k[1]} for k in sorted(disappeared)],
    }, indent=2))
    print(f"\nStructured diff written to: {out_path}")

    return 0 if not digest_changes else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
