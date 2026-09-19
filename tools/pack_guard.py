"""Refuse to pack a gate result that is fixture data, not a measurement.

A renderer dry-run fixture reached a delivered p0-artifacts.zip once. That is
the same class of defect as the P1.1 self-contradicting report: test state
reaching a deliverable. Every signature that fixture had is rejected here, and
the check runs before zip so a fixture cannot be packed at all.

Usage: python tools/pack_guard.py [path/to/gate0.json]
Exit 0 = safe to pack. Exit 1 = refuse, with the reason on stderr.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Host names the renderer fixture has been seen to carry. A real gate run
# happens on the DGX, whose hostname is not any of these.
FIXTURE_HOSTS = {"10.nate.com", "fixture", "localhost", "example.invalid", "test-host"}

# A check whose runner_duration_sec is exactly 1.0 to the last digit did not run
# a model load; it was hand-written. Real durations carry sub-second noise.
FIXTURE_DURATION = 1.0


def problems(gate: dict) -> list[str]:
    out: list[str] = []
    summary = gate.get("summary") or {}
    checks = gate.get("checks")

    if not isinstance(checks, dict) or not checks:
        out.append("checks object is empty -- no check ever ran; this is not a gate result")
        return out  # nothing below is meaningful without checks

    host = str(summary.get("host") or "")
    if host in FIXTURE_HOSTS:
        out.append(f"summary.host is a fixture value: {host!r}")

    exact = [
        cid for cid, c in checks.items()
        if c.get("runner_duration_sec") == FIXTURE_DURATION or c.get("duration_sec") == FIXTURE_DURATION
    ]
    if exact:
        out.append(f"checks {sorted(exact)} report a duration of exactly {FIXTURE_DURATION}s -- fixture, not measurement")

    all_one = all(
        (c.get("runner_duration_sec") or c.get("duration_sec")) == FIXTURE_DURATION for c in checks.values()
    )
    if all_one and len(checks) > 1:
        out.append("every check reports an identical duration -- fixture, not measurement")

    sc = summary.get("checks") or {}
    if isinstance(sc, dict) and sc and all(v.get("duration_sec") == FIXTURE_DURATION for v in sc.values()):
        out.append("summary.checks durations are all exactly 1.0s -- fixture, not measurement")

    for cid, c in checks.items():
        if not isinstance(c.get("data"), dict) or not c["data"]:
            out.append(f"check {cid} has no data payload -- it did not run")
    return out


def main(argv=None) -> int:
    path = Path((argv or sys.argv[1:] or ["env/gate0.json"])[0])
    if not path.exists():
        print(f"pack_guard: {path} does not exist; nothing to pack", file=sys.stderr)
        return 1
    try:
        gate = json.loads(path.read_text())
    except Exception as exc:
        print(f"pack_guard: {path} is not valid JSON: {exc!r}", file=sys.stderr)
        return 1
    probs = problems(gate)
    if probs:
        print(f"pack_guard: REFUSING to pack {path}:", file=sys.stderr)
        for p in probs:
            print(f"  - {p}", file=sys.stderr)
        return 1
    n = len(gate["checks"])
    print(f"pack_guard: {path} looks like a real gate result "
          f"({n} checks, host={gate['summary'].get('host')!r}); ok to pack")
    return 0


if __name__ == "__main__":
    sys.exit(main())
