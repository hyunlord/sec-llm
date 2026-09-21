# -*- coding: utf-8 -*-
"""Read dependency licenses from the interpreter that produced env/versions.lock.

P7 left every package at NOASSERTION, and that was right at the time: the build
ran on a laptop where a different set of packages at different versions happened
to be importable, and reading a licence off those would have been a fabricated
attribution. The fix is not to guess better, it is to read the right machine.

So this runs on the training host, against `.venv/bin/python`, and records which
host and which interpreter it read. Three rules:

  * A package whose installed version does not match the locked version is left
    NOASSERTION with that mismatch recorded. The lock is what the gates ran on.
  * A licence is taken only from what the distribution itself declares --
    `License-Expression` (PEP 639), the legacy `License` field, or the OSI
    classifiers. Nothing is inferred from a package's name or its neighbours.
  * A package that declares nothing stays NOASSERTION and is counted as such.

    python -m tools.extract_licenses > env/package_licenses.json
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def parse_lock(text: str) -> dict:
    """`name==version` -> {name: version}.

    Deliberately duplicated from docs/common.py instead of imported: this runs
    on the training host, where the repository checkout predates the docs
    package. The two must agree, and `docs/sbom.py` refuses to build if the
    package set in the emitted record does not match its own parse of the same
    lock file, so a divergence fails the documentation build rather than
    passing silently.
    """
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, _, ver = line.partition("==")
            out[name.strip()] = ver.strip()
    return out

# Trove classifier -> SPDX identifier. Reading a declared classifier is not a
# guess; the mapping is only the translation of a fixed vocabulary. Anything
# not in this table falls through to the raw classifier string, which is
# published verbatim rather than forced into an identifier.
CLASSIFIER_SPDX = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: Common Development and Distribution License 1.0 (CDDL-1.0)": "CDDL-1.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "License :: OSI Approved :: Academic Free License (AFL)": "AFL-3.0",
    "License :: OSI Approved :: Universal Permissive License (UPL)": "UPL-1.0",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "License :: Public Domain": "LicenseRef-Public-Domain",
}

# Substrings that make a licence reciprocal in a way worth checking against the
# things this project distributes. Matched against the resolved identifier, not
# against a package name.
COPYLEFT_MARKERS = ("GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL", "CPL", "OSL", "EUPL", "SSPL")


def resolve(name: str, locked: str) -> dict:
    rec = {"name": name, "locked_version": locked, "spdx": None,
           "declared": None, "source_field": None, "classifiers": []}
    try:
        dist = md.distribution(name)
    except md.PackageNotFoundError:
        rec["note"] = "not installed in the pinned interpreter"
        return rec
    meta = dist.metadata
    installed = dist.version
    rec["installed_version"] = installed
    if installed != locked:
        rec["note"] = f"installed {installed} != locked {locked}; not attributed"
        return rec

    classifiers = [c for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
    rec["classifiers"] = classifiers
    expr = meta.get("License-Expression")
    legacy = (meta.get("License") or "").strip()

    if expr:                                    # PEP 639, already an SPDX expression
        rec["spdx"], rec["declared"], rec["source_field"] = expr.strip(), expr.strip(), "License-Expression"
    elif classifiers:
        mapped = [CLASSIFIER_SPDX[c] for c in classifiers if c in CLASSIFIER_SPDX]
        rec["declared"] = "; ".join(classifiers)
        rec["source_field"] = "Classifier"
        if mapped:
            rec["spdx"] = " AND ".join(sorted(set(mapped))) if len(set(mapped)) > 1 else mapped[0]
        else:
            rec["note"] = "classifier present but outside the translation table; not forced into an identifier"
    elif legacy and "\n" not in legacy and len(legacy) <= 64:
        # The legacy field is free text. A short single line is a declaration;
        # a pasted licence body is not an identifier and is not treated as one.
        rec["spdx"], rec["declared"], rec["source_field"] = legacy, legacy, "License"
    elif legacy:
        rec["declared"] = "full licence text in the legacy License field"
        rec["source_field"] = "License"
        rec["note"] = "legacy field contains licence text, not an identifier; not attributed"
    else:
        rec["note"] = "the distribution declares no licence metadata"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="-")
    a = ap.parse_args()

    lock = parse_lock((REPO / "env" / "versions.lock").read_text())
    packages = {name: resolve(name, ver) for name, ver in sorted(lock.items())}

    resolved = [p for p in packages.values() if p["spdx"]]
    unresolved = [p for p in packages.values() if not p["spdx"]]
    copyleft = sorted(p["name"] for p in resolved
                      if any(m in p["spdx"].upper() for m in COPYLEFT_MARKERS))

    try:
        host = subprocess.run(["hostname"], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        host = platform.node()

    out = {
        "_comment": ("Dependency licences read from the interpreter that produced env/versions.lock. "
                     "Nothing here is inferred from a package name; every value comes from the "
                     "distribution's own metadata, and the field it came from is recorded."),
        # A real timestamp, because this produces a committed record like
        # ingest/sources.lock.json does. `make docs` reads the committed value,
        # so the published documents stay byte-reproducible regardless.
        "read_on": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "read_from": {
            "host": host,
            "machine": platform.machine(),
            "interpreter": sys.executable,
            "python_version": platform.python_version(),
        },
        "method": {
            "fields_consulted": ["License-Expression", "Classifier", "License"],
            "version_check": "a package whose installed version differs from the locked version is left unattributed",
            "classifier_table": "fixed Trove -> SPDX translation; a classifier outside it is published verbatim, not forced",
            "copyleft_markers": list(COPYLEFT_MARKERS),
        },
        "counts": {
            "locked": len(lock),
            "resolved": len(resolved),
            "unresolved": len(unresolved),
            "copyleft": len(copyleft),
        },
        "copyleft_packages": copyleft,
        "unresolved_reasons": sorted({p.get("note", "unknown") for p in unresolved}),
        "packages": packages,
    }
    text = json.dumps(out, indent=1, ensure_ascii=False, sort_keys=False) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        Path(a.out).write_text(text)
        print(f"wrote {a.out}: {len(resolved)}/{len(lock)} resolved, "
              f"{len(copyleft)} copyleft, {len(unresolved)} unresolved", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
