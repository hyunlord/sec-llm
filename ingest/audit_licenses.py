"""Audit: a permission asserted in a field must appear in that field's evidence.

The defect this exists to prevent: `commercial_status` read
`permitted_with_attribution` for CVE List while the evidence recorded beside it
said the word "commercial" does not appear in the CVE Terms of Use. The prose
was honest and the machine-readable field was not, and only the prose was ever
read by a human.

Run as `python -m ingest.audit_licenses`. Non-zero exit means a field claims
something its own quoted evidence does not support.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.sources import SOURCE_ORDER, SOURCES  # noqa: E402

# A status that asserts a permission must be backed by evidence containing at
# least one of these. `not_addressed`/`unknown`/`prohibited` assert no
# permission and are checked differently.
ASSERTS_PERMISSION = {"permitted", "permitted_with_attribution"}

# A keyword search alone is not enough, and the first version of this audit
# proved it: CVE's evidence contains the word "commercial" inside the sentence
# "the word 'commercial' does not appear in the CVE Terms of Use", so a naive
# match saw the keyword and passed the very defect this file exists to catch.
# An explicit statement of absence therefore contradicts any asserted
# permission, and is checked before the keyword match.
NEGATION_PATTERNS = {
    "commercial_status": [
        r'word\s+"?commercial"?\s+does not appear',
        r'does not (?:mention|address|state|say)[^.]{0,40}commercial',
        r'no (?:explicit )?(?:mention|statement) of commercial',
        r'silent[^.]{0,40}commercial',
    ],
    "redistribution_status": [
        r'does not (?:mention|address|permit|allow)[^.]{0,40}(?:redistribut|distribut)',
        r'silent[^.]{0,40}(?:redistribut|distribut)',
        r'prohibit[^.]{0,20}(?:redistribut|distribut)',
    ],
    "model_publication_status": [
        r'do(?:es)? not mention[^.]{0,60}(?:machine learning|training|model weight)',
        r'silent on[^.]{0,60}(?:machine learning|training|model weight)',
        r'not settled',
    ],
}

FIELD_KEYWORDS = {
    "redistribution_status": [
        r"\bdistribute\b", r"\bredistribut", r"\breproduce\b", r"\bpublic domain\b", r"\bcopy\b",
    ],
    "commercial_status": [
        r"\bcommercial\b", r"\bcommercially\b",
    ],
    "model_publication_status": [
        r"\bmodel weight", r"\btrain(ing|ed)\b", r"\bmachine learning\b",
    ],
}

EVIDENCE_FIELD = {
    "redistribution_status": "license_evidence",
    "commercial_status": "license_evidence",
    "model_publication_status": "weights_release_evidence",
}


def audit() -> list[str]:
    problems: list[str] = []
    for sid in SOURCE_ORDER:
        lic = SOURCES[sid]["license"]
        for field, patterns in FIELD_KEYWORDS.items():
            status = lic.get(field)
            evidence = lic.get(EVIDENCE_FIELD[field], "") or ""
            hits = [p for p in patterns if re.search(p, evidence, re.I)]

            negations = [
                n for n in NEGATION_PATTERNS.get(field, [])
                if re.search(n, evidence, re.I)
            ]

            if status in ASSERTS_PERMISSION:
                if negations:
                    problems.append(
                        f"{sid}.{field} = '{status}' asserts a permission, but its own evidence "
                        f"explicitly records the ABSENCE of that permission "
                        f"(matched: {negations[0]!r}). The prose and the field disagree."
                    )
                elif not hits:
                    problems.append(
                        f"{sid}.{field} = '{status}' asserts a permission, but its evidence "
                        f"contains none of {patterns}. Either the field overclaims or the "
                        f"evidence is missing the sentence that supports it."
                    )
            elif status == "not_addressed":
                # The claim is that the document is silent. Evidence must say so.
                if not re.search(r"do(es)? not (mention|address|appear|say)|silent|not settled|"
                                 r"does not appear|no field-of-use|not mention",
                                 evidence, re.I):
                    problems.append(
                        f"{sid}.{field} = 'not_addressed' claims the licence is silent, but its "
                        f"evidence does not record that absence."
                    )
            elif status == "unknown":
                if not evidence.strip():
                    problems.append(f"{sid}.{field} = 'unknown' with no note on what was checked")
    return problems


def main() -> int:
    problems = audit()
    for sid in SOURCE_ORDER:
        lic = SOURCES[sid]["license"]
        print(f"{sid:9} redistribution={lic['redistribution_status']:26} "
              f"commercial={lic['commercial_status']:26} "
              f"model_publication={lic['model_publication_status']}")
    print()
    if problems:
        print(f"{len(problems)} PROBLEM(S):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("AUDIT PASSED: every asserted permission appears in its own quoted evidence, "
          "and every 'not_addressed' records the absence it claims")
    return 0


if __name__ == "__main__":
    sys.exit(main())
