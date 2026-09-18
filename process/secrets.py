"""Stage 5 -- secret and PII detection.

Two rules govern this file and both are absolute.

**Never write a detected secret value anywhere.** Not into reports, not into
logs, not into test fixtures, not into the manifest. Counts by type, field and
source only. A secret-scanning pipeline that commits the secrets it found is a
security incident with a nice report attached.

**Public malicious indicators are not secrets.** Malware C2 domains, attacker
IP addresses and file hashes in ATT&CK references and CVE writeups are the IOC
content of this corpus -- masking them destroys the thing it exists for. The
distinction drawn here is between a credential that leaked into a URL and an
indicator that is the point of the record.

Pseudonyms are stable across the corpus: the same value always maps to the same
`USER_7f31` / `HOST_c2a9`, so co-occurrence structure survives masking. Real
secrets get an unrecoverable marker instead -- a pseudonym would imply the value
could be recovered, and for a live credential that is the wrong promise.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.common import INDEX_PATH, PROCESSED, REPO, iter_jsonl, peak_rss_bytes  # noqa: E402
from process.textract import extract  # noqa: E402

# --- ruleset ---------------------------------------------------------------
# Patterns follow the shapes published by the providers themselves (GitHub,
# AWS, Slack, Google) rather than being invented here; entropy is used as a
# secondary filter on the generic high-entropy rule only, because applying it
# broadly flags every base64 blob and file hash in the corpus.
RULES: list[tuple[str, re.Pattern, bool]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), False),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), False),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), False),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), False),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), False),
    # Capture only the userinfo. Redacting the whole URL would also destroy the
    # scheme and host, which are legitimate signal -- the credential is the part
    # that must not survive.
    ("credentials_in_url",
     re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://([^\s/:@]+:[^\s/@]+)@[^\s/]+"), False),
    ("generic_secret_assignment",
     re.compile(r"(?i)\b(?:api[_\-]?key|secret|passwd|password|token|auth[_\-]?token)\b\s*[:=]\s*"
                r"[\"']?([A-Za-z0-9/+_\-]{16,})[\"']?"), True),
]

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:internal|local|corp|lan|intranet|test)\b", re.I)

# Example/documentation values that are not real. Counting them as findings
# would inflate every number in the report with noise.
PLACEHOLDER_EMAIL = re.compile(
    r"(?i)\b(?:example|test|user|admin|foo|bar|someone|name|email|your|xxx|abc|a)@"
    r"(?:example\.(?:com|org|net)|test\.com|domain\.com|email\.com|localhost)\b"
)
PLACEHOLDER_TOKENS = re.compile(r"(?i)^(?:x{8,}|a{8,}|0{8,}|1{8,}|<[^>]+>|\$\{[^}]+\}|your[_\-]?\w+|placeholder\w*)$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_private_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def pseudonym(kind: str, value: str) -> str:
    """Stable across the corpus: same value -> same pseudonym, always."""
    h = hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:4]
    return f"{kind.upper()}_{h}"


REDACTION = "[REDACTED_SECRET]"


def scan_text(text: str, *, source_id: str = "", content_type: str = "") -> list[dict]:
    """Return findings as TYPE + LOCATION ONLY. The matched value never leaves.

    A finding carries a salted digest of the value so the same secret can be
    counted once across the corpus, and nothing else. The digest is one-way and
    is never rendered into a report.
    """
    findings: list[dict] = []

    def add(kind, value, category, action):
        findings.append({
            "type": kind,
            "category": category,
            "action": action,
            # Identity for counting only. Not reversible, never reported.
            "value_id": hashlib.sha256(("sec-llm-p2:" + value).encode()).hexdigest()[:12],
            "length": len(value),
        })

    for name, pat, use_entropy in RULES:
        for m in pat.finditer(text):
            val = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            if PLACEHOLDER_TOKENS.match(val or ""):
                continue
            if use_entropy and shannon_entropy(val) < 3.5:
                continue
            add(name, val, "secret", "redact")

    for m in EMAIL_RE.finditer(text):
        val = m.group(0)
        if PLACEHOLDER_EMAIL.match(val):
            continue
        add("email", val, "pii", "pseudonymize")

    for m in HOSTNAME_RE.finditer(text):
        add("internal_hostname", m.group(0), "pii", "pseudonymize")

    for m in IPV4_RE.finditer(text):
        val = m.group(0)
        if is_private_ip(val):
            add("private_ip", val, "pii", "pseudonymize")
        # A routable IP in this corpus is an IOC, not a leak. Not a finding.

    return findings


def redact(text: str) -> str:
    """Apply the masking policy. Secrets vanish; PII becomes a stable pseudonym."""
    out = text
    for name, pat, use_entropy in RULES:
        def _sub(m, _u=use_entropy):
            val = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            if PLACEHOLDER_TOKENS.match(val or ""):
                return m.group(0)
            if _u and shannon_entropy(val) < 3.5:
                return m.group(0)
            return m.group(0).replace(val, REDACTION)
        out = pat.sub(_sub, out)
    out = EMAIL_RE.sub(lambda m: m.group(0) if PLACEHOLDER_EMAIL.match(m.group(0))
                       else pseudonym("user", m.group(0)), out)
    out = HOSTNAME_RE.sub(lambda m: pseudonym("host", m.group(0)), out)
    out = IPV4_RE.sub(lambda m: pseudonym("ip", m.group(0)) if is_private_ip(m.group(0))
                      else m.group(0), out)
    return out


def scan_corpus() -> dict:
    t0 = time.time()
    by_type = Counter()
    by_source = Counter()
    by_source_type: dict[str, Counter] = defaultdict(Counter)
    by_category = Counter()
    unique_values: dict[str, set] = defaultdict(set)
    records_with_findings = Counter()
    scanned = 0

    for row in iter_jsonl(INDEX_PATH):
        scanned += 1
        f = scan_text(row["text"], source_id=row["source_id"], content_type=row["content_type"])
        if not f:
            continue
        records_with_findings[row["source_id"]] += 1
        for item in f:
            by_type[item["type"]] += 1
            by_source[row["source_id"]] += 1
            by_source_type[row["source_id"]][item["type"]] += 1
            by_category[item["category"]] += 1
            unique_values[item["type"]].add(item["value_id"])

    return {
        "records_scanned": scanned,
        "findings_total": sum(by_type.values()),
        "findings_by_type": dict(by_type.most_common()),
        "unique_values_by_type": {k: len(v) for k, v in sorted(unique_values.items())},
        "findings_by_source": dict(by_source),
        "findings_by_source_and_type": {s: dict(c) for s, c in sorted(by_source_type.items())},
        "findings_by_category": dict(by_category),
        "records_with_findings": dict(records_with_findings),
        "elapsed_seconds": round(time.time() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "policy": {
            "secrets": "replaced with an unrecoverable marker",
            "pii": "replaced with a stable pseudonym so co-occurrence structure survives",
            "public_iocs": "NOT masked -- routable IPs, C2 domains and file hashes are the "
                           "IOC content of this corpus",
            "values_recorded": "never; counts and one-way digests only",
        },
    }


def scan_repo() -> int:
    """Gate 2 condition 7: scan the committed tree with the same ruleset."""
    import subprocess

    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True).stdout.split()
    total = 0
    per_file = Counter()
    for rel in files:
        p = REPO / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # The ruleset itself contains the patterns; matching them would be
        # circular. Findings inside process/secrets.py are its own definitions.
        if rel == "process/secrets.py":
            continue
        f = [x for x in scan_text(text) if x["category"] == "secret"]
        if f:
            per_file[rel] = len(f)
            total += len(f)
    print(f"scanned {len(files)} committed files with the P2 ruleset")
    if total:
        print(f"FAIL: {total} secret-category findings in the committed tree:")
        for rel, n in per_file.most_common():
            # Filename and count only -- never the value.
            print(f"  {rel}: {n} finding(s)")
        return 1
    print("ZERO secret-category findings in the committed tree")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-repo", action="store_true")
    args = ap.parse_args()
    if args.scan_repo:
        sys.exit(scan_repo())
    out = scan_corpus()
    print(json.dumps(out, indent=2, ensure_ascii=False))
