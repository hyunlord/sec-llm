"""`make pin` -- resolve every source to an immutable reference.

Pinning is deliberately a separate command from ingestion. If resolving a pin
were a side effect of `make ingest`, then "re-run the ingester" would silently
mean "fetch today's HEAD", Gate 1's byte-identical requirement could never hold,
and the failure would be invisible rather than loud.

This command performs metadata requests only -- commit SHAs, release tags, git
blob IDs, HTTP HEAD. It downloads no corpus data. Content digests belong in the
manifests, which are produced by ingestion; what belongs here is the immutable
name of the thing to fetch.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common.fetch import get_json, head, http_get  # noqa: E402
from ingest.sources import SOURCES  # noqa: E402

LOCK_PATH = REPO / "ingest" / "sources.lock.json"
GITHUB_API = "https://api.github.com"
LOCK_SCHEMA_VERSION = 1


def _gh_headers() -> dict:
    """Authenticate to the GitHub API if a token is available.

    All of this is public metadata, so a token is not required -- but the
    anonymous limit is 60 requests/hour per IP and pinning four sources plus any
    earlier tooling exhausts it easily. A token raises it to 5000/hour. Read
    from the environment, falling back to the gh CLI's stored credential; never
    committed, and never logged.
    """
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                token = r.stdout.strip()
        except Exception:
            token = None
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _gh(path: str) -> dict:
    return get_json(f"{GITHUB_API}/{path.lstrip('/')}", headers=_gh_headers())


def pin_cve_list(cfg: dict, override: str | None = None) -> dict:
    repo = cfg["repo"]
    if override:
        commit = _gh(f"repos/{repo}/commits/{override}")
    else:
        commit = _gh(f"repos/{repo}/commits/main")
    sha = commit["sha"]
    meta = _gh(f"repos/{repo}")
    return {
        "pin_type": "git_commit",
        "repo": repo,
        "clone_url": f"https://github.com/{repo}.git",
        "commit_sha": sha,
        "commit_date": commit["commit"]["committer"]["date"],
        "commit_message_first_line": commit["commit"]["message"].split("\n")[0],
        "repo_packed_size_kb": meta.get("size"),
        "resolved_ref": override or "main",
    }


def pin_nvd(cfg: dict, snapshot: str | None = None) -> dict:
    """Pin NVD to a snapshot instant plus the exact query parameters.

    NVD is the one source here with no immutable server-side reference. There is
    no dated feed file any more and the API always serves current data, so a
    "pin" can only be a cutoff instant plus the parameters used. Ingestion
    applies the cutoff client-side against each record's `lastModified`, which
    makes the *record set* deterministic; it cannot make the *content* of a
    record that upstream edited after the cutoff deterministic. That limitation
    is recorded here and in reports/ingest.md rather than papered over.
    """
    snap = snapshot or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    probe = get_json(cfg["source_url"], params={"resultsPerPage": 1, "startIndex": 0})
    return {
        "pin_type": "api_snapshot",
        "api_base": cfg["source_url"],
        "snapshot_instant_utc": snap,
        "params": {
            "resultsPerPage": cfg["results_per_page"],
            "startIndex": "<paged 0..totalResults>",
        },
        "cutoff_field": "cve.lastModified",
        "cutoff_rule": "include record iff lastModified <= snapshot_instant_utc",
        "api_format": probe.get("format"),
        "api_version": probe.get("version"),
        "total_results_at_pin": probe.get("totalResults"),
        "immutability": (
            "NOT immutable upstream. NVD serves current data and retired its dated "
            "JSON feeds; reproducibility is anchored to the locally retained snapshot "
            "whose file digests are recorded in manifests/nvd.manifest.json."
        ),
        "rate_limit": cfg["rate_limit"],
    }


def pin_cwe(cfg: dict, version: str | None = None) -> dict:
    """Resolve the CWE catalog version, then pin the *versioned* URL.

    cwec_latest.xml.zip is a moving target; cwec_v<version>.xml.zip is not. The
    version is read out of the catalog's own root element rather than scraped
    from the downloads page, because the XML is authoritative about itself.
    """
    if version is None:
        blob = http_get(cfg["version_probe_url"])
        tmp = REPO / "data" / "raw" / "_cwe_version_probe.zip"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(blob)
        with zipfile.ZipFile(tmp) as z:
            name = z.namelist()[0]
            head_bytes = z.open(name).read(600).decode("utf-8", "replace")
        tmp.unlink()
        m = re.search(r'Weakness_Catalog[^>]*\bVersion="([0-9.]+)"', head_bytes)
        d = re.search(r'Weakness_Catalog[^>]*\bDate="([0-9-]+)"', head_bytes)
        if not m:
            raise RuntimeError("could not read Version from the CWE catalog root element")
        version = m.group(1)
        catalog_date = d.group(1) if d else None
    else:
        catalog_date = None

    url = cfg["versioned_url_template"].format(version=version)
    h = head(url)
    if h.get("status") != 200:
        raise RuntimeError(f"versioned CWE URL not reachable: {url} -> {h}")
    return {
        "pin_type": "versioned_release",
        "version": version,
        "catalog_date": catalog_date,
        "url": url,
        "inner_filename": f"cwec_v{version}.xml",
        "content_length": h.get("content_length"),
        "last_modified": h.get("last_modified"),
        "immutability": "Versioned URL; MITRE does not republish a released version in place.",
    }


def pin_attack(cfg: dict, tag: str | None = None) -> dict:
    """Pin the ATT&CK STIX bundles to a release tag and the git blob IDs.

    Blob IDs are recorded so ingestion can verify it received exactly the
    objects that were pinned, without this command having to download 50 MB of
    bundles just to compute a digest.
    """
    repo = cfg["repo"]
    if tag is None:
        releases = get_json(f"{GITHUB_API}/repos/{repo}/releases?per_page=1", headers=_gh_headers())
        if not releases:
            raise RuntimeError("no releases found for attack-stix-data")
        tag = releases[0]["tag_name"]
        published = releases[0]["published_at"]
    else:
        published = None

    ref = _gh(f"repos/{repo}/git/ref/tags/{tag}")
    obj_sha, obj_type = ref["object"]["sha"], ref["object"]["type"]
    if obj_type == "tag":  # annotated tag -> dereference to the commit
        commit_sha = _gh(f"repos/{repo}/git/tags/{obj_sha}")["object"]["sha"]
    else:
        commit_sha = obj_sha

    tree = _gh(f"repos/{repo}/git/trees/{commit_sha}?recursive=1")
    version = tag.lstrip("v")
    files = []
    for domain in cfg["domains"]:
        want = f"{domain}/{domain}-{version}.json"
        entry = next((t for t in tree["tree"] if t["path"] == want), None)
        if entry is None:
            raise RuntimeError(f"pinned bundle not present at {tag}: {want}")
        files.append({
            "path": entry["path"],
            "git_blob_sha": entry["sha"],
            "bytes": entry["size"],
            "raw_url": f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{entry['path']}",
        })
    return {
        "pin_type": "git_tag_release",
        "repo": repo,
        "tag": tag,
        "version": version,
        "commit_sha": commit_sha,
        "published_at": published,
        "files": files,
        "immutability": "Release tag pinned to a commit SHA; raw URLs are commit-addressed.",
    }


def build_lock(only=None, cve_sha=None, cwe_version=None, attack_tag=None, nvd_snapshot=None) -> dict:
    resolvers = {
        "cve_list": lambda c: pin_cve_list(c, cve_sha),
        "nvd": lambda c: pin_nvd(c, nvd_snapshot),
        "cwe": lambda c: pin_cwe(c, cwe_version),
        "attack": lambda c: pin_attack(c, attack_tag),
    }
    existing = {}
    if LOCK_PATH.exists():
        try:
            existing = json.loads(LOCK_PATH.read_text()).get("sources", {})
        except Exception:
            existing = {}

    out = {}
    for sid in ("cve_list", "nvd", "cwe", "attack"):
        if only and sid not in only:
            if sid in existing:
                out[sid] = existing[sid]
                print(f"[{sid}] kept existing pin")
            continue
        print(f"[{sid}] resolving pin...", flush=True)
        pin = resolvers[sid](SOURCES[sid])
        pin["source_id"] = sid
        pin["source_name"] = SOURCES[sid]["source_name"]
        pin["pinned_at_utc"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        out[sid] = pin
        head_line = pin.get("commit_sha") or pin.get("version") or pin.get("tag") or pin.get("snapshot_instant_utc")
        print(f"[{sid}] -> {pin['pin_type']}: {head_line}")
    return {"schema_version": LOCK_SCHEMA_VERSION, "sources": out}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Resolve immutable pins for every ingestion source.")
    ap.add_argument("--only", nargs="*", help="pin only these source ids")
    ap.add_argument("--cve-sha", help="pin CVE List to this commit instead of main")
    ap.add_argument("--cwe-version", help="pin CWE to this version instead of the current release")
    ap.add_argument("--attack-tag", help="pin ATT&CK to this tag instead of the newest release")
    ap.add_argument("--nvd-snapshot", help="pin NVD to this ISO-8601 UTC instant instead of now")
    args = ap.parse_args(argv)

    lock = build_lock(
        only=set(args.only) if args.only else None,
        cve_sha=args.cve_sha,
        cwe_version=args.cwe_version,
        attack_tag=args.attack_tag,
        nvd_snapshot=args.nvd_snapshot,
    )
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_bytes(
        json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    print(f"\nwrote {LOCK_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
