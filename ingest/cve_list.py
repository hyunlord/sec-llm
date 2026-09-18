"""CVE List V5 ingester -- pinned to a commit SHA of CVEProject/cvelistV5.

Clone strategy: a blobless partial clone (`--filter=blob:none`) followed by a
checkout of the pinned commit. This keeps the full commit history, so the pin is
verifiable by ancestry as well as by object hash, while only materialising the
blobs the pinned tree actually needs. A `--depth 1` shallow clone would also
verify the object hash -- git's Merkle structure guarantees that much -- but it
discards the history that lets anyone confirm the pinned commit is genuinely on
this repository's main line, which is the check the work order is protecting.

Nothing is compiled and nothing runs in the background; the clone streams to
stdout in the foreground and is resumable in the sense that an interrupted clone
leaves the partial repo in place for git to continue from.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common import paths  # noqa: E402
from ingest.common.fetch import human_bytes  # noqa: E402
from ingest.common.lineage import content_hash, make_lineage  # noqa: E402
from ingest.common.manifest import ManifestBuilder  # noqa: E402
from ingest.common.writer import RecordWriter  # noqa: E402
from ingest.sources import SOURCES, license_block  # noqa: E402

SOURCE_ID = "cve_list"


def run_git(args, cwd=None, timeout=7200, stream=False):
    cmd = ["git"] + args
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if stream:
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in p.stdout:
            print(f"    {line.rstrip()}", flush=True)
        p.wait(timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed with rc={p.returncode}")
        return ""
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()[:500]}")
    return r.stdout.strip()


def dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def ensure_clone(pin: dict, work: Path) -> dict:
    """Clone (or reuse) the repo and check out the pinned commit."""
    sha = pin["commit_sha"]
    info = {"strategy": "partial_clone_blob_none"}

    if not (work / ".git").exists():
        work.parent.mkdir(parents=True, exist_ok=True)
        print(f"  cloning {pin['clone_url']} (blobless partial clone)")
        t0 = time.time()
        run_git(
            ["clone", "--filter=blob:none", "--no-checkout", pin["clone_url"], str(work)],
            stream=True,
        )
        info["clone_seconds"] = round(time.time() - t0, 1)
    else:
        print(f"  reusing existing clone at {work}")
        info["clone_seconds"] = 0.0

    # Make sure the pinned object is present even if it postdates the clone.
    try:
        run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=work)
    except RuntimeError:
        print(f"  fetching pinned commit {sha[:12]}")
        run_git(["fetch", "--filter=blob:none", "origin", sha], cwd=work, stream=True)

    print(f"  checking out pinned commit {sha[:12]}")
    t0 = time.time()
    run_git(["checkout", "--force", "--detach", sha], cwd=work, stream=True)
    info["checkout_seconds"] = round(time.time() - t0, 1)

    head = run_git(["rev-parse", "HEAD"], cwd=work)
    if head != sha:
        raise RuntimeError(f"pin verification failed: HEAD={head} but pin={sha}")
    info["verified_head"] = head

    # Ancestry check -- this is the property a shallow clone would have lost.
    try:
        count = run_git(["rev-list", "--count", "HEAD"], cwd=work)
        info["history_depth"] = int(count)
        info["pin_verifiable_by_ancestry"] = int(count) > 1
    except RuntimeError as exc:
        info["history_depth"] = None
        info["pin_verifiable_by_ancestry"] = False
        info["ancestry_note"] = f"rev-list failed: {exc}"

    info["commit_date"] = run_git(["show", "-s", "--format=%cI", "HEAD"], cwd=work)
    return info


def ingest(pin: dict, *, force: bool = False) -> Path:
    cfg = SOURCES[SOURCE_ID]
    paths.ensure_dirs()
    t0 = time.time()

    work = paths.RAW / SOURCE_ID / "cvelistV5"
    est = (pin.get("repo_packed_size_kb") or 0) * 1024 * 2  # packed + working tree
    ok, msg = paths.check_size_bound(SOURCE_ID, est)
    print(f"  {msg} (packed {human_bytes((pin.get('repo_packed_size_kb') or 0)*1024)} x2 for the checkout)")
    if not ok:
        raise RuntimeError(msg)

    clone_info = ensure_clone(pin, work)
    print(f"  pin verified: HEAD={clone_info['verified_head'][:12]}, "
          f"history depth={clone_info['history_depth']}, "
          f"ancestry-verifiable={clone_info['pin_verifiable_by_ancestry']}")

    on_disk = dir_size(work)
    print(f"  on-disk size: {human_bytes(on_disk)}")

    lic = license_block(SOURCE_ID)
    retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pin_str = f"cve_list:{pin['commit_sha']}"

    mb = ManifestBuilder(
        source_id=SOURCE_ID,
        source_name=cfg["source_name"],
        source_url=cfg["source_url"],
        pin=pin,
        content_type=cfg["content_type"],
        license_block=lic,
        source_timestamp=pin["commit_date"],
        notes=[
            "INTEGRITY: this source carries no per-file sha256 -- ~300k files would bloat "
            "the manifest past usefulness. Content integrity is anchored to two real "
            "digests instead: the git commit SHA (a Merkle root over the entire tree) and "
            "records_digest (SHA-256 over every record's content hash). Neither is "
            "synthesised.",
            f"clone strategy: {clone_info['strategy']} then checkout of the pinned commit; "
            f"history depth {clone_info['history_depth']} commits, so the pin is verifiable "
            "by ancestry and not only by object hash.",
            "Attribution required by the CVE Program Terms of Use: reproduce MITRE's "
            "copyright designation and the license in any copy.",
        ],
    )
    # Per-file digests for ~300k files would bloat the manifest past usefulness,
    # so this source's integrity is anchored to two real values rather than a
    # synthesised per-file one: the git commit SHA (which is itself a Merkle
    # root over the whole tree) and records_digest (a SHA-256 over every
    # record's content hash). The checkout is recorded as a directory, with the
    # commit id under a key that says what it is.
    mb.add_file_entry(
        str(work.relative_to(paths.REPO)),
        pin["commit_sha"],
        "git_commit_sha",
        on_disk,
        kind="directory",
    )

    cves_dir = work / "cves"
    if not cves_dir.exists():
        raise RuntimeError(f"expected {cves_dir} in the checkout")

    out = paths.INGESTED / f"{SOURCE_ID}.jsonl"
    n = malformed = no_id = 0
    state_counts: dict[str, int] = {}
    t_scan = time.time()

    with RecordWriter(out, SOURCE_ID) as w:
        for path in sorted(cves_dir.rglob("CVE-*.json")):
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                malformed += 1
                continue
            meta = obj.get("cveMetadata") or {}
            entity_id = meta.get("cveId")
            if not entity_id:
                no_id += 1
            st = meta.get("state") or "UNKNOWN"
            state_counts[st] = state_counts.get(st, 0) + 1
            csha = content_hash(obj)
            lin = make_lineage(
                source_id=SOURCE_ID,
                source_name=cfg["source_name"],
                source_url=f"https://github.com/{cfg['repo']}/blob/{pin['commit_sha']}/"
                           + str(path.relative_to(work)),
                source_pin=pin_str,
                retrieved_at=retrieved_at,
                record_id=str(path.relative_to(work)),
                entity_id=entity_id,
                content_type=cfg["content_type"],
                content_sha256=csha,
                transform_history=[],
                **lic,
            )
            w.write(lin, obj)
            mb.add_record(csha, entity_id, cfg["content_type"])
            n += 1
            if n % 50000 == 0:
                print(f"    {n} records ({time.time()-t_scan:.0f}s)", flush=True)

    mb.notes.append(
        f"records={n}, malformed JSON skipped={malformed}, records with no cveMetadata.cveId={no_id}"
    )
    mb.notes.append("cveMetadata.state counts: " + ", ".join(f"{k}={v}" for k, v in sorted(state_counts.items())))
    mb.notes.append(f"on-disk checkout size: {human_bytes(on_disk)}")

    mpath = mb.write(paths.MANIFESTS)
    b = mb.build()
    print(f"  {n} records ({malformed} malformed skipped) -> {out.relative_to(paths.REPO)}")
    print(f"  manifest {mpath.relative_to(paths.REPO)} (entity_id coverage {b['entity_id_coverage']:.4f})")
    print(f"  wall {time.time()-t0:.1f}s")
    return mpath
