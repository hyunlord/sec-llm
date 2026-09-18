"""NVD ingester -- paged CVE API 2.0 under the documented rate limit.

Rate limits, read from https://nvd.nist.gov/developers/start-here on 2026-09-18
and quoted here so nobody has to re-derive them:

    "The public rate limit (without an API key) is 5 requests in a rolling 30
    second window; the rate limit with an API key is 50 requests in a rolling 30
    second window. ... it is still recommended that your application sleeps for
    several seconds between requests"
    "It is recommended that users 'sleep' their scripts for six seconds between
    requests."

NVD is the one source in this work order with **no immutable upstream
reference**. The dated JSON feeds are retired and the API always serves current
data, so a pin can only be a cutoff instant plus the query parameters. Two
consequences, both handled explicitly rather than hidden:

  * The record *set* is made deterministic by filtering client-side on
    `lastModified <= snapshot_instant`, so a later refetch does not sweep in
    newly published CVEs.
  * The record *content* cannot be made deterministic -- upstream can edit a
    record after the snapshot. So once a snapshot exists on disk it is reused
    rather than refetched, and its page digests are in the manifest. Drift
    becomes detectable instead of silent.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common import paths  # noqa: E402
from ingest.common.fetch import RateLimiter, ResumeState, get_json, human_bytes  # noqa: E402
from ingest.common.lineage import content_hash, file_sha256, make_lineage  # noqa: E402
from ingest.common.manifest import ManifestBuilder  # noqa: E402
from ingest.common.writer import RecordWriter  # noqa: E402
from ingest.sources import SOURCES, license_block  # noqa: E402

SOURCE_ID = "nvd"
AVG_BYTES_PER_CVE = 6_000  # for the pre-fetch size estimate only

# Optional wall-clock budget for one invocation. The fetch is resumable by
# design, so a bounded run that stops cleanly between pages and is restarted is
# strictly better than one killed mid-write by an outer timeout. Unset means
# "run to completion", which is the default for an unattended run.
TIME_BUDGET_SEC = float(os.environ.get("NVD_TIME_BUDGET_SEC", "0") or 0)


class BudgetExhausted(RuntimeError):
    """Raised between pages when the per-invocation time budget runs out."""


def _limiter(has_key: bool, rl: dict) -> RateLimiter:
    max_req = rl["api_key_requests_per_window"] if has_key else rl["public_requests_per_window"]
    return RateLimiter(
        max_requests=max_req,
        window_sec=rl["window_seconds"],
        min_interval_sec=rl["recommended_sleep_seconds"],
    )


def fetch_pages(pin: dict, snap_dir: Path, stats: dict) -> list[Path]:
    """Page through the API into snap_dir/page_NNNNN.json, resumable."""
    rl = pin["rate_limit"]
    api_key = os.environ.get(rl["api_key_env_var"])
    headers = {"apiKey": api_key} if api_key else {}
    limiter = _limiter(bool(api_key), rl)
    rpp = int(pin["params"]["resultsPerPage"])

    print(f"  rate limit: {'50' if api_key else '5'} req / {rl['window_seconds']}s "
          f"({'API key present' if api_key else 'no API key -- public limit'}), "
          f"{rl['recommended_sleep_seconds']}s min interval")
    if not api_key:
        print(f"  (set {rl['api_key_env_var']} to raise the limit 10x; never commit it)")

    state = ResumeState(paths.STATE / f"{SOURCE_ID}_{pin['snapshot_instant_utc'].replace(':','')}.json")
    start = int(state.get("next_start_index", 0))
    total = int(state.get("total_results", pin.get("total_results_at_pin") or 0))
    if start:
        print(f"  resuming from startIndex={start} (of {total})")

    snap_dir.mkdir(parents=True, exist_ok=True)
    pages: list[Path] = []
    idx = start
    t_start = time.monotonic()
    while True:
        if TIME_BUDGET_SEC and (time.monotonic() - t_start) > TIME_BUDGET_SEC:
            raise BudgetExhausted(
                f"time budget {TIME_BUDGET_SEC:.0f}s reached at startIndex={idx} of {total}; "
                "state saved, re-run to resume"
            )
        page_path = snap_dir / f"page_{idx:07d}.json"
        if page_path.exists() and page_path.stat().st_size > 0:
            pages.append(page_path)
            try:
                got = json.loads(page_path.read_text())
                total = got.get("totalResults", total)
                n = len(got.get("vulnerabilities") or [])
            except Exception:
                page_path.unlink()
                continue
            idx += rpp
            if idx >= total or n == 0:
                break
            continue

        body = get_json(
            pin["api_base"],
            params={"resultsPerPage": rpp, "startIndex": idx},
            headers=headers,
            limiter=limiter,
            stats=stats,
            retries=6,
            backoff=8.0,
        )
        total = body.get("totalResults", total)
        vulns = body.get("vulnerabilities") or []
        tmp = page_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, ensure_ascii=False, sort_keys=True))
        tmp.replace(page_path)
        pages.append(page_path)

        idx += rpp
        state.set("next_start_index", idx)
        state.set("total_results", total)
        pct = idx / total * 100 if total else 0
        print(f"    startIndex={idx - rpp:>7} got {len(vulns):>5} | {pct:5.1f}% of {total} | "
              f"{stats['requests']} requests, {human_bytes(stats['bytes'])}", flush=True)
        if idx >= total or not vulns:
            break

    state.set("complete", True)
    return sorted(pages)


def ingest(pin: dict, *, force: bool = False) -> Path:
    cfg = SOURCES[SOURCE_ID]
    paths.ensure_dirs()
    t0 = time.time()
    stats = {"requests": 0, "bytes": 0}

    snap = pin["snapshot_instant_utc"]
    snap_dir = paths.RAW / SOURCE_ID / snap.replace(":", "")
    total_at_pin = int(pin.get("total_results_at_pin") or 0)

    ok, msg = paths.check_size_bound(SOURCE_ID, total_at_pin * AVG_BYTES_PER_CVE)
    print(f"  {msg} (estimate: {total_at_pin} CVEs x ~{AVG_BYTES_PER_CVE}B)")
    if not ok:
        raise RuntimeError(msg)

    # Reuse only a snapshot that is *known complete*. Treating any directory of
    # pages as a finished snapshot would silently emit a manifest over a partial
    # corpus and report it as a successful ingest -- which is worse than failing,
    # because the record count looks plausible and nothing says it is short.
    state = ResumeState(paths.STATE / f"{SOURCE_ID}_{snap.replace(':','')}.json")
    existing = sorted(snap_dir.glob("page_*.json")) if snap_dir.exists() else []
    complete = bool(state.get("complete")) and existing

    if complete and not force:
        print(f"  reusing the completed snapshot at {snap_dir.relative_to(paths.REPO)} "
              f"({len(existing)} pages) -- NVD has no immutable upstream reference, so "
              "re-deriving from disk is what makes this reproducible")
        pages = existing
    else:
        if existing:
            print(f"  snapshot at {snap_dir.relative_to(paths.REPO)} is INCOMPLETE "
                  f"({len(existing)} pages, next startIndex={state.get('next_start_index', 0)} "
                  f"of {state.get('total_results', total_at_pin)}); resuming")
        try:
            pages = fetch_pages(pin, snap_dir, stats)
        except BudgetExhausted as exc:
            print(f"  {exc}")
            raise

    # Belt and braces: the page count must cover totalResults before a manifest
    # is written at all.
    rpp = int(pin["params"]["resultsPerPage"])
    expected_pages = -(-int(state.get("total_results", total_at_pin) or total_at_pin) // rpp)
    if len(pages) < expected_pages:
        raise RuntimeError(
            f"refusing to write a manifest over a partial snapshot: have {len(pages)} pages, "
            f"expected {expected_pages} for {state.get('total_results', total_at_pin)} records. "
            "Re-run to resume the fetch."
        )

    lic = license_block(SOURCE_ID)
    retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pin_str = f"nvd:snapshot@{snap}"

    mb = ManifestBuilder(
        source_id=SOURCE_ID,
        source_name=cfg["source_name"],
        source_url=cfg["source_url"],
        pin=pin,
        content_type=cfg["content_type"],
        license_block=lic,
        source_timestamp=snap,
        notes=[
            "NVD has no immutable upstream snapshot: the dated JSON feeds are retired and "
            "the API serves current data. The record SET is made deterministic by a "
            "client-side cutoff on lastModified <= snapshot_instant_utc; the record "
            "CONTENT cannot be, because upstream may edit a record after the snapshot.",
            "Reproducibility is therefore anchored to the retained local snapshot, whose "
            "per-page digests are listed in this manifest. A re-run from scratch on a "
            "later date will legitimately differ, and these digests make that visible "
            "rather than silent.",
            "Attribution required by NVD: This product uses data from the NVD API but is "
            "not endorsed or certified by the NVD.",
        ],
    )

    out = paths.INGESTED / f"{SOURCE_ID}.jsonl"
    kept = skipped_after_cutoff = no_id = 0

    with RecordWriter(out, SOURCE_ID) as w:
        for p in pages:
            mb.add_file_entry(str(p.relative_to(paths.REPO)), file_sha256(p), p.stat().st_size)
            body = json.loads(p.read_text())
            for item in body.get("vulnerabilities") or []:
                cve = item.get("cve") or {}
                last_mod = cve.get("lastModified") or ""
                # Cutoff comparison: NVD emits naive ISO-8601 UTC ("2026-09-17T12:00:00.000"),
                # the pin is Z-suffixed. Compare on the date-time prefix only.
                if last_mod and last_mod[:19] > snap[:19]:
                    skipped_after_cutoff += 1
                    continue
                entity_id = cve.get("id")
                if not entity_id:
                    no_id += 1
                csha = content_hash(item)
                lin = make_lineage(
                    source_id=SOURCE_ID,
                    source_name=cfg["source_name"],
                    source_url=cfg["source_url"],
                    source_pin=pin_str,
                    retrieved_at=retrieved_at,
                    record_id=entity_id or f"nvd:idx{kept}",
                    entity_id=entity_id,
                    content_type=cfg["content_type"],
                    content_sha256=csha,
                    transform_history=[],
                    **lic,
                )
                w.write(lin, item)
                mb.add_record(csha, entity_id, cfg["content_type"])
                kept += 1

    mb.notes.append(
        f"pages={len(pages)}, records kept={kept}, excluded by the lastModified cutoff="
        f"{skipped_after_cutoff}, records with no cve.id={no_id}"
    )
    mpath = mb.write(paths.MANIFESTS)
    b = mb.build()
    elapsed = time.time() - t0
    print(f"  {kept} records kept, {skipped_after_cutoff} excluded by cutoff")
    print(f"  -> {out.relative_to(paths.REPO)}")
    print(f"  manifest {mpath.relative_to(paths.REPO)} (entity_id coverage {b['entity_id_coverage']:.4f})")
    print(f"  wall {elapsed:.1f}s, {stats['requests']} requests, {human_bytes(stats['bytes'])}")
    return mpath
