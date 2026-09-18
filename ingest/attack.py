"""ATT&CK ingester -- pinned STIX 2.1 bundles, object structure preserved.

Each STIX object is stored as it arrived. Flattening to a technique list at
ingest time would discard relationship objects, mitigations, groups, software,
campaigns, data components and the kill-chain phases -- and those are the parts
that make ATT&CK a graph rather than a taxonomy. P2 can derive whatever flat
view it needs; it cannot recover structure that ingestion threw away.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common import paths  # noqa: E402
from ingest.common.metrics import RunMetrics  # noqa: E402
from ingest.common.fetch import download, human_bytes  # noqa: E402
from ingest.common.lineage import content_hash, make_lineage  # noqa: E402
from ingest.common.manifest import ManifestBuilder  # noqa: E402
from ingest.common.writer import RecordWriter  # noqa: E402
from ingest.sources import SOURCES, license_block  # noqa: E402

SOURCE_ID = "attack"


def attack_external_id(obj: dict) -> str | None:
    """The ATT&CK ID (T1059, S0002, G0016, M1040 ...) is the cross-source key.

    It lives in external_references under source_name 'mitre-attack'. Relationship
    and marking objects genuinely have none -- those return None and are counted
    as missing rather than given a synthetic value that would later look like a
    real identifier.
    """
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def ingest(pin: dict, *, force: bool = False) -> Path:
    cfg = SOURCES[SOURCE_ID]
    paths.ensure_dirs()
    m = RunMetrics(SOURCE_ID)
    stats = m.new_stats()

    tag, version, commit = pin["tag"], pin["version"], pin["commit_sha"]
    est = sum(f["bytes"] for f in pin["files"])
    ok, msg = paths.check_size_bound(SOURCE_ID, est)
    print(f"  {msg}")
    if not ok:
        raise RuntimeError(msg)

    lic = license_block(SOURCE_ID)
    retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pin_str = f"attack:{tag}@{commit}"

    mb = ManifestBuilder(
        source_id=SOURCE_ID,
        source_name=cfg["source_name"],
        source_url=cfg["source_url"],
        pin=pin,
        content_type=cfg["content_type"],
        license_block=lic,
        source_timestamp=pin.get("published_at") or tag,
        no_entity_id_types=[
            "stix_relationship",
            "stix_marking-definition",
            "stix_identity",
            "stix_x-mitre-collection",
        ],
        notes=[
            "STIX object structure preserved; not flattened to a technique list. "
            "Relationship, mitigation, group, software, campaign and data-component "
            "objects are all retained.",
            "Attribution required by the ATT&CK license: © 2026 The MITRE Corporation. "
            "This work is reproduced and distributed with the permission of The MITRE Corporation.",
        ],
    )

    raw_dir = paths.RAW / SOURCE_ID / tag
    out = paths.INGESTED / f"{SOURCE_ID}.jsonl"
    type_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}

    with RecordWriter(out, SOURCE_ID) as w:
        for finfo in pin["files"]:
            rel = finfo["path"]
            domain = rel.split("/", 1)[0]
            dest = raw_dir / Path(rel).name
            print(f"  downloading {rel} ({human_bytes(finfo['bytes'])})")
            dl = download(finfo["raw_url"], dest, stats=stats)
            print(f"    {'cached' if dl['cached'] else 'fetched'} sha256={dl['sha256'][:16]}...")
            mb.add_file_entry(str(dest.relative_to(paths.REPO)), dl["sha256"], "sha256", dl["bytes"])

            bundle = json.loads(dest.read_text(encoding="utf-8"))
            objects = bundle.get("objects") or []
            if bundle.get("type") != "bundle":
                raise RuntimeError(f"{rel} is not a STIX bundle (type={bundle.get('type')!r})")
            print(f"    {len(objects)} STIX objects")

            for obj in objects:
                stix_type = obj.get("type", "unknown")
                entity_id = attack_external_id(obj)
                record_id = obj.get("id") or f"{domain}:{stix_type}:{type_counts.get(stix_type,0)}"
                csha = content_hash(obj)
                lin = make_lineage(
                    source_id=SOURCE_ID,
                    source_name=cfg["source_name"],
                    source_url=finfo["raw_url"],
                    source_pin=pin_str,
                    retrieved_at=retrieved_at,
                    record_id=record_id,
                    entity_id=entity_id,
                    content_type=f"stix_{stix_type}",
                    content_sha256=csha,
                    transform_history=[],
                    **lic,
                )
                w.write(lin, obj)
                mb.add_record(csha, entity_id, f"stix_{stix_type}")
                type_counts[stix_type] = type_counts.get(stix_type, 0) + 1
                domain_counts[domain] = domain_counts.get(domain, 0) + 1

    top = sorted(type_counts.items(), key=lambda kv: -kv[1])
    for k, v in top[:12]:
        print(f"    {k}: {v}")
    mb.notes.append("STIX object counts: " + ", ".join(f"{k}={v}" for k, v in top))
    mb.notes.append("objects by domain: " + ", ".join(f"{k}={v}" for k, v in sorted(domain_counts.items())))

    built = mb.build()
    mb.notes.append(
        f"entity_id absent for {built['counts']['entity_id_missing']} of "
        f"{built['counts']['records']} objects. STIX relationship, marking-definition, "
        "identity and collection objects carry no ATT&CK external_id by design and are "
        "excluded from the identifiable denominator; among object types that should have "
        f"one, coverage is {built['entity_id_coverage_identifiable']:.4f}. Missing ids are "
        "counted, never synthesised."
    )
    mpath = mb.write(paths.MANIFESTS)
    print(f"  {mb.record_count} records -> {out.relative_to(paths.REPO)}")
    b = mb.build()
    print(f"  manifest {mpath.relative_to(paths.REPO)} (entity_id coverage "
          f"{b['entity_id_coverage']:.4f} overall, {b['entity_id_coverage_identifiable']:.4f} among identifiable types)")
    m.absorb(stats)
    metrics = m.finish()
    print(f"  wall {metrics['elapsed_seconds']}s ({'network' if metrics['used_network'] else 'cached'}), "
          f"{metrics['http_requests']} requests, {human_bytes(metrics['bytes_transferred'])}")
    return mpath, metrics
