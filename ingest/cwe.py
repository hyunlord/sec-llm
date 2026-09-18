"""CWE ingester -- versioned XML catalog, hierarchy preserved.

A flat list of CWE IDs would lose the structure that makes CWE-level evaluation
possible later, so the weakness hierarchy is carried through intact: each
Weakness keeps its Related_Weaknesses edges, each Category keeps its members,
and each View keeps its own membership and filter. The XML is converted
structurally rather than field-by-field, so nothing is dropped just because this
work order did not anticipate needing it.
"""

from __future__ import annotations

import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common import paths  # noqa: E402
from ingest.common.fetch import download, human_bytes  # noqa: E402
from ingest.common.lineage import content_hash, make_lineage  # noqa: E402
from ingest.common.manifest import ManifestBuilder  # noqa: E402
from ingest.common.writer import RecordWriter  # noqa: E402
from ingest.sources import SOURCES, license_block  # noqa: E402

SOURCE_ID = "cwe"
CWE_NS = "{http://cwe.mitre.org/cwe-7}"


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def xml_to_dict(elem: ET.Element) -> dict:
    """Structural XML -> dict. Attributes, text, and children all preserved.

    Repeated child tags become lists so ordering and multiplicity survive;
    collapsing them would silently drop, for example, a weakness's second
    parent relationship.
    """
    node: dict = {}
    if elem.attrib:
        node["@attributes"] = dict(elem.attrib)
    children = list(elem)
    if children:
        grouped: dict[str, list] = {}
        for child in children:
            grouped.setdefault(_strip_ns(child.tag), []).append(xml_to_dict(child))
        for k, v in grouped.items():
            node[k] = v[0] if len(v) == 1 else v
    text = (elem.text or "").strip()
    if text:
        node["#text"] = text
    tail_texts = [(c.tail or "").strip() for c in children]
    if any(tail_texts):
        node["#tails"] = tail_texts
    return node


def ingest(pin: dict, *, force: bool = False) -> Path:
    cfg = SOURCES[SOURCE_ID]
    paths.ensure_dirs()
    t0 = time.time()
    stats = {"requests": 0, "bytes": 0}

    version = pin["version"]
    url = pin["url"]
    est = pin.get("content_length") or 0
    ok, msg = paths.check_size_bound(SOURCE_ID, est)
    print(f"  {msg}")
    if not ok:
        raise RuntimeError(msg)

    raw_dir = paths.RAW / SOURCE_ID / version
    zip_path = raw_dir / f"cwec_v{version}.xml.zip"
    print(f"  downloading {url}")
    dl = download(url, zip_path, stats=stats)
    print(f"  {'cached' if dl['cached'] else 'fetched'} {human_bytes(dl['bytes'])} sha256={dl['sha256'][:16]}...")

    with zipfile.ZipFile(zip_path) as z:
        inner = pin.get("inner_filename") or z.namelist()[0]
        if inner not in z.namelist():
            inner = z.namelist()[0]
        xml_bytes = z.read(inner)
    print(f"  parsing {inner} ({human_bytes(len(xml_bytes))})")

    root = ET.fromstring(xml_bytes)
    catalog_version = root.attrib.get("Version")
    catalog_date = root.attrib.get("Date")
    if catalog_version != version:
        raise RuntimeError(
            f"pin says CWE {version} but the catalog declares {catalog_version} -- pin is stale"
        )

    lic = license_block(SOURCE_ID)
    # retrieved_at is per-run and deliberately never enters the manifest digest.
    retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pin_str = f"cwe:{version}@{catalog_date}"

    mb = ManifestBuilder(
        source_id=SOURCE_ID,
        source_name=cfg["source_name"],
        source_url=cfg["source_url"],
        pin=pin,
        content_type=cfg["content_type"],
        license_block=lic,
        source_timestamp=catalog_date,
        notes=[
            "Weakness hierarchy preserved: Related_Weaknesses edges, Category members, "
            "and View members are carried through structurally rather than flattened.",
            f"catalog declares Version={catalog_version} Date={catalog_date}",
        ],
    )
    mb.add_file_entry(str(zip_path.relative_to(paths.REPO)), dl["sha256"], dl["bytes"])

    out = paths.INGESTED / f"{SOURCE_ID}.jsonl"
    kinds = {
        "Weaknesses": ("Weakness", "cwe_weakness"),
        "Categories": ("Category", "cwe_category"),
        "Views": ("View", "cwe_view"),
        "External_References": ("External_Reference", "cwe_external_reference"),
    }
    counts: dict[str, int] = {}

    with RecordWriter(out, SOURCE_ID) as w:
        for container_tag, (child_tag, content_type) in kinds.items():
            container = root.find(f"{CWE_NS}{container_tag}")
            if container is None:
                continue
            for elem in container.findall(f"{CWE_NS}{child_tag}"):
                obj = xml_to_dict(elem)
                attrs = obj.get("@attributes", {})
                raw_id = attrs.get("ID") or attrs.get("Reference_ID")
                entity_id = f"CWE-{raw_id}" if raw_id and content_type != "cwe_external_reference" else (raw_id or None)
                record_id = f"{content_type}:{raw_id}" if raw_id else f"{content_type}:idx{counts.get(content_type, 0)}"
                csha = content_hash(obj)
                lin = make_lineage(
                    source_id=SOURCE_ID,
                    source_name=cfg["source_name"],
                    source_url=url,
                    source_pin=pin_str,
                    retrieved_at=retrieved_at,
                    record_id=record_id,
                    entity_id=entity_id,
                    content_type=content_type,
                    content_sha256=csha,
                    transform_history=[],
                    **lic,
                )
                w.write(lin, obj)
                mb.add_record(csha, entity_id, content_type)
                counts[content_type] = counts.get(content_type, 0) + 1

    for k, v in sorted(counts.items()):
        print(f"    {k}: {v}")
    mb.notes.append("record counts by type: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    mpath = mb.write(paths.MANIFESTS)
    elapsed = time.time() - t0
    print(f"  {mb.record_count} records -> {out.relative_to(paths.REPO)}")
    print(f"  manifest {mpath.relative_to(paths.REPO)} (entity_id coverage {mb.build()['entity_id_coverage']:.4f})")
    print(f"  wall {elapsed:.1f}s, {stats['requests']} requests, {human_bytes(stats['bytes'])}")
    return mpath
