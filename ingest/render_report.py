# -*- coding: utf-8 -*-
"""Render reports/ingest.md (Korean) from the manifests and the run record.

Per source: pin used, record count, on-disk size, wall time, request count
where applicable, and anything that failed. Run-time facts come from
data/ingest_run.json (which is not committed); data facts come from the
manifests (which are).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.sources import SOURCE_ORDER, SOURCES  # noqa: E402

MANIFESTS = REPO / "manifests"
RUN = REPO / "data" / "ingest_run.json"
LOCK = REPO / "ingest" / "sources.lock.json"
OUT = REPO / "reports" / "ingest.md"


def human(n):
    n = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or u == "TiB":
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TiB"


def tracked_size():
    try:
        files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True).stdout.split()
        total = 0
        for f in files:
            p = REPO / f
            if p.is_file():
                total += p.stat().st_size
        return total, len(files)
    except Exception:
        return None, None


def pin_headline(pin: dict) -> str:
    t = pin.get("pin_type")
    if t == "git_commit":
        return f"`{t}` → `{pin['commit_sha']}` ({pin.get('commit_date')})"
    if t == "git_tag_release":
        return f"`{t}` → `{pin['tag']}` @ `{pin['commit_sha'][:12]}` ({pin.get('published_at')})"
    if t == "versioned_release":
        return f"`{t}` → v{pin['version']} ({pin.get('catalog_date')})"
    if t == "api_snapshot":
        return f"`{t}` → 스냅숏 기준시각 `{pin['snapshot_instant_utc']}`"
    return f"`{t}`"


def render() -> Path:
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {"sources": {}}
    pins = lock.get("sources", {})
    run = json.loads(RUN.read_text()) if RUN.exists() else {"sources": {}}
    runs = run.get("sources", {})

    mans = {}
    for sid in SOURCE_ORDER:
        p = MANIFESTS / f"{sid}.manifest.json"
        if p.exists():
            mans[sid] = json.loads(p.read_text())

    L = []
    L.append("# P1 수집 보고서 — 출처 수집과 계보(lineage)\n")
    L.append("> 이 문서는 `manifests/*.json`과 실행 기록으로부터 **자동 생성**된다. "
             "`make ingest-report`로 다시 만들 것.\n")
    L.append("실행 호스트: 로컬 Mac Studio M3 Ultra (DGX 아님). "
             "이 작업지시서에는 CUDA·GPU·학습 프레임워크·모델 로드가 없다 — HTTP, git, JSON 파싱, 파일 해싱뿐이다.\n")

    # --- summary table ----------------------------------------------------
    L.append("## 출처별 요약\n")
    L.append("| 출처 | 핀 | 레코드 수 | 디스크 사용량 | 소요 시간 | 요청 수 | entity_id 커버리지 | 상태 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for sid in SOURCE_ORDER:
        m = mans.get(sid)
        r = runs.get(sid, {})
        pin = pins.get(sid, {})
        if not m:
            status = "❌ 실패" if r.get("status") == "failed" else "⛔ 미실행"
            L.append(f"| `{sid}` | {pin_headline(pin) if pin else '—'} | — | — | — | — | — | {status} |")
            continue
        cov = m["entity_id_coverage"]
        cov_id = m.get("entity_id_coverage_identifiable", cov)
        cov_txt = f"{cov:.4f}" if abs(cov - cov_id) < 1e-9 else f"{cov:.4f} (식별가능 타입 {cov_id:.4f})"
        reqs = "—"
        for n in m.get("notes", []):
            if n.startswith("pages="):
                reqs = n.split(",")[0].replace("pages=", "") + " 페이지"
        L.append(
            f"| `{sid}` | {pin_headline(pin)} | {m['counts']['records']:,} | "
            f"{human(m['counts']['bytes'])} | {r.get('wall_seconds','—')} 초 | {reqs} | "
            f"{cov_txt} | {'✅ 성공' if r.get('status')=='ok' else '✅ 매니페스트 존재'} |"
        )
    L.append("")

    failed = {s: r for s, r in runs.items() if r.get("status") != "ok"}
    if failed:
        L.append("### 실패한 출처\n")
        for sid, r in failed.items():
            L.append(f"- **`{sid}`**: {r.get('error','(사유 미기록)')[:400]}")
        L.append("")
    else:
        L.append("실패한 출처는 없다.\n")

    # --- per source -------------------------------------------------------
    L.append("## 출처별 상세\n")
    for sid in SOURCE_ORDER:
        m = mans.get(sid)
        pin = pins.get(sid, {})
        r = runs.get(sid, {})
        s = SOURCES[sid]
        L.append(f"### `{sid}` — {s['source_name']}\n")
        if not m:
            L.append(f"- 상태: **{'실패' if r.get('status')=='failed' else '미실행'}**")
            if r.get("error"):
                L.append(f"- 오류: `{r['error'][:600]}`")
            L.append("")
            continue
        L.append(f"- 사용한 핀: {pin_headline(pin)}")
        L.append(f"- 불변성: {pin.get('immutability', '커밋/태그/버전 주소 지정으로 불변')}")
        L.append(f"- 레코드 수: **{m['counts']['records']:,}**")
        L.append(f"- 디스크 사용량: **{human(m['counts']['bytes'])}** (파일 {m['counts']['files']:,}개)")
        L.append(f"- 소요 시간: **{r.get('wall_seconds','—')} 초**")
        L.append(f"- entity_id 커버리지: **{m['entity_id_coverage']:.4f}**"
                 + (f" (식별 가능한 타입만 기준 **{m['entity_id_coverage_identifiable']:.4f}**)"
                    if m.get("entity_id_coverage_identifiable") is not None
                    and abs(m["entity_id_coverage_identifiable"] - m["entity_id_coverage"]) > 1e-9 else ""))
        if m.get("content_types_without_entity_id"):
            L.append(f"  - 출처가 식별자를 주지 않는 타입(분모에서 제외): `{', '.join(m['content_types_without_entity_id'])}`")
        L.append(f"- 레코드 다이제스트: `{m['records_digest'][:32]}...`")
        L.append(f"- 컨테이너 라이선스: {m['license']['source_license']}")
        L.append(f"- 내용물 라이선스: {m['license']['upstream_license']}")
        if m.get("notes"):
            L.append("- 기록 사항:")
            for n in m["notes"]:
                L.append(f"  - {n}")
        L.append("")

    # --- reproducibility --------------------------------------------------
    L.append("## 재현성\n")
    L.append("매니페스트에는 **실행 시각(wall-clock) 필드가 없다.** 모든 시각 값은 커밋된 핀에서 나오며, "
             "레코드 해시는 lineage 봉투가 아니라 **출처 콘텐츠만** 대상으로 계산한다 "
             "(`retrieved_at`은 매 실행마다 달라지는 값이므로 봉투를 해싱하면 재현성이 깨진다).\n")
    L.append("```bash\nmake ingest\nshasum -a 256 manifests/*.json > /tmp/m1.txt\nmake ingest\n"
             "shasum -a 256 manifests/*.json > /tmp/m2.txt\ndiff /tmp/m1.txt /tmp/m2.txt\n```\n")
    L.append("`make ingest-verify`가 위 과정을 수행하고 차이가 있으면 실패한다.\n")
    L.append("### NVD의 예외 — 정직하게 적는다\n")
    L.append("NVD는 이 작업지시서의 네 출처 중 **유일하게 상류에 불변 참조가 없다.** "
             "날짜별 JSON 피드는 폐지되었고 API는 항상 현재 데이터를 제공한다. 그래서:\n")
    L.append("- **레코드 집합**은 `lastModified <= 스냅숏 기준시각` 클라이언트 측 컷오프로 결정적이게 만들 수 있다.")
    L.append("- **레코드 내용**은 그럴 수 없다. 상류가 스냅숏 이후에 레코드를 수정하면 내용이 달라진다.")
    L.append("- 따라서 재현성의 기준점은 **로컬에 보존된 스냅숏**이며, 그 페이지별 다이제스트가 "
             "`manifests/nvd.manifest.json`에 들어 있다. 나중에 처음부터 다시 받으면 내용이 달라질 수 있고, "
             "이 다이제스트가 그것을 **침묵이 아니라 탐지 가능한 차이**로 만든다.\n")

    # --- git hygiene ------------------------------------------------------
    total, nfiles = tracked_size()
    L.append("## 원시 코퍼스는 git에 들어가지 않는다\n")
    if total is not None:
        L.append(f"- git이 추적하는 파일: **{nfiles:,}개, 합계 {human(total)}**")
        L.append("- 원시 데이터(`data/`)는 `.gitignore`로 제외된다. 커밋되는 것은 매니페스트, 핀, 보고서뿐이다.")
    L.append("")
    L.append("```bash\ngit ls-files | xargs du -ch 2>/dev/null | tail -1\n```\n")

    L.append("## 이 작업지시서가 하지 않은 것\n")
    L.append("- 중복 제거, 정규화, 시크릿 스캐닝을 하지 않았다. 다음 작업지시서(P2)의 몫이다.")
    L.append("- `transform_history`는 모든 레코드에서 **빈 리스트**다. 이후 처리 단계가 여기에 append한다.")
    L.append("- `scripts/env_check/`를 건드리지 않았다. P0.1 재실행은 DGX 복구 후 그대로 이어진다.\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    return OUT


if __name__ == "__main__":
    print(render())
