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
ACQ = REPO / "ingest" / "acquisition_costs.json"


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


class ReportConsistencyError(RuntimeError):
    """The run record and the manifests disagree about what happened."""


def check_consistency(runs: dict, mans: dict) -> None:
    """Refuse to render a document that contradicts itself.

    A source marked failed while a valid manifest for it sits on disk is not a
    state to render -- it means the run record is stale or polluted. A
    self-contradicting report is worse than a missing one, and these reports are
    the deliverable.
    """
    contradictions = []
    for sid, r in (runs or {}).items():
        if r.get("status") != "ok" and sid in mans:
            m = mans[sid]
            contradictions.append(
                f"{sid}: run record says '{r.get('status')}' "
                f"({str(r.get('error'))[:120]}) but manifests/{sid}.manifest.json exists "
                f"with {m['counts']['records']} records"
            )
    if contradictions:
        raise ReportConsistencyError(
            "refusing to render a self-contradicting report:\n  "
            + "\n  ".join(contradictions)
            + "\n\nThe run record is stale or was polluted by a test. Re-run `make ingest`, "
              "or point gate tests at SEC_LLM_DATA_DIR so they never write here."
        )


def render() -> Path:
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {"sources": {}}
    pins = lock.get("sources", {})
    run = json.loads(RUN.read_text()) if RUN.exists() else {"sources": {}}
    runs = run.get("sources", {})
    acq = json.loads(ACQ.read_text()).get("sources", {}) if ACQ.exists() else {}

    mans = {}
    for sid in SOURCE_ORDER:
        p = MANIFESTS / f"{sid}.manifest.json"
        if p.exists():
            mans[sid] = json.loads(p.read_text())

    check_consistency(runs, mans)

    L = []
    L.append("# P1 수집 보고서 — 출처 수집과 계보(lineage)\n")
    L.append("> 이 문서는 `manifests/*.json`과 실행 기록으로부터 **자동 생성**된다. "
             "`make ingest-report`로 다시 만들 것.\n")
    L.append("실행 호스트: 로컬 Mac Studio M3 Ultra (DGX 아님). "
             "이 작업지시서에는 CUDA·GPU·학습 프레임워크·모델 로드가 없다 — HTTP, git, JSON 파싱, 파일 해싱뿐이다.\n")

    # --- summary table ----------------------------------------------------
    L.append("## 출처별 요약\n")
    L.append("| 출처 | 핀 | 레코드 수 | 디스크 사용량 | 이번 실행 소요 | 최초 수집 소요 | 요청 수 | entity_id 커버리지 | 상태 |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for sid in SOURCE_ORDER:
        m = mans.get(sid)
        r = runs.get(sid, {})
        pin = pins.get(sid, {})
        if not m:
            status = "❌ 실패" if r.get("status") == "failed" else "⛔ 미실행"
            L.append(f"| `{sid}` | {pin_headline(pin) if pin else '—'} | — | — | — | — | — | — | {status} |")
            continue
        cov = m["entity_id_coverage"]
        cov_id = m.get("entity_id_coverage_identifiable", cov)
        cov_txt = f"{cov:.4f}" if abs(cov - cov_id) < 1e-9 else f"{cov:.4f} (식별가능 타입 {cov_id:.4f})"
        # When this run re-derived from disk it made no requests; the number
        # worth showing is what acquiring the source actually cost.
        live_reqs = int(r.get("http_requests") or 0)
        if live_reqs:
            reqs = f"{live_reqs:,}"
        else:
            reqs = f"{acq.get(sid, {}).get('http_requests', 0):,} (최초 수집)"
        if r.get("pages"):
            reqs += f", {r['pages']} 페이지"
        elapsed = r.get("elapsed_seconds")
        if elapsed is None:
            elapsed_txt = "미측정"
        else:
            kind = "네트워크" if r.get("used_network") else "캐시"
            elapsed_txt = f"{elapsed:,.1f} 초 ({kind})"
        a = acq.get(sid, {})
        acq_txt = (f"{a['elapsed_seconds_network']:,.1f} 초 (네트워크)" if a.get("elapsed_seconds_network") else "기록 없음")

        L.append(
            f"| `{sid}` | {pin_headline(pin)} | {m['counts']['records']:,} | "
            f"{human(m['counts'].get('bytes') or m['counts'].get('bytes_on_disk'))} | "
            f"{elapsed_txt} | {acq_txt} | {reqs} | "
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
        nbytes = m["counts"].get("bytes") or m["counts"].get("bytes_on_disk")
        nfiles = m["counts"].get("files", 0)
        ndirs = m["counts"].get("directories", 0)
        what = f"파일 {nfiles:,}개" if nfiles else f"디렉터리 {ndirs}개(체크아웃 전체)"
        L.append(f"- 디스크 사용량: **{human(nbytes)}** ({what})")
        el = r.get("elapsed_seconds")
        if el is None:
            L.append("- 소요 시간: **미측정**")
        else:
            kind = "네트워크 실측" if r.get("used_network") else "캐시 재생성 — 최초 수집 비용이 아님"
            L.append(f"- 소요 시간: **{el:,.1f} 초** ({kind})")
            L.append(f"  - HTTP 요청 수: **{r.get('http_requests', 0):,}**"
                     + (f", 페이지 {r['pages']}" if r.get("pages") else ""))
            L.append(f"  - 전송 바이트: **{human(r.get('bytes_transferred', 0))}**")
            if r.get("clone_seconds") is not None:
                L.append(f"  - git clone {r['clone_seconds']:,.1f} 초 / checkout {r.get('checkout_seconds',0):,.1f} 초")
            for n in r.get("notes", []):
                L.append(f"  - {n}")
        a = acq.get(sid, {})
        if a:
            L.append(f"- **최초 수집 실측**: {a['elapsed_seconds_network']:,.1f} 초, "
                     f"HTTP 요청 {a.get('http_requests', 0):,}회, 전송 {a.get('transfer','—')}")
            L.append(f"  - {a.get('detail','')}")
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

    # --- P1.1 corrections ------------------------------------------------
    L.append("## P1.1 — 발견하여 수정한 결함 4건\n")
    L.append("스스로의 수정 이력을 남기는 파이프라인이, 결함이 없었던 것처럼 보이는 파이프라인보다 신뢰할 만하다. "
             "아래 4건은 P1 통과 이후 감사에서 발견되어 P1.1에서 수정되었다.\n")
    L.append("### 1. `sha256` 필드에 위조된 다이제스트\n")
    L.append("`manifests/cve_list.manifest.json`이 `\"sha256\": \"9d4f632a…f69a000000000000000000000000\"`를 "
             "담고 있었다. **git 커밋 SHA-1을 0으로 패딩해 64자로 만든 값**이며 그 무엇의 SHA-256도 아니다. "
             "검증기가 모양(64자 소문자 hex)만 확인했기 때문에 통과했다.\n")
    L.append("- 30만 개 파일에 개별 다이제스트를 넣지 않는다는 **판단 자체는 옳았고 유지**한다. 실행 방식만 틀렸다.")
    L.append("- 이제 체크아웃은 `kind=\"directory\"`, 커밋 id는 이름이 맞는 키(`git_commit_sha`, 40자 무패딩)에 기록한다.")
    L.append("- `add_file_entry`가 **디스크의 바이트로부터 다시 계산해서 대조**한다. 모양 검사로는 이 위조를 잡을 수 없다.")
    L.append("- `python -m ingest.verify_digests`가 커밋된 매니페스트를 독립적으로 재검증한다 (203 entries, 0 problems).\n")
    L.append("### 2. 자기모순인 보고서\n")
    L.append("`reports/ingest.md`가 `cwe`를 '실패한 출처'로 올리면서 동시에 요약 표에서 ✅로 표시했다. "
             "Gate 1 조건 5 테스트(잘못된 핀은 큰 소리로 실패해야 함)의 잔재가 렌더러가 읽는 실행 기록에 남은 것이다.\n")
    L.append("- 테스트 상태와 실행 상태를 분리했다 (`SEC_LLM_DATA_DIR`).")
    L.append("- 렌더러가 **모순 상태를 렌더링하지 않고 예외를 던진다**. 실패로 기록된 출처에 유효한 매니페스트가 "
             "있다면 그것은 렌더링할 상태가 아니라 렌더러 오류다.")
    L.append("- 자기모순 보고서는 없는 보고서보다 나쁘다 — 독자에게 어느 쪽을 믿을지 고르게 만든다.\n")
    L.append("### 3. 요구된 측정이 수행되지 않음\n")
    L.append("모든 소요 시간 칸이 `— 초`였고 요청 수는 4개 중 3개가 비어 있었다. P1이 요구한 항목이다.\n")
    L.append("- 각 인제스터가 시작·종료·경과·HTTP 요청 수·전송 바이트를 기록한다.")
    L.append("- **캐시 재생성 시간을 수집 비용으로 제시하지 않는다.** NVD 재생성은 50초, 최초 수집은 약 1시간이다 — "
             "70배 차이다. 두 값을 각각 `elapsed_seconds_cached` / `elapsed_seconds_network`로 구분하고 "
             "`ingest/acquisition_costs.json`에 최초 수집 실측을 따로 보관한다.\n")
    L.append("### 4. 근거보다 많은 것을 주장하던 라이선스 필드\n")
    L.append("`cve_list.commercial_status`가 `permitted_with_attribution`이었는데, 바로 아래 근거는 "
             "**\"commercial이라는 단어가 CVE 이용 약관에 등장하지 않는다\"**고 적고 있었다. 산문은 정직했고 "
             "기계 판독 필드는 그렇지 않았다.\n")
    L.append("- `not_addressed`를 도입하고 `cve_list.commercial_status`를 그 값으로 정정했다.")
    L.append("- `python -m ingest.audit_licenses`가 **주장된 권한이 그 필드 자신의 인용 근거에 실제로 등장하는지** 감사한다.")
    L.append("- 이 감사의 첫 버전은 키워드만 찾아서 정작 이 결함을 놓쳤다 — CVE 근거 문장 안에 "
             "\"commercial\"이라는 단어가 (부정문으로) 들어 있었기 때문이다. 부정 표현 탐지를 추가해 "
             "**회귀를 실제로 잡는 것까지 확인**했다.\n")
    L.append("### 스키마 추가 — `model_publication_status`\n")
    L.append("학습된 가중치를 공개할 수 있는지가 이 프로젝트의 최종 산출물의 존재 가능 여부를 결정한다. "
             "문서 속 산문이 아니라 **레코드별 기계 판독 필드**여야 P7이 문서를 다시 읽지 않고 질의로 답할 수 있다.\n")
    L.append(f"- `LINEAGE_FIELDS`가 16 → 17개가 되었고, **823,285개 레코드 전부**에 값이 있다.")
    L.append("- 네 출처 모두 현재 `not_addressed`다 — 어느 라이선스 문서도 머신러닝·학습·모델 가중치를 언급하지 않는다. "
             "그것이 정직한 현재 상태이고, 그것을 필드로 기록하는 것이 요점이다.")
    L.append("- 보존된 원시 스냅숏에서 **재파생**했다. 네트워크 재수집은 하지 않았다.")
    L.append("- `records_digest`는 **변하지 않았다** — `content_sha256`이 lineage 봉투가 아니라 출처 콘텐츠만 "
             "해싱하기 때문이며, 스키마 변경이 콘텐츠 다이제스트를 흔들지 않는다는 설계가 검증된 것이다.\n")

    # --- P3 flag ----------------------------------------------------------
    cl = mans.get("cve_list")
    if cl:
        state_note = next((n for n in cl.get("notes", []) if "state counts" in n), "")
        L.append("## P3를 위한 플래그 — REJECTED CVE 레코드\n")
        L.append(f"- {state_note}")
        L.append("- REJECTED 레코드는 취약점 설명 대신 placeholder 텍스트를 담고 있으며 의미 있는 CWE 매핑이 없다.")
        L.append("- 플래그만 세우고 **여기서 걸러내지 않는다.** 무엇을 제외할지는 P3가 결정하고, "
                 "P1의 역할은 그 결정이 가능하도록 만드는 것이다.")
        L.append("- 상태 값은 레코드 페이로드의 `cveMetadata.state`에 그대로 있다 (계보가 아니라 **콘텐츠**다). "
                 "매니페스트가 집계를 보고한다.")
        L.append("- 플래그하지 않으면 CVE→CWE 과제에서 약 1만 8천 건의 **답할 수 없는 문항**이 된다.\n")

    L.append("## 이 작업지시서가 하지 않은 것\n")
    L.append("- 중복 제거, 정규화, 시크릿 스캐닝을 하지 않았다. 다음 작업지시서(P2)의 몫이다.")
    L.append("- `transform_history`는 모든 레코드에서 **빈 리스트**다. 이후 처리 단계가 여기에 append한다.")
    L.append("- `scripts/env_check/`를 건드리지 않았다. P0.1 재실행은 DGX 복구 후 그대로 이어진다.\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    return OUT


if __name__ == "__main__":
    print(render())
