# -*- coding: utf-8 -*-
"""Render the three P2 Korean reports from process.manifest.json.

Generated, like every other report in this repository, so the published numbers
cannot drift from the artifact they describe.

reports/secrets.md carries counts only. No detected value appears in it, in any
form, ever.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.common import MANIFESTS, PROCESSED, REPORTS  # noqa: E402

MANIFEST = MANIFESTS / "process.manifest.json"
RUNTIME = PROCESSED / "process_run.json"


def _n(x):
    return f"{x:,}" if isinstance(x, int) else x


def render_dedup(m: dict, rt: dict) -> Path:
    s, st = m["summary"], m["stages"]
    cal = st["calibration"]
    L = []
    L.append("# P2 중복 제거 보고서\n")
    L.append("> `manifests/process.manifest.json`에서 **자동 생성**된다. `make process-report`로 다시 만들 것.\n")
    L.append("## 0. 아무것도 삭제하지 않았다\n")
    L.append(f"- 입력 레코드: **{_n(s['records_in'])}** → 출력 레코드: **{_n(s['records_out'])}**")
    L.append(f"- **삭제된 레코드: {s['records_deleted']}건**")
    L.append(f"- 제거 대상으로 *표시*된 레코드: **{_n(s['records_marked_not_kept'])}** "
             f"(**{s['removal_rate']:.2%}**)")
    L.append(f"- 유지: {_n(s['records_kept'])}\n")
    L.append("P2는 **표시**만 한다. 물리적 삭제는 P3에서 데이터셋을 실제로 구성할 때 일어난다. "
             "이렇게 하면 제거율이 감사 가능하고, 모든 판단이 되돌릴 수 있으며, 임계값을 바꾸려고 "
             "파이프라인 전체를 다시 돌릴 필요가 없다.\n")

    L.append("## 1. 임계값 보정 — 이 단계의 핵심 산출물\n")
    L.append("논문에서 가져온 임계값은 **주장**이다. 라벨링된 표본에서 정밀도·재현율을 측정해 고른 "
             "임계값은 **측정**이다. 아래가 그 측정이다.\n")
    L.append(f"라벨링된 쌍: **{cal['labelled_pairs']}개** (유사도 구간별 층화 표집)\n")
    L.append("| 임계값 | 클러스터 수 | 표시된 레코드 | 정밀도 (95% CI) | 재현율 (95% CI) | F1 | TP | FP | FN | TN |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in cal["table"]:
        pc = r.get("precision_ci95", [float("nan")] * 2)
        rc = r.get("recall_ci95", [float("nan")] * 2)
        mark = " **←채택**" if abs(r["threshold"] - m["chosen_near_duplicate_threshold"]) < 1e-9 else ""
        L.append(f"| **{r['threshold']:.2f}**{mark} | {_n(r['clusters'])} | {_n(r['records_marked_near_duplicate'])} | "
                 f"{r['precision']:.3f} [{pc[0]:.3f}, {pc[1]:.3f}] | "
                 f"{r['recall']:.3f} [{rc[0]:.3f}, {rc[1]:.3f}] | {r['f1']:.3f} | "
                 f"{r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} |")
    L.append("")
    L.append(f"### 채택 임계값: **{m['chosen_near_duplicate_threshold']}**\n")
    L.append(f"> {m['threshold_rationale']}\n")

    ann = cal.get("annotation") or {}
    L.append("### 라벨링 기록\n")
    L.append(f"- 라벨러: **{ann.get('annotator')}**")
    L.append(f"- 사람 보안 전문가 여부: **{'예' if ann.get('annotator_is_human_domain_expert') else '아니오'}**")
    L.append(f"- 라벨링 일자: {ann.get('labelled_on')}")
    L.append(f"- 주어진 지시문: {ann.get('instruction')}")
    L.append(f"- 방법: {ann.get('method')}")
    L.append(f"- 라벨 원본: `data/labels/near_dup_pairs.jsonl` (저장소에 커밋됨)\n")
    L.append("### 이 표가 말할 수 없는 것\n")
    for lim in cal.get("limits", []):
        L.append(f"- {lim}")
    L.append("")
    if ann.get("caveat"):
        L.append(f"> {ann['caveat']}\n")

    L.append("## 2. 단계별 결과\n")
    L.append("| 단계 | 의미 | 레코드 수 |")
    L.append("|---|---|---|")
    meaning = {
        "exact": "정규화 후 텍스트가 완전히 동일 (동일 content_type 내)",
        "near": f"MinHash+LSH, Jaccard ≥ {m['chosen_near_duplicate_threshold']}",
        "identity": "두 출처가 같은 엔티티를 서술 — **중복이 아니며 전부 유지**",
        "unique": "중복이 발견되지 않음",
    }
    for stage, cnt in sorted(s["decisions_by_stage"].items(), key=lambda kv: -kv[1]):
        L.append(f"| `{stage}` | {meaning.get(stage,'')} | {_n(cnt)} |")
    L.append("")

    L.append("### 정규화(Stage 1) — 무엇이 실제로 바뀌었나\n")
    L.append("무엇이 바뀌었는지가 발견 사항이다. '정규화했다'는 발견 사항이 아니다.\n")
    L.append("| 출처 | 변환 | 영향받은 레코드 |")
    L.append("|---|---|---|")
    for src, counts in sorted(st["canonical"]["transforms_applied_counts"].items()):
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            L.append(f"| `{src}` | `{k}` | {_n(v)} |")
    L.append("")
    L.append("**소문자화·구두점 제거·불용어 제거는 하지 않았다.** 보안 텍스트는 대소문자와 구두점에 "
             "의미가 있다 (`CVE-2021-44228`, `../../`, `${jndi:ldap://}`, `O_CREAT|O_EXCL`). "
             "공격적인 정규화는 이 코퍼스가 존재하는 이유인 신호를 파괴한다.\n")

    L.append("### Stage 2 — 완전 일치 중복\n")
    ex = st["exact"]
    L.append(f"- 클러스터 {_n(ex['exact_clusters'])}개, 중복 표시 {_n(ex['records_marked_duplicate'])}건")
    L.append(f"- 정규화 후 텍스트가 빈 레코드 {_n(ex['records_skipped_empty_text'])}건은 **제외**했다 — "
             "전부 빈 문자열의 SHA-256으로 해시되어 하나의 거대한 가짜 클러스터가 되기 때문이다.\n")

    L.append("### Stage 4 — 근접 중복 (content_type별)\n")
    L.append("| content_type | 레코드 | 해시됨 | 후보 쌍 | 클러스터 | 표시됨 |")
    L.append("|---|---|---|---|---|---|")
    for ct, v in sorted(st["near"]["by_content_type"].items(), key=lambda kv: -kv[1]["records"]):
        if not v["records"]:
            continue
        L.append(f"| `{ct}` | {_n(v['records'])} | {_n(v['hashed'])} | {_n(v['candidate_pairs'])} | "
                 f"{_n(v['clusters'])} | {_n(v['records_marked_near_duplicate'])} |")
    L.append("")
    p = st["near"]["params"]
    L.append(f"- 파라미터: seed=`{p['seed']}`, 순열 {p['num_perm']}개, {p['shingle_size']}-gram 셰일, "
             f"최소 토큰 {p['min_tokens']}, 버킷 상한 {p['max_bucket_size']}")
    L.append("- **content_type별로 실행했고 전역으로 돌리지 않았다.** STIX relationship 객체와 CVE 설명을 "
             "비교하는 것은 의미가 없고, LSH 버킷을 쓰레기로 포화시킨다.")
    L.append("- **셰일 입력에서 보안 엔티티를 제거하지 않았다.** CVE 식별자·제품명·버전 문자열을 빼는 것은 "
             "그럴듯해 보이는 최적화지만, 그러면 \"a buffer overflow in X version Y allows remote attackers "
             "to execute arbitrary code\"만 남아 서로 무관한 수백 개 CVE가 한 클러스터로 뭉친다.\n")

    L.append("## 3. 출처별 / content_type별 분포\n")
    L.append("| 출처 | " + " | ".join(f"`{k}`" for k in sorted(s["decisions_by_stage"])) + " |")
    L.append("|---" * (len(s["decisions_by_stage"]) + 1) + "|")
    for src, c in sorted(s["by_source"].items()):
        L.append(f"| `{src}` | " + " | ".join(_n(c.get(k, 0)) for k in sorted(s["decisions_by_stage"])) + " |")
    L.append("")

    L.append("## 4. 재현성과 비용\n")
    L.append(f"> {m['determinism']}\n")
    if rt:
        L.append(f"- 전체 벽시계 시간: **{rt.get('total_wall_seconds')}초**")
        L.append(f"- 최대 RSS: **{rt.get('peak_rss_bytes', 0)/2**30:.1f} GiB**")
        for k, v in (rt.get("stage_seconds") or {}).items():
            if v is not None:
                L.append(f"  - `{k}`: {v}초")
        slow = [k for k, v in (rt.get("stage_seconds") or {}).items() if v and v > 1800]
        if slow:
            L.append(f"- ⚠️ 30분을 초과한 단계: {slow}")
        else:
            L.append("- 30분을 초과한 단계는 없다.")
    L.append("")
    out = REPORTS / "dedup.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def render_secrets(m: dict) -> Path:
    sec = m["stages"]["secrets"]
    L = []
    L.append("# P2 시크릿·PII 스캔 보고서\n")
    L.append("> **이 문서에는 탐지된 값이 하나도 들어 있지 않다.** 유형·필드·출처별 개수만 적는다. "
             "자기가 찾은 시크릿을 커밋하는 시크릿 스캐너는 '보고서가 딸린 보안 사고'다.\n")
    L.append(f"- 스캔한 레코드: **{_n(sec['records_scanned'])}**")
    L.append(f"- 탐지 건수: **{_n(sec['findings_total'])}**")
    L.append(f"- 분류별: {sec['findings_by_category']}\n")

    L.append("## 유형별\n")
    L.append("| 유형 | 탐지 건수 | 고유 값 개수 | 처리 |")
    L.append("|---|---|---|---|")
    ACTION = {
        "credentials_in_url": "복구 불가 마커로 치환", "aws_access_key_id": "복구 불가 마커로 치환",
        "github_token": "복구 불가 마커로 치환", "slack_token": "복구 불가 마커로 치환",
        "google_api_key": "복구 불가 마커로 치환", "private_key_block": "복구 불가 마커로 치환",
        "jwt": "복구 불가 마커로 치환", "generic_secret_assignment": "복구 불가 마커로 치환",
        "email": "안정적 가명 (`USER_xxxx`)", "internal_hostname": "안정적 가명 (`HOST_xxxx`)",
        "private_ip": "안정적 가명 (`IP_xxxx`)",
    }
    for k, v in sec["findings_by_type"].items():
        L.append(f"| `{k}` | {_n(v)} | {_n(sec['unique_values_by_type'].get(k, 0))} | {ACTION.get(k,'—')} |")
    L.append("")

    L.append("## 출처별\n")
    L.append("| 출처 | 탐지 건수 | 탐지된 레코드 수 |")
    L.append("|---|---|---|")
    for src, v in sorted(sec["findings_by_source"].items(), key=lambda kv: -kv[1]):
        L.append(f"| `{src}` | {_n(v)} | {_n(sec['records_with_findings'].get(src, 0))} |")
    L.append("")
    L.append("### 출처 × 유형\n")
    L.append("| 출처 | 유형 | 건수 |")
    L.append("|---|---|---|")
    for src, c in sorted(sec["findings_by_source_and_type"].items()):
        for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
            L.append(f"| `{src}` | `{k}` | {_n(v)} |")
    L.append("")

    L.append("## 정책 — 공개 악성 지표(IOC)는 마스킹하지 않는다\n")
    for k, v in sec["policy"].items():
        L.append(f"- **{k}**: {v}")
    L.append("")
    L.append("이 구분이 핵심이다. **URL에 유출된 자격증명**과 **그 레코드의 존재 이유인 IOC**는 다르다. "
             "멀웨어 C2 도메인, 공격자 IP, 파일 해시는 ATT&CK과 CVE 참조의 본문 내용이다. "
             "이것들을 가리면 코퍼스의 가치가 사라진다. 그래서 라우팅 가능한 공인 IP는 탐지 대상이 아니고, "
             "사설·루프백 대역만 가명 처리한다.\n")
    L.append("가명은 코퍼스 전체에서 **안정적**이다. 같은 값은 항상 같은 가명이 되므로 동시출현 구조가 살아남는다. "
             "반면 실제 시크릿은 가명이 아니라 복구 불가 마커로 바뀐다 — 가명은 '되돌릴 수 있다'는 잘못된 약속이기 때문이다.\n")
    out = REPORTS / "secrets.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def render_conflicts(m: dict) -> Path:
    ident = m["stages"]["identity"]
    L = []
    L.append("# P2 교차 출처 엔티티 충돌 보고서\n")
    L.append("> `manifests/process.manifest.json`에서 **자동 생성**된다.\n")
    L.append("## 같은 CVE가 두 출처에 있는 것은 중복이 아니다\n")
    L.append("`cve_list`와 `nvd`에 같은 CVE가 나타난다. **이것은 중복이 아니다.** 하나의 엔티티를 "
             "서술하는 두 출처이고, **둘 사이의 차이가 곧 정보다.** 합쳐버리면 이 코퍼스를 만들 이유가 사라진다.\n")
    L.append(f"- 전체 엔티티: **{_n(ident['entities'])}**")
    L.append(f"- 2개 이상 출처에 존재: **{_n(ident['entities_in_multiple_sources'])}**")
    L.append(f"- 단일 출처에만 존재: **{_n(ident['entities_in_one_source_only'])}**")
    L.append(f"- **필드 충돌이 있는 엔티티: {_n(ident['entities_with_field_conflicts'])}**\n")
    L.append("## 필드별 충돌\n")
    L.append("| 충돌 종류 | 엔티티 수 | 의미 |")
    L.append("|---|---|---|")
    MEAN = {
        "cwe_ids": "양쪽 출처가 모두 CWE를 부여했으나 **서로 다르다**",
        "cwe_ids_one_sided": "한쪽 출처에만 CWE가 있다",
        "cvss_base_score": "양쪽 모두 점수가 있으나 0.05 초과로 다르다",
        "cvss_base_score_one_sided": "한쪽에만 점수가 있다",
    }
    for k, v in sorted(ident["conflicts_by_field"].items(), key=lambda kv: -kv[1]):
        L.append(f"| `{k}` | {_n(v)} | {MEAN.get(k,'')} |")
    L.append("")
    L.append("## CVE→CWE 과제 설계에 주는 함의\n")
    n_conf = ident["conflicts_by_field"].get("cwe_ids", 0)
    n_one = ident["conflicts_by_field"].get("cwe_ids_one_sided", 0)
    L.append(f"- **{_n(n_conf)}개 CVE에서 CNA가 부여한 CWE와 NVD 분석가가 부여한 CWE가 다르다.** "
             "어느 쪽을 정답으로 삼을지는 **P3가 결정한다.** P2는 그 선택지가 존재한다는 사실을 드러낼 뿐이며, "
             "여기서 해소하지 않는다.")
    L.append(f"- {_n(n_one)}개 CVE는 한쪽 출처에만 CWE가 있다. 정답 출처를 한쪽으로 고정하면 "
             "이만큼의 학습 데이터가 사라진다.")
    L.append("- 이 숫자들이 과제 설계를 좌우한다: 정답 출처 선택, 다중 정답 허용 여부, "
             "충돌 사례를 평가에서 제외할지 여부.\n")
    L.append(f"> {ident['note']}\n")
    out = REPORTS / "entity_conflicts.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def main():
    m = json.loads(MANIFEST.read_text())
    rt = json.loads(RUNTIME.read_text()) if RUNTIME.exists() else {}
    for p in (render_dedup(m, rt), render_secrets(m), render_conflicts(m)):
        print(f"wrote {p}")


if __name__ == "__main__":
    main()
