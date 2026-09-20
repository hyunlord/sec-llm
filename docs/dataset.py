# -*- coding: utf-8 -*-
"""docs/DATASET.md -- the dataset specification.

Per source: what was pinned, how much came out, what was normalised, what was
deduplicated and at what rate. Per task: how the item was constructed, where
the ground truth came from, how the split was drawn and what was done about
contamination. Then the decisions with their counts, and the corrections.

The corrections section is not an appendix. A specification that records what
it got wrong is easier to trust than one that reads as if nothing ever needed
fixing, and each correction in it produced a rule that is still enforced.
"""

from __future__ import annotations

from docs.common import Fmt, SPLIT_KO, TASK_KO, gen_note

SOURCE_KO = {
    "cve_list": "CVE List V5 — CVE 레코드 원본",
    "nvd": "NVD `CVE API 2.0` — NIST 분석(CVSS·CPE·CWE 매핑)",
    "cwe": "CWE 카탈로그 — 약점 분류 체계",
    "attack": "MITRE ATT&CK STIX 번들 — 공격 기법",
}
SOURCES4 = ("cve_list", "nvd", "cwe", "attack")


def _pin_line(F: Fmt, sid: str) -> str:
    pin = F.get(sid, "pin")
    kind = pin["pin_type"]
    if kind == "git_commit":
        return f"git 커밋 `{pin['commit_sha']}` (`{pin['repo']}`, `{pin['resolved_ref']}`)"
    if kind == "git_tag_release":
        return f"git 태그 `{pin['tag']}` → 커밋 `{pin['commit_sha']}` (`{pin['repo']}`)"
    if kind == "versioned_release":
        return f"버전 고정 URL `{pin['url']}` (v{pin['version']})"
    if kind == "api_paged_snapshot":
        return f"API 페이지 스냅샷 (`{F.get(sid, 'source_url')}`)"
    return kind


def render(F: Fmt) -> str:
    L = ["# 데이터셋 명세", "", gen_note(), ""]

    L.append("이 문서는 무엇이 들어왔고, 무엇이 왜 빠졌고, 무엇이 평가 세트에 남았는지를 적는다. "
             "원본 코퍼스는 재배포하지 않는다 — 핀과 해시와 매니페스트만 배포하고, "
             "다운로더가 그것으로 다시 만든다(`docs/REPRODUCE.md`).")
    L.append("")

    # ============================================================== 출처
    L.append("## 출처")
    L.append("")
    L.append(f"네 개 출처, 정규화 이전 원시 레코드 **{F.n('process', 'summary', 'records_in')}건**. "
             "모두 불변 참조로 고정되어 있고, 같은 핀에 대해 다시 수집하면 매니페스트가 바이트 단위로 재현된다"
             "(`make ingest-verify`, 네트워크를 막고도 `make ingest-offline`).")
    L.append("")
    L.append("| 출처 | 핀 | 고정 시각 (UTC) | 레코드 | 엔티티 ID 커버리지 | 라이선스 |")
    L.append("|---|---|---|---|---|---|")
    for sid in SOURCES4:
        L.append(f"| **{SOURCE_KO[sid]}**<br>`{sid}` "
                 f"| {_pin_line(F, sid)} "
                 f"| {F.s(sid, 'pin', 'pinned_at_utc')} "
                 f"| {F.n(sid, 'counts', 'records')} "
                 f"| {F.pct(sid, 'entity_id_coverage', nd=1)} "
                 f"| {F.s(sid, 'license', 'redistribution_status')} |")
    L.append("")
    L.append("엔티티 ID 커버리지가 출처마다 다른 것은 결함이 아니다. ATT&CK STIX 번들은 "
             "기법·소프트웨어·관계 객체를 한 파일에 담고 있고, 그중 CVE처럼 안정된 외부 식별자를 갖는 것은 "
             f"일부다 — 식별 가능한 레코드만 놓고 보면 커버리지는 "
             f"{F.pct('attack', 'entity_id_coverage_identifiable', nd=1)}이다. "
             "어떤 콘텐츠 타입이 식별자를 갖지 않는지는 매니페스트의 `content_types_without_entity_id`에 "
             "열거되어 있다.")
    L.append("")
    L.append("### 계통(lineage) 필드")
    L.append("")
    L.append("모든 레코드는 아래 필드를 달고 다닌다. 출처를 잃은 레코드는 없다.")
    L.append("")
    fields = F.get("cve_list", "lineage_fields")
    L.append("".join(f"`{f}` · " for f in fields).rstrip(" ·"))
    L.append("")
    L.append(f"필드 수는 {F.count('cve_list', 'lineage_fields')}개이며, 이 중 다섯 개"
             "(`source_license`, `upstream_license`, `redistribution_status`, `commercial_status`, "
             "`model_publication_status`)는 라이선스 판정을 레코드 단위로 끌고 가기 위한 것이다. "
             "그 판정들이 어디서 왔는지는 `docs/LICENSES.md`에 있다.")
    L.append("")

    # ============================================================== 정제
    L.append("## 정제와 중복 제거")
    L.append("")
    L.append("P2는 **표시하고 지우지 않는다.** 입력 레코드는 전부 출력에 나타나며 결정이 달려 있을 뿐이다. "
             f"물리적으로 삭제된 레코드는 {F.plain('process', 'summary', 'records_deleted')}건이다.")
    L.append("")
    L.append("### 정규화")
    L.append("")
    tn = F.get("process", "stages", "canonical", "transform_names")
    L.append("적용된 변환: " + ", ".join(f"`{t}`" for t in tn) + ".")
    L.append("")
    L.append(f"유니코드 NFC, CRLF→LF, 제어문자·제로폭 문자 제거, NBSP 정규화, 공백 정리. "
             f"정규화 후 본문이 비는 레코드는 출처별로 기록된다 — `cve_list` "
             f"{F.n('process', 'stages', 'canonical', 'records_with_empty_text', 'cve_list')}건은 "
             f"거의 전부 REJECTED 상태의 CVE이고, 이들은 아래 결정 절에서 별도로 처리된다.")
    L.append("")
    L.append("### 중복 제거")
    L.append("")
    near = F.get("process", "stages", "near", "by_content_type")["cve_record_v5_json"]
    L.append("| 단계 | 방법 | 파라미터 | 결과 |")
    L.append("|---|---|---|---|")
    L.append(f"| 완전 일치 | 정규화 본문의 sha256 | — | 클러스터 "
             f"{F.n('process', 'stages', 'exact', 'exact_clusters')}개, "
             f"중복 표시 {F.n('process', 'stages', 'exact', 'records_marked_duplicate')}건 |")
    L.append(f"| 근사 중복 | MinHash + LSH, Jaccard "
             f"| 순열 {F.plain('datasets', 'contamination', 'index', 'minhash_params', 'num_perm')} · "
             f"shingle {F.plain('datasets', 'contamination', 'index', 'minhash_params', 'shingle_size')} · "
             f"밴드 {F.plain('process', 'stages', 'near', 'by_content_type', 'cve_record_v5_json', 'bands')}"
             f"×{F.plain('process', 'stages', 'near', 'by_content_type', 'cve_record_v5_json', 'rows_per_band')} "
             f"· 임계값 {F.d('process', 'chosen_near_duplicate_threshold', nd=2)} "
             f"| `cve_record_v5_json`만 해도 후보쌍 {F.n('process', 'stages', 'near', 'by_content_type', 'cve_record_v5_json', 'candidate_pairs')}개 → "
             f"클러스터 {F.n('process', 'stages', 'near', 'by_content_type', 'cve_record_v5_json', 'clusters')}개 |")
    L.append(f"| 동일 엔티티 묶기 | CVE ID | — | 엔티티 "
             f"{F.n('process', 'stages', 'identity', 'entities')}개, "
             f"필드 충돌 {F.n('process', 'stages', 'identity', 'entities_with_field_conflicts')}개 |")
    L.append("")
    L.append("**동일 엔티티 묶기는 중복 제거가 아니다.** 두 출처가 같은 CVE를 서술하는 것은 중복이 아니라 "
             "비교 가능한 두 진술이며, 그 불일치야말로 이 단계가 존재하는 이유다. 묶인 레코드는 모두 "
             "`dedup_keep=true`를 유지한다.")
    L.append("")
    L.append(f"전체 제거율은 **{F.pct('process', 'summary', 'removal_rate', nd=1)}**"
             f"({F.n('process', 'summary', 'records_marked_not_kept')} / "
             f"{F.n('process', 'summary', 'records_in')})이다.")
    L.append("")

    # ------------------------------------------------ threshold provenance
    L.append("### 근사 중복 임계값 — 보정되지 않았다")
    L.append("")
    L.append(f"임계값 **{F.d('datasets', 'contamination', 'index', 'near_threshold', nd=2)}**는 "
             "P2의 보정 실험에서 채택되었다. 그 실험의 **재현율(recall) 열은 나중에 표본 설계를 다시 진술한 것에 "
             "지나지 않는다는 사실이 밝혀졌다** — 재현율은 LSH가 이미 제안한 후보쌍에 대해서만 측정되므로, "
             "LSH가 제안한 적 없는 쌍은 분모에 들어올 수 없다. 임계값을 낮추면 후보가 늘고 재현율이 따라 오르는 것은 "
             "발견이 아니라 정의다. 재보정(P2.1)은 요청되었으나 **아직 수행되지 않았고, 임계값은 재보정되지 않은 채로 "
             "남아 있으며, 평가 세트는 그 위에 서 있다.** 이 문서는 그것을 기다리지 않고 그대로 적는다.")
    L.append("")
    L.append(f"P2가 자기 한계를 매니페스트에 적어 두었고(`stages.calibration.limits`), "
             f"라벨은 {F.n('process', 'stages', 'calibration', 'labelled_pairs')}쌍이다. 그대로 옮긴다.")
    L.append("")
    for i in range(len(F.get("process", "stages", "calibration", "limits"))):
        L.append(f"- {F.s('process', 'stages', 'calibration', 'limits', i)}")
    L.append("")
    L.append("| 임계값 | 정밀도 | 정밀도 신뢰구간(`ci95`) | 재현율(후보쌍 기준) | 근사 중복 표시 |")
    L.append("|---|---|---|---|---|")
    for i in range(len(F.get("process", "stages", "calibration", "table"))):
        base = ("process", "stages", "calibration", "table", i)
        L.append(f"| {F.d(*base, 'threshold', nd=2)} "
                 f"| {F.pct(*base, 'precision', nd=1)} "
                 f"| {F.ci_abs(*base, 'precision_ci95', nd=1, scale=100, unit='%')} "
                 f"| {F.pct(*base, 'recall', nd=1)} "
                 f"| {F.n(*base, 'records_marked_near_duplicate')} |")
    L.append("")

    # ============================================================== 비밀·PII
    L.append("### 비밀과 PII")
    L.append("")
    sec = F.get("process", "stages", "secrets")
    L.append(f"{F.n('process', 'stages', 'secrets', 'records_scanned')}건 전수 스캔, "
             f"발견 {F.n('process', 'stages', 'secrets', 'findings_total')}건"
             f"(비밀 {F.n('process', 'stages', 'secrets', 'findings_by_category', 'secret')}, "
             f"PII {F.n('process', 'stages', 'secrets', 'findings_by_category', 'pii')}).")
    L.append("")
    for k, v in sorted(sec["policy"].items()):
        L.append(f"- `{k}`: {F.s('process', 'stages', 'secrets', 'policy', k)}")
    L.append("")
    L.append("**공개 침해지표는 마스킹하지 않는다.** 라우팅 가능한 IP, C2 도메인, 파일 해시는 이 코퍼스의 "
             "내용 그 자체다. 마스킹되는 것은 사설 IP·내부 호스트명·이메일·URL 내 자격증명이며, "
             "**탐지된 비밀 값은 저장소에 절대 기록되지 않는다** — 개수와 단방향 다이제스트만 남는다.")
    L.append("")

    # ============================================================== 과제
    L.append("## 과제")
    L.append("")
    L.append("| 과제 | 구성 규칙 | 정답 출처 | 학습 | 평가(컷오프 이후) | 평가(컷오프 이전) | 채점 |")
    L.append("|---|---|---|---|---|---|---|")
    rules = {
        "cve_to_cwe": ("CVE 설명 → CWE ID 한 개", "CVE List와 NVD가 **합의한** CWE"),
        "cvss_vector": ("CVE 설명 → `CVSS v3.1` 벡터 문자열", "NVD 기본 메트릭 벡터"),
        "structured_extract": ("CVE 설명 → 벤더·제품·버전 JSON", "CVE 레코드의 `affected` 배열"),
        "attack_technique": ("기법 설명 → ATT&CK 기법 ID", "STIX `external_references`"),
    }
    for t in ("cve_to_cwe", "cvss_vector", "structured_extract", "attack_technique"):
        scored = F.get("datasets", "scored", t)
        L.append(f"| **{TASK_KO[t]}**<br>`{t}` | {rules[t][0]} | {rules[t][1]} "
                 f"| {F.n('datasets', 'tasks', t, 'by_split', 'train')} "
                 f"| {F.n('datasets', 'tasks', t, 'by_split', 'eval_post_cutoff')} "
                 f"| {F.n('datasets', 'tasks', t, 'by_split', 'eval_pre_cutoff')} "
                 f"| {'예' if scored else '**아니오**'} |")
    L.append("")
    L.append(f"각 과제는 프롬프트 템플릿 세 개를 균등하게 돌려 쓴다 — 예를 들어 `cve_to_cwe`는 "
             f"{F.n('datasets', 'tasks', 'cve_to_cwe', 'by_template', '0')} / "
             f"{F.n('datasets', 'tasks', 'cve_to_cwe', 'by_template', '1')} / "
             f"{F.n('datasets', 'tasks', 'cve_to_cwe', 'by_template', '2')}건이다. "
             "템플릿 하나에만 맞춰 과적합된 결과를 능력으로 읽지 않기 위한 것이다.")
    L.append("")
    L.append("### `attack_technique`는 채점하지 않는다")
    L.append("")
    L.append("> " + F.s("datasets", "not_scored_reason", "attack_technique"))
    L.append("")
    L.append("데이터셋과 매니페스트에는 남아 있고 서술적으로 보고되지만, **조건 간 비교에는 들어가지 않는다.** "
             "신뢰구간이 신뢰구간이 매우 넓은 수치로 두 조건의 차이를 주장할 수 없기 때문이다. "
             "지우지 않고 표시만 한다.")
    L.append("")

    # ============================================================== 분할
    L.append("## 분할 정책")
    L.append("")
    t = F.get("datasets", "decisions", "temporal_split")
    L.append(f"**컷오프: {F.s('datasets', 'decisions', 'temporal_split', 'cutoff')}.** "
             "평가 세트는 이 날짜 이후에 공개된 CVE에서만 뽑는다.")
    L.append("")
    L.append("이유는 하나다. CVE 텍스트는 웹 전역에 미러링되어 있어 무작위 분할로는 베이스 모델의 "
             "사전학습 오염을 막을 수 없다. 막을 수 있는 것은 **베이스 모델이 볼 수 없었던 날짜**뿐이다. "
             "학습은 컷오프 이전 데이터만 쓴다"
             f"(`training_uses_only_pre_cutoff`: {F.s('datasets', 'decisions', 'temporal_split', 'training_uses_only_pre_cutoff')}).")
    L.append("")
    L.append("컷오프 이전 평가 세트도 같은 크기로 유지한다. 두 평가 세트의 차이는 "
             "**오염된 상태와 오염되지 않은 상태의 대조**이지, 난이도 비교가 아니다.")
    L.append("")
    L.append("| 항목 | 값 |")
    L.append("|---|---|")
    L.append(f"| 기간별 평가 표본 | {F.n('datasets', 'decisions', 'temporal_split', 'eval_sample_per_period')} |")
    L.append(f"| 학습(CVE) | {F.n('datasets', 'decisions', 'temporal_split', 'split_counts_cve', 'train')} |")
    L.append(f"| 컷오프 이후 · 미사용 | {F.n('datasets', 'decisions', 'temporal_split', 'split_counts_cve', 'post_cutoff_unused')} |")
    L.append(f"| 제외(CVE) | {F.n('datasets', 'decisions', 'temporal_split', 'split_counts_cve', 'excluded')} |")
    L.append(f"| ATT&CK 학습 / 평가·이후 / 평가·이전 / 제외 | "
             f"{F.n('datasets', 'decisions', 'temporal_split', 'split_counts_attack', 'train')} / "
             f"{F.n('datasets', 'decisions', 'temporal_split', 'split_counts_attack', 'eval_post_cutoff')} / "
             f"{F.n('datasets', 'decisions', 'temporal_split', 'split_counts_attack', 'eval_pre_cutoff')} / "
             f"{F.n('datasets', 'decisions', 'temporal_split', 'split_counts_attack', 'excluded')} |")
    L.append("")
    L.append(f"컷오프 이후 CVE 중 {F.n('datasets', 'decisions', 'temporal_split', 'post_cutoff_unused_cves')}건은 "
             "평가 표본에 뽑히지 않고 **미사용으로 남겨 둔다.** 학습에 넣으면 컷오프의 의미가 사라지고, "
             "평가에 다 넣으면 평가 비용이 감당되지 않는다. 지우지 않고 표시한다.")
    L.append("")

    # ============================================================== 오염
    L.append("## 오염 처리")
    L.append("")
    idx = F.get("datasets", "contamination", "index")
    L.append(f"학습 텍스트 {F.n('datasets', 'contamination', 'index', 'train_texts_hashed_for_near_dup')}건을 "
             f"해싱해 평가 항목마다 최근접 이웃을 찾고, Jaccard가 "
             f"{F.d('datasets', 'contamination', 'index', 'near_threshold', nd=2)} 이상이면 제거한다. "
             "**적용되는 기준은 이것 하나다.**")
    L.append("")
    L.append("`13-gram` 커버리지는 **측정해서 붙이되 거르지 않는다.** 모든 평가 항목에 "
             "`train_ngram_coverage`가 달리고, 평가 세트마다 사분위 경계가 기록되며, "
             "P4는 전체 점수와 계층별 점수를 함께 보고한다. "
             "커버리지가 높은 항목의 정확도가 높은 것은 오염일 수도, 그 항목이 쉬운 것일 수도 있다 — "
             "거르면 그 구분이 영원히 불가능해진다.")
    L.append("")
    L.append("| 평가 세트 | 제거 전 | 제거 후 | 제거 | 제거율 | 커버리지 0 | `P3.1`이라면 제거했을 수 |")
    L.append("|---|---|---|---|---|---|---|")
    for t_ in ("cve_to_cwe", "cvss_vector", "structured_extract", "attack_technique"):
        for sp in ("eval_post_cutoff", "eval_pre_cutoff"):
            k = f"{t_}/{sp}"
            base = ("datasets", "contamination", "eval_sets", k)
            L.append(f"| `{t_}` / {SPLIT_KO[sp]} "
                     f"| {F.n(*base, 'before')} | {F.n(*base, 'after')} "
                     f"| {F.n(*base, 'removed')} | {F.pct(*base, 'removed_fraction', nd=2)} "
                     f"| {F.n(*base, 'coverage_zero')} "
                     f"| {F.n(*base, 'diag_p31_criterion_would_remove')} |")
    L.append("")
    rec = F.get("datasets", "contamination", "reconciliation_with_p31")
    L.append(f"`P3.1`은 근사 중복 **또는** 커버리지가 "
             f"{F.d('datasets', 'contamination', 'index', 'superseded_p31_coverage_max', nd=1)}을 넘는 것을 적용해 "
             f"{F.n('datasets', 'contamination', 'reconciliation_with_p31', 'p31_removed_total')}건을 제거했다. "
             f"`P3.2`는 근사 중복만 적용해 "
             f"{F.n('datasets', 'contamination', 'reconciliation_with_p31', 'p32_removed_total')}건을 제거하고 "
             f"{F.n('datasets', 'contamination', 'reconciliation_with_p31', 'restored_coverage_only')}건을 되돌렸다. "
             "두 수의 합은 정확히 첫 번째 수와 같으며, 그 항등식은 "
             f"`datasets/build.py`의 단언으로 강제된다.")
    L.append("")
    L.append("제거된 항목의 Jaccard 분포: "
             f"최소 {F.d('datasets', 'contamination', 'removed_near_jaccard', 'min', nd=2)}, "
             f"`q25` {F.d('datasets', 'contamination', 'removed_near_jaccard', 'q25', nd=4)}, "
             f"중앙값 {F.d('datasets', 'contamination', 'removed_near_jaccard', 'q50', nd=4)}, "
             f"`q75` {F.d('datasets', 'contamination', 'removed_near_jaccard', 'q75', nd=2)}, "
             f"최대 {F.d('datasets', 'contamination', 'removed_near_jaccard', 'max', nd=1)}.")
    L.append("")
    L.append(f"평가 세트끼리의 교차 오염은 네 과제 모두 "
             f"{F.plain('datasets', 'contamination', 'cross_eval', 'cve_to_cwe')}건이다.")
    L.append("")

    # ============================================================== 결정
    L.append("## 결정과 그 개수")
    L.append("")
    L.append("각 결정은 얼마나 많은 레코드를 움직였는지와 함께 적는다. 개수 없는 정책은 검증할 수 없다.")
    L.append("")
    g = F.get("datasets", "decisions", "cwe_ground_truth")
    L.append("### CWE 정답 정책")
    L.append("")
    L.append("> " + F.s("datasets", "decisions", "cwe_ground_truth", "policy"))
    L.append("")
    L.append("| 버킷 | 건수 | 처리 |")
    L.append("|---|---|---|")
    bucket_ko = {
        "agreed": ("두 출처가 합의", "정답으로 사용"),
        "nvd": ("NVD만 라벨", "출처를 기록하고 사용"),
        "cna": ("CNA만 라벨", "출처를 기록하고 사용"),
        "contested": ("두 출처가 **불일치**", "**제외하고 보고**"),
        "placeholder": ("NVD-CWE-noinfo 등 플레이스홀더", "**라벨 없음으로 취급**"),
        "multi_cwe": ("CWE 여러 개", "단일 라벨 과제에서 제외"),
        "none": ("라벨 없음", "제외"),
        "rejected": ("REJECTED 상태 CVE", "**제외**"),
    }
    for b in ("agreed", "nvd", "cna", "contested", "placeholder", "multi_cwe", "none", "rejected"):
        L.append(f"| {bucket_ko[b][0]} (`{b}`) | {F.n('datasets', 'decisions', 'cwe_ground_truth', 'buckets', b)} "
                 f"| {bucket_ko[b][1]} |")
    L.append("")
    L.append(f"**불일치 {F.n('datasets', 'decisions', 'cwe_ground_truth', 'buckets', 'contested')}건을 제외한 것**은 "
             "이 명세에서 가장 큰 임의적 결정이다. 두 권위 있는 출처가 같은 CVE에 다른 CWE를 붙였을 때 "
             "어느 쪽을 정답으로 삼을 근거가 없다. 정답 없는 항목으로 모델을 채점하면 채점하는 것은 "
             "모델이 아니라 출처 선택이다. 제외하되 **보고한다** — "
             "상위 CNA와 상위 충돌 쌍은 매니페스트의 `contested_structure`에 있다.")
    L.append("")
    L.append(f"플레이스홀더 {F.n('datasets', 'decisions', 'cwe_ground_truth', 'buckets', 'placeholder')}건은 "
             "\"분류 정보 없음\"을 뜻하는 표식이지 CWE가 아니다. 라벨로 취급하면 모델은 "
             "\"모름\"을 예측하도록 학습된다. 라벨 없음으로 취급한다.")
    L.append("")
    L.append(f"REJECTED CVE {F.n('datasets', 'decisions', 'cwe_ground_truth', 'buckets', 'rejected')}건은 "
             "철회된 식별자다. 본문이 비어 있거나 철회 사유만 남아 있다. 제외한다.")
    L.append("")
    L.append("**누출 가드**: 근사 중복 클러스터의 대표 하나만 남기면, 남은 대표가 평가 세트에 있을 때 "
             "동일 내용의 학습 항목이 조용히 사라진다. 이를 막기 위해 "
             f"{F.n('datasets', 'decisions', 'cwe_ground_truth', 'guard', 'readmitted_to_train')}건을 학습으로 되돌리고, "
             f"대표가 평가에 있어 되돌리지 않은 "
             f"{F.n('datasets', 'decisions', 'cwe_ground_truth', 'guard', 'not_readmitted_rep_in_eval')}건은 "
             "그 사실과 함께 기록했다. 이 가드의 출처 표기는 "
             f"`{F.s('datasets', 'cwe_guard_provenance')}`로 매니페스트에 남아 있다.")
    L.append("")

    L.append("### 학습 조건")
    L.append("")
    c = F.get("datasets", "decisions", "conditions")
    L.append("> " + F.s("datasets", "decisions", "conditions", "design"))
    L.append("")
    L.append("| | Cond-1 | Cond-2 |")
    L.append("|---|---|---|")
    L.append(f"| 도메인 토큰 | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'domain_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'domain_tokens')} |")
    L.append(f"| 리플레이 토큰 | {F.plain('datasets', 'decisions', 'conditions', 'cond1', 'replay_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'replay_tokens')} |")
    L.append(f"| 합계 | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'total_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'total_tokens')} |")
    L.append(f"| 예제 | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'examples')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'domain_examples')} + "
             f"{F.n('datasets', 'decisions', 'conditions', 'cond2', 'replay_pairs')} 리플레이 |")
    L.append(f"| 옵티마이저 스텝 | {F.plain('datasets', 'lengths', 'equal_budget_schedule', 'cond1', 'optimizer_steps_per_epoch')} "
             f"| {F.plain('datasets', 'lengths', 'equal_budget_schedule', 'cond2', 'optimizer_steps_per_epoch')} |")
    L.append("")
    L.append(f"두 조건의 예산 차이는 {F.n('datasets', 'decisions', 'conditions', 'budget_residue_tokens')}토큰, "
             f"즉 {F.pct('datasets', 'decisions', 'conditions', 'budget_residue_fraction', nd=4)}다. "
             "**Cond-2의 도메인 집합은 Cond-1의 진부분집합**이며, 정렬된 `example_id`의 sha256이 "
             "교집합의 sha256과 같다는 것으로 증명된다"
             f"(`{F.s('datasets', 'decisions', 'conditions', 'subset_proof', 'verify')}`).")
    L.append("")
    L.append("이 설계의 대가는 분명하다: 동일 토큰 예산을 유지했으므로 Cond-2는 도메인 데이터를 "
             "Cond-1보다 적게 본다. 도메인 정확도에서 Cond-1이 앞서는 것은 발견이 아니라 설계의 귀결이다.")
    L.append("")

    L.append("### 리플레이 세트")
    L.append("")
    r = F.get("datasets", "decisions", "replay")
    L.append(f"출처는 `{F.s('datasets', 'decisions', 'replay', 'source')}`. "
             f"원본에서 쌍 {F.n('datasets', 'decisions', 'replay', 'parse', 'pairs')}개를 뽑았고 "
             f"이 중 {F.n('datasets', 'decisions', 'replay', 'subsample', 'pairs_selected')}개가 "
             "동일 예산 조건에 들어갔다.")
    L.append("")
    L.append(f"제외 사유별 개수: 언어 "
             f"{F.n('datasets', 'decisions', 'replay', 'parse', 'skip_language')}, "
             f"삭제됨 {F.n('datasets', 'decisions', 'replay', 'parse', 'skip_deleted')}, "
             f"검수 탈락 {F.n('datasets', 'decisions', 'replay', 'parse', 'skip_failed_review')}, "
             f"너무 짧음 {F.n('datasets', 'decisions', 'replay', 'parse', 'skip_too_short')}. "
             f"선택된 쌍의 언어 분포는 영어 {F.n('datasets', 'decisions', 'replay', 'lang_counts', 'en')} / "
             f"한국어 {F.plain('datasets', 'decisions', 'replay', 'lang_counts', 'ko')}이다.")
    L.append("")
    L.append(f"리플레이에도 P2와 **동일한** 비밀·PII 스캔을 적용했다 — "
             f"{F.n('datasets', 'decisions', 'replay', 'scan', 'pairs_scanned')}쌍 중 "
             f"{F.n('datasets', 'decisions', 'replay', 'scan', 'pairs_with_findings')}쌍에서 발견. "
             "정책은 P2와 같다.")
    L.append("")
    L.append("모델이 생성한 메시지(`synthetic: true`)는 **제외**한다. 사람이 쓴 턴만 쓴다는 제약이며, "
             "그것이 HelpSteer2를 쓰지 않은 이유이기도 하다 — 라이선스가 아니라 출처 때문이다"
             "(`docs/LICENSES.md`).")
    L.append("")

    # ============================================================== 수정 이력
    L.append("## 이 명세가 수정한 것들")
    L.append("")
    L.append("아래 네 건은 모두 **출판된 뒤에 발견된 결함**이다. 각각이 "
             "`docs/engineering-rules.md`의 규칙 하나를 낳았고, 그 규칙은 지금도 강제된다. "
             "수정 이력을 적지 않은 명세보다 적은 명세가 더 믿을 만하다.")
    L.append("")
    L.append("| 단계 | 결함 | 독자가 내렸을 결론 | 실제 | 낳은 규칙 |")
    L.append("|---|---|---|---|---|")
    L.append("| `P1.1` | `cwe` 매니페스트의 다이제스트가 Gate 1 테스트의 유도된 실패로 오염 "
             "| `cwe` 수집 실패 | 완전한 `v4.20` 매니페스트로 성공 | 규칙 {F.plain('refs', 'engineering_rules', 'report_renders_the_record')} |")
    L.append("| P3 | `--assert-zero` 재검증이 제거 기록과 **같은 파일**을 `removed: 0`으로 덮어씀 "
             "| 오염 없음 | 평가 세트의 상당 부분이 제거됨 | 규칙 {F.plain('refs', 'engineering_rules', 'report_renders_the_record')} |")
    L.append("| `P3.1` | 커버리지 초과를 **근거 없이** 제거 기준으로 사용 "
             f"| 오염 제거 | 커버리지가 높다는 것과 오염되었다는 것은 다른 진술 · "
             f"{F.n('datasets', 'contamination', 'reconciliation_with_p31', 'restored_coverage_only')}건 복원 | 규칙 {F.plain('refs', 'engineering_rules', 'no_unevidenced_threshold_deletes_data')} |")
    L.append("| P5 | 짝지은 비교를 주변 신뢰구간 겹침으로 판정 "
             f"| 차이 없음 | McNemar p={F.p('compare', 'general', 'hellaswag', 'pairs', 'cond1 vs cond2', 'mcnemar_p')}인 "
             "비교가 \"차이 검출되지 않음\"으로 출판됨 | 규칙 {F.plain('refs', 'engineering_rules', 'the_test_must_match_the_design')} |")
    L.append("")
    L.append("네 번째 결함의 판정 규칙은 **P4 작업지시서가 명시한 것**이고 구현은 그대로 따랐다. "
             "그 규칙은 출처까지 기록한다 — 지시서에서 온 결함도 결함이며, 지시서를 따랐다는 것은 "
             "잘못된 숫자를 출판한 변명이 되지 않는다.")
    L.append("")
    L.append("보정 전 수치는 지우지 않았다. `runs/compare_p5_uncorrected.json`에 그대로 있다.")
    L.append("")
    L.append("전체 규칙과 각 규칙이 나온 사건은 `docs/engineering-rules.md`에 있다.")
    L.append("")

    # ============================================================== 무결성
    L.append("## 무결성")
    L.append("")
    L.append(f"데이터셋 매니페스트 해시 `{F.get('compare', 'dataset_manifest_sha256', 'baseline')}`는 "
             "세 실행 모두에서 같다. 평가 하니스는 모델을 적재하기 **전에** 이 해시와 개별 평가 파일의 "
             "sha256을 검증하고, 하나라도 어긋나면 중단한다.")
    L.append("")
    L.append("| 평가 파일 | 건수 | sha256 |")
    L.append("|---|---|---|")
    files = F.get("baseline_run", "dataset", "files_verified")
    for k in sorted(files):
        L.append(f"| `{k}` | {F.n('baseline_run', 'dataset', 'files_verified', k, 'count')} "
                 f"| `{files[k]['sha256'][:16]}…` |")
    L.append("")
    L.append(f"결정론: {F.s('cve_list', 'determinism')}")
    L.append("")
    return "\n".join(L) + "\n"
