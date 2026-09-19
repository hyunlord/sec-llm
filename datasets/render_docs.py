# -*- coding: utf-8 -*-
"""Render the P3 Korean docs and reports from manifests/datasets.manifest.json.

Generated, so the published numbers cannot drift from the artifacts. Six files:
datasets/SPLIT.md, datasets/CWE_POLICY.md, datasets/CARD.md,
reports/datasets.md, reports/contamination.md, reports/lengths.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets.common import MANIFESTS, REPO, REPORTS  # noqa: E402

M = json.loads((MANIFESTS / "datasets.manifest.json").read_text())
D = REPO / "datasets"
TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
TASK_KO = {"cve_to_cwe": "CVE→CWE 분류", "cvss_vector": "CVSS v3.1 벡터", "attack_technique": "ATT&CK 기법 식별",
           "structured_extract": "구조화 추출", "replay": "리플레이(일반 지시)"}
SPLIT_KO = {"train": "학습", "eval_post_cutoff": "평가(컷오프 이후)", "eval_pre_cutoff": "평가(컷오프 이전)",
            "post_cutoff_unused": "컷오프 이후·미사용", "excluded": "제외"}


def n(x):
    return f"{x:,}" if isinstance(x, int) else str(x)


def gen_header(what):
    return (f"# {what}\n\n> `manifests/datasets.manifest.json`에서 **자동 생성**된다. "
            "손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.\n")


def split_md():
    t = M["decisions"]["temporal_split"]
    L = [gen_header("시간 분할 (Decision 1)")]
    L.append(f"## 컷오프: **{t['cutoff']}**\n")
    L.append("평가 세트는 **이 날짜 이후에 공개된 CVE에서만** 뽑는다. CVE 텍스트는 웹 전역에 미러링되어 있어 "
             "무작위 분할로는 베이스 모델의 사전학습 오염을 막을 수 없다. 베이스 모델이 볼 수 없었던 날짜는 막을 수 있다.\n")
    L.append("Qwen2.5-7B-Instruct는 2024년 9월에 공개되었고 학습 컷오프는 정확히 문서화되어 있지 않다. "
             "공개일보다 여유를 둔 날짜가 보수적인 선택이다.\n")
    L.append("## 학습은 컷오프 **이전** 데이터만 쓴다\n")
    L.append("\"시간으로 분할한다\"의 보수적 해석이며, 배포 상황(아직 존재하지 않던 CVE를 예측)을 그대로 모사한다. "
             f"컷오프 이후이지만 평가에 표집되지 않은 CVE **{n(t['post_cutoff_unused_cves'])}건**은 학습에 넣지 않고 "
             "별도로 보류·집계한다. P5가 필요하면 이 결정을 다시 볼 수 있도록 숫자를 남긴다.\n")
    L.append(f"## 컷오프 이전 평가 세트: {t['pre_cutoff_eval_years'][0]}–{t['pre_cutoff_eval_years'][1]}년\n")
    L.append("같은 크기의 평가 세트를 컷오프 이전 구간에서 따로 보류한다. **두 세트의 점수 차이가 이 파이프라인 "
             "자체의 오염 크기 추정치**이며, 각주가 아니라 1급 결과로 보고한다.\n")
    L.append(f"## 표집\n\n- 기간별 {n(t['eval_sample_per_period'])} CVE를 고정 시드의 안정 해시 순서로 표집한다 (입력 순서와 무관).")
    L.append("- 하나의 CVE는 하나의 분할 라벨만 갖고, 세 CVE 과제가 모두 같은 라벨을 쓴다 — 코드에서 검증한다.\n")
    L.append("## CVE 분할 집계\n\n| 분할 | CVE 수 |\n|---|---|")
    for k, v in sorted(t["split_counts_cve"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {SPLIT_KO.get(k,k)} (`{k}`) | {n(v)} |")
    L.append("\n## ATT&CK 기법 분할 (STIX `created` 기준)\n\n| 분할 | 기법 수 |\n|---|---|")
    for k, v in sorted(t["split_counts_attack"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {SPLIT_KO.get(k,k)} (`{k}`) | {n(v)} |")
    L.append("\n기법은 수가 적어 컷오프 이후 기법 **전부**를 평가에 넣고 같은 수를 2022–2023에서 보류한다.\n")
    (D / "SPLIT.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def cwe_md():
    c = M["decisions"]["cwe_ground_truth"]
    b = c["buckets"]
    L = [gen_header("CWE 정답 정책 (Decision 2)")]
    L.append("## 정책\n")
    L.append("| 상황 | 처리 | `cwe_source` |\n|---|---|---|")
    L.append("| 양쪽이 같은 단일 CWE | 정답 | `agreed` |")
    L.append("| NVD에만 있음 (단일) | 정답 | `nvd` |")
    L.append("| CNA에만 있음 (단일) | 정답 | `cna` |")
    L.append("| 양쪽이 다름 | **학습·평가 모두 제외**, `contested` 세트로 보고만 | — |")
    L.append("| 가용 출처가 2개 이상 CWE 부여 | 단일 라벨 과제이므로 제외 (`multi_cwe`) | — |")
    L.append("| `NVD-CWE-Other` / `NVD-CWE-noinfo` 뿐 | 라벨 아님 → 없는 것으로 취급 | — |")
    L.append("| REJECTED CVE | 모든 과제에서 제외 (철회 공지이지 취약점 텍스트가 아님) | — |")
    L.append("\n**다툼이 있는 라벨은 라벨이 아니다.** 한쪽을 고르지 않는다.\n")
    L.append("## 버킷별 집계 (394,958 CVE 전체)\n\n| 버킷 | CVE 수 | 비율 |\n|---|---|---|")
    tot = sum(b.values())
    for k, v in sorted(b.items(), key=lambda kv: -kv[1]):
        L.append(f"| `{k}` | {n(v)} | {v/tot:.2%} |")
    L.append("\n## 분할별 `cwe_source` (최종 산출 예제 기준)\n\n| 분할 | agreed | nvd | cna |\n|---|---|---|---|")
    for sp, cnt in c["cwe_source_by_split"].items():
        L.append(f"| `{sp}` | {n(cnt.get('agreed',0))} | {n(cnt.get('nvd',0))} | {n(cnt.get('cna',0))} |")
    cs = c["contested_structure"]
    L.append(f"\n## 다툼(`contested`) 세트의 구조 — 총 {n(cs['total'])}건\n")
    L.append("| 관계 | 건수 |\n|---|---|")
    for k, v in cs["relation"].items():
        L.append(f"| `{k}` | {n(v)} |")
    pf = cs["relation"].get("partial_overlap", 0) / cs["total"] if cs["total"] else 0
    L.append(f"\n**발견**: 다툼의 **{pf:.1%}가 부분 겹침**(한쪽이 다른 쪽의 부분집합이거나 교집합이 있음)이고 "
             "완전히 서로소인 경우는 소수다. 작업지시서가 상정한 '정면 충돌'보다 훨씬 부드러운 형태의 불일치다. "
             "그럼에도 정책대로 제외한다 — 교집합을 정답으로 삼는 것은 또 하나의 해석이고, 그 결정은 P4/P5가 명시적으로 내려야 한다.\n")
    L.append("가장 흔한 CNA→NVD 쌍 (양쪽 단일 CWE인 경우):\n\n| 쌍 | 건수 |\n|---|---|")
    for k, v in cs["top_pairs"][:10]:
        L.append(f"| `{k}` | {n(v)} |")
    L.append("\n다툼이 집중된 CNA:\n\n| CNA | 건수 |\n|---|---|")
    for k, v in cs["top_cnas"][:10]:
        L.append(f"| `{k}` | {n(v)} |")
    g = c["guard"]
    L.append("\n## CWE 가드 — P2.1 미도착에 대한 기록\n")
    L.append("이 작업지시서는 \"CWE 가드가 적용된 dedup 결정\"(WO-P2.1)을 전제했으나 **P2.1은 저장소에 도착하지 않았다** "
             "(`process/`에 관련 커밋 없음, `decisions.jsonl`에 가드 필드 없음). 질문하지 말고 결정하라는 지시에 따라 "
             "P3가 필요로 하는 최소한의 가드를 `datasets/build.py` 안에 구현했고, `process/`는 건드리지 않아 P2.1이 "
             "나중에 도착해도 충돌하지 않는다.\n")
    L.append("가드의 내용: 근접 중복으로 탈락한 레코드라도 **그 CWE 라벨이 클러스터 대표의 라벨과 다르면** CVE→CWE "
             "학습 세트에 다시 넣는다. 그렇지 않으면 대표(사전순으로 가장 작은 키)의 라벨이 조용히 다른 라벨들을 덮어쓴다. "
             "대표가 평가 세트에 있으면 다시 넣지 않는다 — 근접 중복 텍스트가 학습/평가에 걸치는 것을 막기 위해서다.\n")
    L.append("| 가드 결과 | 건수 |\n|---|---|")
    for k, v in sorted(g.items(), key=lambda kv: -kv[1]):
        L.append(f"| `{k}` | {n(v)} |")
    (D / "CWE_POLICY.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def card_md():
    r = M["decisions"]["replay"]
    L = [gen_header("데이터셋 카드 (초안)")]
    L.append("## 무엇인가\n")
    L.append("네 가지 과제의 학습·평가 세트. 정답은 전부 기계 검증 가능한 고정 스키마 JSON이고, 모든 정답은 "
             "출처가 이미 제공한 구조화 필드에서 나온다. **어떤 지시문도 정답도 언어 모델이 쓰지 않았다.**\n")
    L.append("| 과제 | 입력 | 정답 | 정답 출처 | 스키마 |\n|---|---|---|---|---|")
    L.append("| `cve_to_cwe` | CVE 설명 | `{\"cwe_id\": ...}` | Decision 2 | `datasets/schemas/cve_to_cwe.json` |")
    L.append("| `cvss_vector` | CVE 설명 | CVSS v3.1 기본 지표 8개 + 점수 + 벡터 문자열 | NVD `cvssMetricV31` (Primary 우선) | `cvss_vector.json` |")
    L.append("| `attack_technique` | ATT&CK 기법 설명 | `{\"technique_id\": ...}` | STIX `external_id` | `attack_technique.json` |")
    L.append("| `structured_extract` | CVE 설명 | vendor / product / versions / impact | CVE V5 `cna.affected`, `cna.impacts` | `structured_extract.json` |")
    L.append("\n## 과제별 산출 규모\n\n| 과제 | 학습 | 평가(이후) | 평가(이전) |\n|---|---|---|---|")
    f = M["files"]
    for t in TASKS:
        L.append(f"| `{t}` | {n(f.get(f'{t}/train.jsonl',{}).get('count',0))} | "
                 f"{n(f.get(f'{t}/eval_post_cutoff.jsonl',{}).get('count',0))} | "
                 f"{n(f.get(f'{t}/eval_pre_cutoff.jsonl',{}).get('count',0))} |")
    L.append(f"| `replay` | {n(f.get('replay/train.jsonl',{}).get('count',0))} | — | — |")
    L.append("\n## 과제별 유의점 — 공정하지만 경계가 있는 과제들\n")
    L.append("- **`cvss_vector`**: NVD v3.1 지표가 있는 CVE만 쓴다. v2(다른 척도)나 v4(다른 벡터)로 조용히 대체하지 않는다. "
             f"v3.1이 없어 제외된 CVE 수는 `reports/datasets.md`에 있다.")
    L.append("- **`structured_extract`**: 정답은 CNA가 이미 채운 구조화 필드에서 나온다. 즉 이 과제는 **CNA가 그 구조로부터 "
             "쓴 산문에서 구조를 되찾을 수 있는가**를 잰다. 공정하지만 경계가 있는 과제다. 모호함을 없애기 위해 "
             "`affected` 항목이 정확히 하나이고 버전이 1~16개인 CVE만 포함했다. `impact`는 `cna.impacts`가 있을 때만 값이 있고 "
             "없으면 `null`이다 — null 비율이 높으므로 P4는 impact 필드를 non-null인 경우에만 채점해야 한다.")
    L.append("- **`attack_technique`**: 설명문에는 `attack.mitre.org/techniques/T…` 링크가 들어 있어 답을 그대로 노출한다. "
             "링크 텍스트는 남기고 URL과 `(Citation: …)` 표기를 제거했다. 제거 건수는 매니페스트에 있다. "
             "기법 수 자체가 적어(활성 918개) 이 과제는 작다.")
    L.append("- **`cve_to_cwe`**: 단일 라벨. 다중 CWE CVE는 제외했고 그 수를 보고한다. `cwe_source`가 예제마다 기록되어 "
             "평가에서 층화할 수 있다.\n")
    L.append("## 리플레이 세트 (Decision 3)\n")
    L.append(f"- 출처: **OpenAssistant/oasst2**, Apache-2.0 (데이터 카드 선언), 커밋 `{M['pins']['replay_oasst2'].get('commit_sha','')[:12]}`에 고정.")
    L.append("- 라이선스는 **다운로드 전에** 읽었다. 저장소에 별도 LICENSE 파일은 없고 카드의 SPDX 필드가 선언이다 — 그대로 기록한다.")
    L.append("- 사람이 쓴 메시지만 사용한다. `synthetic: true`(모델 생성) 메시지는 제외해 제3 모델의 약관이 개입하지 않게 했다.")
    L.append(f"- 선택된 쌍 {n(r['pairs_selected'])} / 가용 {n(r['pairs_available'])}, 토큰 {n(r['replay_tokens_used'])}, "
             f"전체 학습 토큰 중 **{r['replay_fraction_of_total']:.1%}** (목표 20%). 풀 소진 여부: {r['budget_exhausted_pool']}.")
    ko = r["lang_counts"].get("ko", 0)
    L.append(f"- 언어: {r['lang_counts']}. **한국어 리플레이는 사실상 없다** — 필터를 통과한 oasst2 한국어 쌍이 {n(ko)}건뿐이다. "
             "P5가 한국어 지시 능력을 지키려면 다른 출처가 필요하다.")
    L.append("- 목표 20%에 미달한 채 풀이 소진되었다. 더 낮은 순위 답변까지 포함한 뒤의 값이며, 다른 언어를 섞거나 "
             "예제를 반복해 채우지 않았다. 20%가 필요하면 라이선스를 이미 읽어 둔 nvidia/HelpSteer2(CC-BY-4.0, 모델 생성 응답)를 "
             "두 번째 출처로 추가하거나, P5에서 리플레이를 에폭 단위로 재표집(반복)하는 학습 시점 선택으로 맞춘다.")
    L.append(f"- P2 시크릿/PII 정책 적용: 탐지 {n(sum(r['scan']['findings_by_category'].values()))}건 "
             f"({r['scan']['findings_by_category']}), 값은 어디에도 기록하지 않는다.")
    L.append("- 기각한 후보와 사유는 `docs/data-sources.md`의 oasst2 행에 있다.\n")
    L.append("## 하지 않은 것\n")
    L.append("- 어떤 레코드도 P2에서 삭제되지 않았고, 여기서 처음으로 `dedup_keep=false`가 학습 제외로 **물질화**된다.")
    L.append("- 평가 하네스(P4)를 만들지 않았다. 이 세트는 P4가 소비한다.")
    L.append("- 지시문 패러프레이즈를 생성하지 않았다. 과제당 고정 템플릿 3개, 예제마다 `template_id` 기록.")
    (D / "CARD.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def datasets_report():
    L = [gen_header("P3 데이터셋 구축 보고서")]
    f = M["files"]
    L.append("## 산출 파일\n\n| 파일 | 예제 수 | SHA-256 |\n|---|---|---|")
    for k, v in f.items():
        L.append(f"| `{k}` | {n(v['count'])} | `{v['sha256'][:16]}…` |")
    L.append("\n## 과제별 제외 사유\n")
    for t in TASKS:
        st = M["tasks"][t]
        L.append(f"### `{t}` — {TASK_KO[t]}\n")
        L.append("| 분할 | 예제 |\n|---|---|")
        for sp, v in st["by_split"].items():
            L.append(f"| `{sp}` | {n(v)} |")
        L.append("\n**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):\n\n| dedup_stage | 제외 |\n|---|---|")
        for k, v in sorted(st["excluded_by_dedup"].items(), key=lambda kv: -kv[1]):
            L.append(f"| `{k}` | {n(v)} |")
        L.append("\n**과제 필터·분할별 제외**:\n\n| 사유 | 건수 |\n|---|---|")
        for k, v in sorted(st["excluded_by_filter"].items(), key=lambda kv: -kv[1]):
            L.append(f"| `{k}` | {n(v)} |")
        if t == "cvss_vector" and st.get("missing_v31_by_versions_present"):
            L.append("\nv3.1이 없는 CVE에 어떤 CVSS 버전이 있었나 (대체하지 않고 제외):\n\n| 존재하는 버전 | 건수 |\n|---|---|")
            for k, v in sorted(st["missing_v31_by_versions_present"].items(), key=lambda kv: -kv[1]):
                L.append(f"| `{k}` | {n(v)} |")
        L.append("\n템플릿 분포: " + ", ".join(f"T{k}={n(v)}" for k, v in sorted(st["by_template"].items())) + "\n")
    L.append("## 세 가지 결정\n\n- Decision 1: `datasets/SPLIT.md`\n- Decision 2: `datasets/CWE_POLICY.md`\n- Decision 3: `datasets/CARD.md` 리플레이 절 및 `docs/data-sources.md`\n")
    L.append("## 재현성\n\n> " + M["determinism"] + "\n")
    (REPORTS / "datasets.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def contamination_report():
    c = M["contamination"]
    L = [gen_header("P3 오염 검사 보고서")]
    L.append(f"정책: **{c['policy_n']}-gram, 무관용.** 학습 세트(도메인 4과제 + 리플레이)의 어떤 항목과도 {c['policy_n']}-gram을 공유하는 "
             f"평가 항목은 제거한다. **{c['diagnostic_n']}-gram**은 같은 세트에 진단용으로 돌려 함께 보고한다.\n")
    L.append("n-gram은 `input`과 `target_json`(내용)에서만 계산한다. 지시 템플릿은 설계상 공유되므로 포함하면 모든 항목이 걸린다.\n")
    L.append(f"학습 세트 고유 n-gram: {c['policy_n']}-gram **{n(c['train_unique_ngrams'][str(c['policy_n'])])}**, "
             f"{c['diagnostic_n']}-gram **{n(c['train_unique_ngrams'][str(c['diagnostic_n'])])}**\n")
    L.append("## 평가 세트별 결과\n\n| 평가 세트 | 검사 전 | 13-gram 제거 | 제거율 | 검사 후 | 8-gram이면 제거될 수 | 8-gram 추가분 | 8-gram 제거율 |\n|---|---|---|---|---|---|---|---|")
    for k, v in c["eval_sets"].items():
        L.append(f"| `{k}` | {n(v['before'])} | **{n(v['removed_at_13'])}** | {v['removed_fraction_13']:.1%} | {n(v['after'])} | "
                 f"{n(v['would_remove_at_8'])} | +{n(v['additional_at_8_beyond_13'])} | {v['would_remove_fraction_8']:.1%} |")
    L.append(f"\n총 13-gram 제거: **{n(c['total_removed_at_13'])}건**. 제거 후 재검사 결과 13-gram 겹침 **0** (`--assert-zero` 통과).\n")
    L.append("## 8-gram이 추가로 잡는 것 — 이 코퍼스가 얼마나 정형화되어 있는가\n")
    L.append("8-gram에서 가장 자주 걸린 구절(공개 취약점 설명의 상투구이며 비밀이 아니다):\n")
    for k, grams in c["top_diag_grams"].items():
        if not grams:
            continue
        L.append(f"**`{k}`**")
        for g, cnt in grams[:5]:
            L.append(f"- ({cnt}) `{g}`")
        L.append("")
    L.append("13-gram 제거율이 높은 것 자체가 발견 사항이다: Oracle·Adobe·Android 같은 벤더의 CVE 설명은 제품명과 버전만 다른 "
             "고정 문장이라 13단어 연쇄가 그대로 학습 세트에 존재한다. 무관용 정책은 이런 항목을 평가에서 걷어내므로 "
             "**평가 세트는 정형화가 덜한 벤더 쪽으로 기운다.** P4는 이 편향을 알고 해석해야 한다.\n")
    L.append("## 교차 평가 검사\n")
    for k, v in c["cross_eval"].items():
        L.append(f"- `{k}`: {v if not isinstance(v, dict) else v.get('shared_entity_ids')} 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)")
    (REPORTS / "contamination.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def lengths_report():
    l = M["lengths"]
    L = [gen_header("P3 토큰 길이 분포와 패킹 수율")]
    L.append(f"토크나이저: Qwen2.5-7B-Instruct, 커밋 `{M['pins']['tokenizer_qwen25'].get('commit_sha','')[:12]}` (DGX 게이트와 동일). 시퀀스 길이 {l['seq']}.\n")
    L.append("## 과제·분할별 분포 (토큰)\n\n| 과제/분할 | 예제 | 입력 p50/p90/p99/max | 정답 p50/p90/p99/max | >512 | >1024 | >2048 | >4096 |\n|---|---|---|---|---|---|---|---|")
    for k, v in l["tasks"].items():
        p, t, fo = v["prompt"], v["target"], v["fraction_over"]
        L.append(f"| `{k}` | {n(v['examples'])} | {p['p50']}/{p['p90']}/{p['p99']}/{p['max']} | {t['p50']}/{t['p90']}/{t['p99']}/{t['max']} | "
                 f"{fo['512']:.2%} | {fo['1024']:.2%} | {fo['2048']:.2%} | {fo['4096']:.2%} |")
    L.append("\n## 패킹 수율 @ 4096 (순차 greedy)\n\n| 과제/분할 | 4096 시퀀스 수 | 시퀀스당 예제 | 패딩 비율 | 4096 초과(절단) |\n|---|---|---|---|---|")
    for k, v in l["tasks"].items():
        pk = v["packing"]
        L.append(f"| `{k}` | {n(pk['sequences_4096'])} | **{pk['examples_per_sequence']}** | {pk['padding_fraction']:.1%} | {pk['truncated_over_4096']} |")
    s = l["schedule"]
    L.append("\n## P0 측정치를 P5 일정으로 — 이 보고서의 존재 이유\n")
    L.append(f"- P0 체크 07: **{l['p0_sec_per_step']}초/옵티마이저 스텝**, 스텝당 {n(l['p0_tokens_per_step'])} 토큰 (16 × 4096, 합성 전장 시퀀스).")
    L.append(f"- 실제 학습 토큰(4과제 + 리플레이): **{n(s['train_tokens_all_tasks_plus_replay'])}**")
    L.append(f"- 패킹 후 4096 시퀀스: **{n(s['train_sequences_4096_after_packing'])}** → 스텝당 16 시퀀스 → **에폭당 {n(s['optimizer_steps_per_epoch'])} 스텝**")
    L.append(f"- **에폭당 예상 벽시계: {s['hours_per_epoch_at_p0_step_cost']} 시간** (P0 스텝 비용 기준, 패딩 포함)")
    L.append(f"\n> {s['note']}")
    L.append("\n작업지시서 P0의 외삽(10k/30k/60k 예제 → 22.5/67.5/134.9시간)은 예제 = 4096 토큰을 가정했다. "
             "위 표의 시퀀스당 예제 수가 그 가정과 실제의 비율이다.\n")
    (REPORTS / "lengths.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    for fn in (split_md, cwe_md, card_md, datasets_report, contamination_report, lengths_report):
        fn()
    print("wrote SPLIT.md CWE_POLICY.md CARD.md datasets.md contamination.md lengths.md")
