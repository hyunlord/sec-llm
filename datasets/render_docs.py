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
    L.append("\n### P2.1과의 조정(P3.1 Change 5) — 현재 상태: **보류**\n")
    L.append(f"- 가드 출처: `{M.get('cwe_guard_provenance','')}`")
    L.append("- P3.1 시점에도 P2.1 문서와 커밋은 존재하지 않는다 (저장소·작업 디렉터리·임시 경로 전역 검색 결과 없음). "
             "따라서 위 임시 가드가 그대로 남아 있고, 근접 중복 임계값도 P2의 0.75를 쓴다.")
    L.append("- P2.1이 도착하면: `build.py`가 `decisions.jsonl`의 가드 필드를 직접 소비하고 임시 가드를 제거하며, "
             "임시 가드와 P2.1 가드 사이에 **상태가 바뀌는 레코드 수**를 이 절에 기록한다. 두 가드가 크게 다르면 그것은 "
             "덮을 것이 아니라 기록할 발견이다.")
    L.append("- 비교 기준선(임시 가드): " + ", ".join(f"`{k}`={n(v)}" for k, v in sorted(g.items())))
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
    L.append("\n## 과제별 산출 규모와 채점 여부\n\n| 과제 | 채점 | 학습 | Cond-1 서브샘플(60k) | 평가(이후) | 평가(이전) |\n|---|---|---|---|---|---|")
    f = M["files"]
    sc = M.get("scored", {})
    for t in TASKS:
        L.append(f"| `{t}` | {'**예**' if sc.get(t, True) else '**아니오** (`scored: false`)'} | "
                 f"{n(f.get(f'{t}/train.jsonl',{}).get('count',0))} | "
                 f"{n(f.get(f'{t}/train_subsample.jsonl',{}).get('count',0)) if f'{t}/train_subsample.jsonl' in f else '—'} | "
                 f"{n(f.get(f'{t}/eval_post_cutoff.jsonl',{}).get('count',0))} | "
                 f"{n(f.get(f'{t}/eval_pre_cutoff.jsonl',{}).get('count',0))} |")
    L.append(f"| `replay` | — | {n(f.get('replay/train.jsonl',{}).get('count',0))} | "
             f"{n(f.get('replay/train_cond2.jsonl',{}).get('count',0))} (Cond-2) | — | — |")
    nsr = M.get("not_scored_reason", {})
    if nsr:
        L.append("\n### `scored: false` — 채점하지 않는 과제\n")
        for t, why in nsr.items():
            L.append(f"- **`{t}`**: {why}")
        L.append("")
    L.append("### 라벨 출처가 시간에 따라 달라진다\n")
    cs = M["decisions"]["cwe_ground_truth"]["cwe_source_by_split"]
    L.append("| 분할 | agreed | nvd | cna |\n|---|---|---|---|")
    for sp, c in cs.items():
        L.append(f"| `{sp}` | {n(c.get('agreed',0))} | {n(c.get('nvd',0))} | {n(c.get('cna',0))} |")
    L.append("\n컷오프 이후 평가는 `agreed`가 우세하고 학습은 `nvd`가 우세하다 — 최근 CVE는 CNA가 CWE를 달고, 오래된 CVE는 "
             "NVD 분석가만 달았기 때문이다. 같은 과제 안에서 라벨의 **출처 구성이 분할마다 다르므로** P4는 `cwe_source`로 층화해 보고해야 한다.")
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
    # The leakage finding, rendered from the recorded contamination block.
    c = M["contamination"]
    j = c["removed_near_jaccard"]
    L.append("## 오염 검사에서 실제로 찾은 것\n")
    L.append(f"적용한 기준은 **근접 중복 하나**다. 그것이 잡아낸 항목은 **{n(c['total_removed'])}건**이고, "
             f"최근접 학습 입력과의 Jaccard가 최소 **{j['min']}**, 중앙값 **{j['q50']}**, **최대 {j['max']}**다. "
             "최대 1.0은 **CVE ID만 다르고 사실상 동일한 입력이 시간 경계를 넘어 존재한다**는 뜻이다 — 이것이 진짜 누수이고 제거했다.")
    L.append(f"여섯 개 CVE 평가 세트에 고르게 퍼져 있다 (세트별 {min(v for k,v in c['removed_per_eval_set'].items())}–"
             f"{max(c['removed_per_eval_set'].values())}건): 한 벤더의 특이현상이 아니다.\n")
    L.append("**커버리지(13-gram)는 필터가 아니라 측정값이다.** P3.1은 커버리지 0.5 초과 항목 2,483건을 지웠지만 "
             "그 임계값에는 근거가 없었고, 기록된 CNA 분포는 그 삭제가 편향을 **줄이지 않고 바꿨다**는 것을 보여줬다. "
             "지금 모든 평가 항목은 `train_ngram_coverage`와 그 사분위를 필드로 들고 다니며, P4는 모든 점수를 "
             "전체 및 커버리지 사분위별로 보고한다. 커버리지 0 그룹은 별도로 본다 (세트별 41–91%). "
             "자세한 내용은 `reports/contamination.md`, 근거는 `docs/engineering-rules.md` 규칙 5.\n")
    L.append("## 절제 실험의 균형 — 계산량을 고정한 대가\n")
    co = M["decisions"]["conditions"]
    L.append(f"총 토큰 예산 T = {n(co['budget_T_tokens'])}를 **두 조건에 동일하게** 고정했다. "
             f"Cond-1은 T 전부를 도메인에 쓰고, Cond-2는 0.8T 도메인 + 0.2T 리플레이를 쓴다. "
             f"Cond-2의 도메인은 Cond-1의 부분집합({n(co['cond2']['domain_examples'])} / {n(co['cond1']['examples'])} 예제)이다.")
    L.append("**그래서 Cond-2는 도메인 데이터를 Cond-1보다 20% 적게 본다.** 도메인 정확도에서 Cond-1이 앞서는 것은 "
             "**예상된 결과이고 리플레이에 불리한 증거가 아니다.** 의미 있는 비교는 **같은 계산량에서의 범용 능력 격차**다. "
             "P3.1 설계(Cond-2 = Cond-1 + 리플레이)에서는 Cond-2가 토큰과 스텝을 25% 더 썼으므로 "
             "범용 능력 우위를 리플레이 효과와 학습량 효과로 분리할 수 없었다 — 교란된 설계였다.\n")
    L.append("## 리플레이 세트 (Decision 3)\n")
    L.append(f"- 출처: **OpenAssistant/oasst2**, Apache-2.0 (데이터 카드 선언), 커밋 `{M['pins']['replay_oasst2'].get('commit_sha','')[:12]}`에 고정.")
    L.append("- 라이선스는 **다운로드 전에** 읽었다. 저장소에 별도 LICENSE 파일은 없고 카드의 SPDX 필드가 선언이다 — 그대로 기록한다.")
    L.append("- 사람이 쓴 메시지만 사용한다. `synthetic: true`(모델 생성) 메시지는 제외해 제3 모델의 약관이 개입하지 않게 했다.")
    fs, ss = r["full_set"], r["subsample"]
    L.append(f"- **Cond-2가 실제로 쓰는 리플레이**: 선택 {n(ss['pairs_selected'])}쌍, 토큰 {n(ss['replay_tokens_used'])}, "
             f"Cond-2 전체 토큰 중 **{ss['replay_fraction_of_total']:.1%}** — 목표 20% **도달**. "
             f"예산 산정: {ss['replay_token_budget_source']} (= T − 도메인 토큰). 풀 소진: {ss['budget_exhausted_pool']}.")
    L.append(f"- **전체 세트(선택적 후속 실행)**: 선택 {n(fs['pairs_selected'])} / 가용 {n(fs['pairs_available'])}쌍, 토큰 {n(fs['replay_tokens_used'])}, "
             f"**{fs['replay_fraction_of_total']:.1%}** — 목표 20% **미달**, 풀 소진: {fs['budget_exhausted_pool']}. 미달 상태로 기록한다.")
    L.append(f"- HelpSteer2 (CC-BY-4.0) 보충 검토 결과: **사용하지 않음.** {r.get('helpsteer2','')} 라이선스는 적합하지만 "
             "카드 스스로 응답이 사내 LLM 생성이라고 밝히므로 '사람이 쓴 턴만' 제약에 걸린다. 다른 언어를 섞거나 예제를 반복해 채우지 않았다.")
    ko = r["lang_counts"].get("ko", 0)
    L.append(f"- 언어: {r['lang_counts']}. **한국어 리플레이는 사실상 없다** — 필터를 통과한 oasst2 한국어 쌍이 {n(ko)}건뿐이다. "
             "P5가 한국어 지시 능력을 지키려면 다른 출처가 필요하다.")
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
    # Rendered from the manifest's recorded removal by the module that owns the
    # criteria. Nothing is recomputed here (docs/engineering-rules.md rule 1).
    from datasets import contamination
    contamination.render(M)


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
    ss = l.get("equal_budget_schedule")
    if ss:
        L.append("\n## 사전 등록된 P5 절제 실험 — **동일 토큰 예산** 일정\n")
        sub = M["decisions"]["subsample"]
        co = M["decisions"]["conditions"]
        L.append(f"- 표집: {n(sub['n'])}개 도메인 예제, 채점 과제 3개에 비례 층화 (`{sub['quota']}`), 시드 `{sub['seed']}`.")
        L.append(f"- **총 토큰 예산 T = {n(ss['token_budget_T'])}** (= 현재 Cond-1 예산).")
        L.append(f"- Cond-1: T 전부 도메인 ({n(ss['cond1_examples'])} 예제). "
                 f"Cond-2: **0.8T 도메인 + 0.2T 리플레이** (도메인 {n(ss['cond2_domain_examples'])} 예제 + 리플레이 {n(ss['cond2_replay_examples'])}쌍).")
        L.append(f"- Cond-2의 도메인 예제는 **같은 시드·같은 순서로 Cond-1에서 뽑은 부분집합**이다 "
                 f"(Cond-1의 {ss['cond2_domain_share_of_cond1_examples']:.1%}). "
                 f"부분집합 증명: `{co['subset_proof']['cond2_domain_ids_sha256'][:16]}…` = Cond-1 ∩ Cond-2 해시. "
                 "`python -m datasets.build --verify-subset`으로 재검증한다.\n")
        L.append("| 조건 | 예제 | 토큰 | 4096 시퀀스 | 시퀀스당 예제 | 패딩 | **에폭당 스텝** | 남는 시퀀스 | **에폭당 시간** |\n|---|---|---|---|---|---|---|---|---|")
        for k in ("cond1", "cond2"):
            c = ss[k]
            L.append(f"| {c['label']} | {n(c['examples'])} | {n(c['tokens'])} | {n(c['sequences_4096'])} | {c['examples_per_sequence']} | "
                     f"{c['padding_fraction']:.1%} | **{c['optimizer_steps_per_epoch']}** | {c['sequences_left_over']} | **{c['hours_per_epoch_at_p0_step_cost']} h** |")
        L.append(f"\n- **두 조건의 옵티마이저 스텝 수가 같다: {ss['shared_optimizer_steps_per_epoch']}스텝** "
                 f"(일치 확인: `steps_match = {ss['steps_match']}`, `datasets/lengths.py`에서 assert). "
                 "토큰이 같아도 패딩이 달라 패킹된 시퀀스 수는 약간 다르므로, 스텝 수를 두 조건에 대해 하나로 고정하고 "
                 "남는 시퀀스를 그대로 보고한다.")
        L.append(f"- Cond-2 총 토큰 {n(ss['cond2_total_tokens'])} = T − {n(ss['token_gap_vs_T'])} "
                 f"({ss['token_gap_fraction']:.4%}) — 예제를 쪼개지 않고 예산에 맞추다 남은 잔차다.")
        L.append(f"- Cond-2에서 리플레이가 차지하는 토큰 비율: **{ss['replay_fraction_of_cond2_tokens']:.1%}**")
        L.append(f"- 두 조건 합계(1 에폭씩): **{ss['cond1']['hours_per_epoch_at_p0_step_cost'] + ss['cond2']['hours_per_epoch_at_p0_step_cost']:.1f} h** "
                 f"— 전체 세트 두 조건 {2*l['schedule']['hours_per_epoch_at_p0_step_cost']:.1f} h 대비.")
        L.append("- P3.1에서는 Cond-2 = Cond-1 + 리플레이였다: 토큰 25% 많고 스텝 25% 많았다(5.67h vs 7.11h). "
                 "그 설계에서는 Cond-2가 범용 능력에서 이겨도 **리플레이 덕인지 더 오래 학습한 덕인지 구분할 수 없다.** "
                 "지금은 계산량이 같다.\n")
    s = l["schedule"]
    L.append("\n## 전체 세트 일정 (절제 실험 후 선택적 실행)\n")
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
