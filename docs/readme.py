# -*- coding: utf-8 -*-
"""README.md -- the front door.

A reviewer reads this for about ninety seconds before deciding whether to read
anything else. So the claim comes first, the boundary comes second, and every
number below them is generated rather than typed.

The base-model section exists because `Qwen2.5-7B-Instruct` reads as a dated
default unless the reasoning is stated. It is a constraint the experiment
requires, not an oversight, and the two vLLM issues that make the alternatives
unavailable are cited by number.
"""

from __future__ import annotations

from docs import seed2 as seed2_doc
from docs.common import Fmt, cell, gen_note

THESIS_EN = (
    "This pipeline does not measure security capability. It measures a narrow set of "
    "abilities — weakness classification, severity vector inference, structured extraction "
    "— under controlled contamination and verified determinism, and it reports what it "
    "cannot measure as carefully as what it can."
)
BOUNDARY_EN = (
    "The design rule, applied at three layers: what a machine can judge is judged by a "
    "machine, and what it cannot is not dressed up as if it were. Licenses separate "
    "\"may redistribute\" from \"may publish weights\". Rewards are exact-match and schema "
    "parsing. Scoring is mechanical end to end, with no language model in the loop."
)


def render(F: Fmt) -> str:
    L = ["# sec-llm", ""]
    L.append("> " + THESIS_EN)
    L.append("")
    L.append("이 파이프라인은 **보안 능력을 측정하지 않는다.** 좁은 능력 몇 가지를 측정한다 — "
             "약점 분류, 심각도 벡터 추론, 구조화 추출. 오염을 통제한 상태에서, 결정론이 검증된 "
             "조건으로 측정하고, **측정할 수 없는 것을 측정한 것만큼 꼼꼼히 적는다.**")
    L.append("")
    L.append("> " + BOUNDARY_EN)
    L.append("")
    L.append("설계 규칙은 하나이고 세 층에 걸쳐 적용된다: **기계가 판단할 수 있는 것은 기계가 판단하고, "
             "할 수 없는 것은 할 수 있는 척하지 않는다.** 라이선스는 \"재배포해도 되는가\"와 "
             "\"가중치를 공개해도 되는가\"를 분리한다. 보상은 완전 일치와 스키마 파싱이다. "
             "채점은 처음부터 끝까지 기계적이며, 언어모델은 채점 고리 안에 들어오지 않는다.")
    L.append("")
    L.append("---")
    L.append("")

    # ---------------------------------------------------------- 무엇이 있는가
    L.append("## 무엇이 있는가")
    L.append("")
    L.append(f"- **네 개 공개 보안 출처**, 정규화 이전 원시 레코드 "
             f"**{F.n('process', 'summary', 'records_in')}건.** 전부 불변 참조로 고정되고, "
             f"모든 레코드가 {F.count('cve_list', 'lineage_fields')}개 계통 필드를 달고 다닌다. "
             "같은 핀으로 다시 수집하면 매니페스트가 바이트 단위로 재현되며, 네트워크를 막고도 재현된다.")
    L.append(f"- **네 개 과제**, 그중 채점되는 것은 세 개. 컷오프 "
             f"`{F.s('datasets', 'decisions', 'temporal_split', 'cutoff')}` 기준 시간 분할이며, "
             "학습은 컷오프 이전만, 평가는 이후와 이전 양쪽을 쓴다.")
    L.append(f"- **평가 하니스**, 출력이 바이트 단위로 재현된다. 전체 평가를 두 번 완주해 "
             f"출력 차이 {F.plain('gate4', 'outputs', 'n_differing')}건"
             f"(sha256 `{F.get('gate4', 'outputs', 'sha256')[:16]}…`)을 확인했다. "
             "채점에 언어모델을 쓰지 않는다.")
    L.append(f"- **두 학습 조건**, 동일 토큰 예산. Cond-1 "
             f"{F.n('datasets', 'decisions', 'conditions', 'cond1', 'total_tokens')}토큰(도메인만), "
             f"Cond-2 {F.n('datasets', 'decisions', 'conditions', 'cond2', 'total_tokens')}토큰"
             f"(도메인 + 리플레이 {F.pct('datasets', 'decisions', 'conditions', 'cond2', 'replay_fraction_achieved', nd=0)}). "
             f"차이는 {F.n('datasets', 'decisions', 'conditions', 'budget_residue_tokens')}토큰이고 "
             "Cond-2의 도메인 집합은 Cond-1의 진부분집합임이 해시로 증명된다.")
    L.append("")

    # ---------------------------------------------------------- 핵심 결과
    L.append("## 핵심 결과")
    L.append("")
    k = cell("cve_to_cwe", "eval_post_cutoff", "constrained")
    acc = ("compare", "domain", k, "pairs", "cond1 vs baseline", "accuracy")
    L.append(f"**도메인은 올라간다.** `cve_to_cwe`(컷오프 이후, 제약 디코딩)에서 베이스 "
             f"{F.pct('compare', 'domain', k, 'rates', 'baseline', 'rate', nd=1)} → Cond-1 "
             f"{F.pct('compare', 'domain', k, 'rates', 'cond1', 'rate', nd=1)}, "
             f"쌍 차이 {F.pp(*acc, 'paired_difference', 'diff', nd=1)} "
             f"{F.ci(*acc, 'paired_difference', 'ci95', nd=1, scale=100, unit='pp')}, "
             f"McNemar Holm p={F.p(*acc, 'mcnemar_p_holm')} "
             f"(패밀리 {F.plain(*acc, 'family_size')}).")
    L.append("")
    hs = ("compare", "general", "hellaswag", "pairs", "cond1 vs cond2")
    mm = ("compare", "general", "mmlu", "pairs", "cond2 vs baseline")
    L.append(f"**일반 능력은 두 벤치마크가 다른 답을 준다.** `hellaswag`에서 리플레이는 작동했다 — "
             f"Cond-2가 Cond-1보다 {F.abspp(*hs, 'paired_difference', 'diff', nd=1)} 앞서고 "
             f"Holm p={F.p(*hs, 'mcnemar_p_holm')}로 살아남으며, 베이스와는 구별되지 않는다. "
             f"`mmlu`에서는 작동하지 않았다 — Cond-2가 베이스보다 "
             f"{F.abspp(*mm, 'paired_difference', 'diff', nd=1)} 낮고 "
             f"Holm p={F.p(*mm, 'mcnemar_p_holm')}로 검출된다. "
             "**하나를 고르지 않는다.** 쓸 수 있는 결론은 리플레이의 효과가 무엇을 일반 능력으로 "
             f"정의하느냐에 달렸다는 것뿐이다. {seed2_doc.readme_clause(F)}")
    L.append("")
    L.append(f"**암기는 검출되지 않았다 — 결론이 아니라 상한이다.** 각 조건이 실제로 학습한 텍스트에 대해 "
             f"다시 계산한 탐침 {F.n('probe', 'conditions', 'cond1', 'n_with_matched_control')}쌍과 "
             f"{F.n('probe', 'conditions', 'cond2', 'n_with_matched_control')}쌍에서, "
             "바닥선 대비 초과분은 검출 가능 최소차 안에 있다.")
    L.append("")
    if seed2_doc.have(F):
        conflicts = seed2_doc._domain_conflicts(F)
        if conflicts:
            L.append("")
            L.append("**도메인 쪽은 그만큼 버티지 못했다.** " + ", ".join(conflicts) +
                     "에서 두 시드가 **서로 반대 조건을 각각 검출했다.** 동일 예산에서 도메인 과제의 "
                     "조건 간 우열은 시드에 종속된다 — 시드 하나로 주장할 수 없는 종류의 결과이고, "
                     "두 번째 시드를 돌리지 않았다면 반대 결론을 자신 있게 적었을 것이다. "
                     + seed2_doc.base_clause(F))
            L.append("")
            L.append(seed2_doc.readme_variance(F))
    L.append("")
    L.append("표 전체와 판정 규칙은 `docs/MODEL_CARD.md`에 있다.")
    L.append("")

    # ---------------------------------------------------------- 아닌 것
    L.append("## 이것이 아닌 것")
    L.append("")
    L.append("- **익스플로잇 생성이 아니다.** 공격 코드는 학습 데이터에도 평가에도 없다.")
    L.append("- **침해사고 대응이 아니다.** 로그도 탐지 룰도 다루지 않는다.")
    L.append("- **코드 분석이 아니다.** 이 파이프라인은 소스 코드가 아니라 CVE **설명문**을 다룬다.")
    L.append("- **추론 벤치마크가 아니다.** 추론 능력을 재는 평가가 없다.")
    L.append(f"- **`attack_technique`는 채점하지 않는다.** 평가 항목이 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_post_cutoff')}건과 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_pre_cutoff')}건뿐이라 "
             "조건 간 비교를 지탱하지 못한다. 데이터셋에는 남기고 서술적으로만 보고한다.")
    L.append("")

    # ---------------------------------------------------------- 재현
    L.append("## 재현")
    L.append("")
    L.append("```bash")
    L.append("make env-check     # 게이트 0: 환경과 결정론")
    L.append("make pin ingest    # 출처 고정과 수집")
    L.append("make process       # 정규화 · 중복 제거 · 동일성 · 비밀 스캔")
    L.append("make datasets      # 과제 · 분할 · 리플레이 · 오염")
    L.append("make docs          # 여섯 개 문서와 SBOM 재생성")
    L.append("make all           # 위 전체 (GPU 필요 구간 제외)")
    L.append("```")
    L.append("")
    L.append(f"**원본 코퍼스는 재배포하지 않는다.** 핀과 해시와 매니페스트만 배포하고 다운로더가 "
             f"그것으로 다시 만든다. 빈 디스크에서 네 출처를 처음 받는 데 실측 "
             f"{F.calc('hours', [('costs', 'sources', 'cve_list', 'elapsed_seconds_network'), ('costs', 'sources', 'nvd', 'elapsed_seconds_network'), ('costs', 'sources', 'attack', 'elapsed_seconds_network'), ('costs', 'sources', 'cwe', 'elapsed_seconds_network')], nd=1)}시간이 "
             "걸렸고, 대부분은 NVD API의 공개 속도 제한이다. 단계별 비용과 GPU가 필요한 구간은 "
             "`docs/REPRODUCE.md`에 있다.")
    L.append("")

    # ---------------------------------------------------------- 베이스 모델
    L.append("## 베이스 모델 선택의 근거")
    L.append("")
    L.append(f"베이스 모델은 `{F.s('refs', 'model', 'repo')}`다. 최신 모델이 아니며, **그것이 요구사항이다.** "
             "세 가지 이유가 있고, 셋 다 이 실험이 하려는 측정에서 직접 따라 나온다.")
    L.append("")
    L.append(f"**컷오프 여유가 요구사항이다.** 평가 세트는 "
             f"`{F.s('datasets', 'decisions', 'temporal_split', 'cutoff')}` 이후에 공개된 CVE다. "
             "그 이후까지 학습된 베이스 모델은 평가 항목을 이미 본 상태다. "
             "오염을 통제한 벤치마크에서 컷오프 여유는 선택지가 아니라 전제이고, "
             "**최신 모델일수록 그 여유가 적다.** 이 방향의 요구는 \"최신을 쓰라\"와 정면으로 충돌한다.")
    L.append("")
    L.append(f"**결정론이 요구사항이다.** Gate {F.plain('refs', 'gates', 'evaluation_determinism')}의 바이트 단위 재현성은 `VLLM_BATCH_INVARIANT=1`에 "
             "의존한다. vLLM은 Gated DeltaNet 계열 어텐션(Qwen3.5 / Qwen3.6)에서 이 플래그를 "
             f"거부하며([vllm#{F.plain('refs', 'vllm_issues', 'gdn_batch_invariant', 'number')}]"
             f"({F.get('refs', 'vllm_issues', 'gdn_batch_invariant', 'url')})), "
             "fused MoE 커널에서도 마찬가지다"
             f"([vllm#{F.plain('refs', 'vllm_issues', 'fused_moe_batch_invariant', 'number')}]"
             f"({F.get('refs', 'vllm_issues', 'fused_moe_batch_invariant', 'url')})). "
             "그 모델들에서는 **재현성 보장 자체를 제공할 수 없다.** 결정론을 포기하고 최신 모델을 "
             "쓸 수도 있었지만, 그러면 이 저장소가 내세우는 주장 하나가 사라진다.")
    L.append("")
    L.append("**대가는 분명하다.** 절대 점수는 최신 모델보다 낮을 것이다. 이 저장소는 절대 점수를 "
             "주장하지 않는다 — 동일 조건에서의 **조건 간 차이**를 주장한다. 그 차이는 "
             "베이스 모델을 바꿔도 다시 측정하면 된다.")
    L.append("")
    L.append("**파이프라인은 베이스 모델에 의존하지 않는다.** 모든 입력이 해시로 고정되어 있어 "
             f"모델 교체는 재작성이 아니라 **문서화된 재실행**이다 — Gate {F.plain('refs', 'gates', 'environment_and_determinism')}과 "
             f"Gate {F.plain('refs', 'gates', 'evaluation_determinism')}를 다시 돌리고, "
             "학습과 평가를 다시 하면 된다. 후보 모델 비교는 "
             f"`{F.s('refs', 'candidates_doc')}`에 표로 있다.")
    L.append("")

    # ---------------------------------------------------------- 문서
    L.append("## 문서")
    L.append("")
    L.append("| 문서 | 내용 |")
    L.append("|---|---|")
    L.append("| [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md) | 모델 카드 — 의도된 사용, 범위 밖 사용, 평가 전체, 한계 |")
    L.append("| [`docs/DATASET.md`](docs/DATASET.md) | 데이터셋 명세 — 출처별 핀·정제·중복 제거, 과제별 구성, 결정과 개수, 수정 이력 |")
    L.append("| [`docs/LICENSES.md`](docs/LICENSES.md) | 라이선스 정합성 — 권한 매트릭스와 근거 문장 |")
    L.append("| [`docs/SBOM.md`](docs/SBOM.md) · [`sbom.spdx.json`](sbom.spdx.json) | 의존성 목록과 데이터·의존성 라이선스 교차 확인 |")
    L.append("| [`docs/REPRODUCE.md`](docs/REPRODUCE.md) | 빈 체크아웃에서의 재현 절차와 비용 |")
    L.append("| [`docs/engineering-rules.md`](docs/engineering-rules.md) | 결함에서 나온 규칙들 |")
    L.append("| [`docs/model-candidates.md`](docs/model-candidates.md) | 베이스 모델 후보 비교 |")
    L.append("| [`docs/determinism.md`](docs/determinism.md) · [`docs/hardware-notes.md`](docs/hardware-notes.md) | 결정론 측정과 하드웨어 기록 |")
    L.append("")
    L.append("`reports/` 아래에는 각 단계의 한국어 보고서가 있다. 모두 매니페스트에서 생성된다.")
    L.append("")
    L.append("---")
    L.append("")
    L.append(gen_note())
    return "\n".join(L) + "\n"
