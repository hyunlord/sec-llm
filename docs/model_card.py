# -*- coding: utf-8 -*-
"""docs/MODEL_CARD.md -- the model card.

Every rate here carries its interval and its n. Every comparison carries the
paired test, the Holm-adjusted p, and the family the adjustment was made in.
Nothing is a marginal-interval-overlap verdict; that defect is recorded in
`docs/engineering-rules.md` rule 6 and its uncorrected numbers are kept beside
the corrected ones in `runs/compare_p5_uncorrected.json`.

The one thing this file refuses to print is a minimum detectable difference
computed at a rate near zero. The normal approximation collapses there and the
formula returns figures like 0.000004 percentage points. Publishing that would
undo the credibility the rest of the document is built on, so the cell says so
instead. `docs.common._r_mdd` holds the rule.
"""

from __future__ import annotations

from docs import seed2 as seed2_doc
from docs.common import DEC_KO, SPLIT_KO, TASK_KO, Fmt, at_boundary, cell, gen_note

SCORED = ("cve_to_cwe", "cvss_vector", "structured_extract")
SPLITS = ("eval_post_cutoff", "eval_pre_cutoff")
PAIRS = ("cond1 vs baseline", "cond2 vs baseline", "cond1 vs cond2")
PAIR_KO = {"cond1 vs baseline": "Cond-1 vs Cond-0", "cond2 vs baseline": "Cond-2 vs Cond-0",
           "cond1 vs cond2": "Cond-1 vs Cond-2"}
COND_SHORT = {"baseline": "Cond-0", "cond1": "Cond-1", "cond2": "Cond-2"}
VERDICT_KO = {"difference detected": "**차이 검출됨**", "no difference detected": "차이 검출되지 않음"}

MDD_FOOTNOTE = "mdd-boundary"


def _rate(F: Fmt, *base) -> str:
    return (f"{F.pct(*base, 'rate', nd=1)} {F.ci_abs(*base, 'ci95', nd=1, scale=100, unit='%')} "
            f"(n={F.n(*base, 'n')})")


def _verdict(F: Fmt, *base) -> str:
    v = F.get(*base, "verdict")
    if v not in VERDICT_KO:
        raise KeyError(f"unmapped verdict {v!r}")
    return VERDICT_KO[v]


def _pairrow(F: Fmt, label: str, *base) -> str:
    """One comparison: difference, paired interval, both p's, family, verdict."""
    pd = base + ("paired_difference",)
    return (f"| {label} "
            f"| {F.pp(*pd, 'diff', nd=1)} "
            f"| {F.ci(*pd, 'ci95', nd=1, scale=100, unit='pp')} "
            f"| {F.p(*base, 'mcnemar_p')} "
            f"| {F.p(*base, 'mcnemar_p_holm')} "
            f"| {F.plain(*base, 'family_size')} "
            f"| {_verdict(F, *base)} |")


def render(F: Fmt) -> str:
    L = ["# 모델 카드", "", gen_note(), ""]

    L.append(f"베이스 모델 `{F.s('refs', 'model', 'repo')}`, 커밋 "
             f"`{F.s('cond1_train', 'model_repo_commit')}`에 LoRA 어댑터를 얹고 병합한 두 체크포인트다. "
             "두 조건은 **같은 토큰 예산, 같은 옵티마이저 스텝 수**로 학습되었고, 차이는 "
             "리플레이 데이터의 유무 하나다.")
    L.append("")
    L.append("| | Cond-0 | Cond-1 | Cond-2 |")
    L.append("|---|---|---|---|")
    L.append("| 설명 | 학습하지 않은 베이스 | 도메인 데이터만 | 도메인 + 일반 지시 리플레이 |")
    L.append(f"| 총 학습 토큰 | — | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'total_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'total_tokens')} |")
    L.append(f"| 리플레이 비중 | — | {F.plain('datasets', 'decisions', 'conditions', 'cond1', 'replay_tokens')} "
             f"| {F.pct('datasets', 'decisions', 'conditions', 'cond2', 'replay_fraction_achieved', nd=0)} |")
    L.append(f"| 옵티마이저 스텝 | — | {F.plain('cond1_train', 'config', 'steps')} "
             f"| {F.plain('cond2_train', 'config', 'steps')} |")
    L.append("")

    # ================================================================ 사용
    L.append("## 의도된 사용")
    L.append("")
    L.append("이 체크포인트는 **연구용 대조군**이다. 제품이 아니다. 답하려고 만든 질문은 하나다 — "
             "동일한 학습 예산에서 일반 지시 데이터를 섞으면 도메인 성능과 일반 능력이 각각 어떻게 움직이는가.")
    L.append("")
    L.append("측정된 능력은 **세 가지**뿐이다.")
    L.append("")
    for t in SCORED:
        L.append(f"- **{TASK_KO[t]}** (`{t}`) — 평가 항목 "
                 f"{F.n('datasets', 'tasks', t, 'by_split', 'eval_post_cutoff')}건(컷오프 이후) / "
                 f"{F.n('datasets', 'tasks', t, 'by_split', 'eval_pre_cutoff')}건(컷오프 이전)")
    L.append("")

    L.append("## 범위 밖 사용")
    L.append("")
    L.append("아래는 **측정되지 않았다.** 측정되지 않은 것을 못한다고 단정하지는 않지만, "
             "이 카드의 어떤 수치도 아래에 대한 근거가 되지 못한다.")
    L.append("")
    L.append("- 취약점 **익스플로잇** 작성이나 공격 실행 — 학습 데이터에도 평가에도 없다")
    L.append("- 침해사고 대응, 포렌식, 로그 분석, 탐지 룰 작성")
    L.append("- 소스 코드 분석 및 취약점 발견 — 이 파이프라인은 코드를 다루지 않는다. CVE **설명문**을 다룬다")
    L.append("- 추론·논증 능력 — 벤치마크가 없다")
    L.append("- 운영 환경에서의 자동 판정 — 아래 정확도 수치를 보면 그 용도로는 어느 조건도 충분하지 않다")
    L.append("")
    L.append(f"`attack_technique` 과제는 데이터셋에 있지만 **채점하지 않는다**: "
             f"{F.s('datasets', 'not_scored_reason', 'attack_technique')}")
    L.append("")
    L.append(f"인용한 문장의 \"72 / 44 evaluation items\"는 기록된 결함이다 — 그 두 수는 평가 항목 수가 "
             f"아니라 커버리지 0 항목 수이고, 실제 평가 항목은 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_post_cutoff')}건과 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_pre_cutoff')}건이다. "
             "자세한 사정은 `docs/DATASET.md`에 있다. 채점하지 않는다는 결론은 그대로다.")
    L.append("")

    # ============================================================ 학습 데이터
    L.append("## 학습 데이터와 그 출처")
    L.append("")
    L.append(f"네 개 공개 보안 출처, 정규화 이전 "
             f"{F.n('process', 'summary', 'records_in')}건에서 만들어진다. 모든 출처는 불변 참조로 "
             "고정되어 있고, 모든 레코드는 계통 필드를 달고 다닌다. 전체는 `docs/DATASET.md`에 있다.")
    L.append("")
    L.append("| | Cond-1 | Cond-2 |")
    L.append("|---|---|---|")
    L.append(f"| 도메인 예제 | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'examples')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'domain_examples')} |")
    L.append(f"| 도메인 토큰 | {F.n('datasets', 'decisions', 'conditions', 'cond1', 'domain_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'domain_tokens')} |")
    L.append(f"| 리플레이 쌍 | {F.plain('datasets', 'decisions', 'conditions', 'cond1', 'replay_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'replay_pairs')} |")
    L.append(f"| 리플레이 토큰 | {F.plain('datasets', 'decisions', 'conditions', 'cond1', 'replay_tokens')} "
             f"| {F.n('datasets', 'decisions', 'conditions', 'cond2', 'replay_tokens')} |")
    L.append(f"| **합계** | **{F.n('datasets', 'decisions', 'conditions', 'cond1', 'total_tokens')}** "
             f"| **{F.n('datasets', 'decisions', 'conditions', 'cond2', 'total_tokens')}** |")
    L.append("")
    L.append(f"두 조건의 예산 차이는 {F.n('datasets', 'decisions', 'conditions', 'budget_residue_tokens')}토큰"
             f"({F.pct('datasets', 'decisions', 'conditions', 'budget_residue_fraction', nd=4)})이다. "
             "Cond-2의 도메인 집합은 Cond-1의 **진부분집합**이며, 정렬된 예제 ID의 해시가 교집합의 해시와 "
             "같다는 것으로 증명된다.")
    L.append("")
    L.append("학습은 컷오프 **이전** 데이터만 쓴다. 평가는 컷오프 이후와 이전 두 세트로 한다. "
             f"컷오프는 `{F.s('datasets', 'decisions', 'temporal_split', 'cutoff')}`이며, 이유는 "
             "베이스 모델이 볼 수 없었던 날짜가 오염을 막는 유일한 장치이기 때문이다.")
    L.append("")
    L.append("리플레이는 `oasst2`의 사람이 쓴 영어 턴만 쓴다. 모델이 생성한 메시지는 제외한다. "
             "라이선스 판정과 후보 기각 사유는 `docs/LICENSES.md`에 있다.")
    L.append("")

    # ============================================================ 학습 절차
    L.append("## 학습 절차")
    L.append("")
    cfg = F.get("cond1_train", "config")
    L.append("| 항목 | 값 |")
    L.append("|---|---|")
    L.append(f"| 방법 | LoRA (`r`={F.plain('cond1_train', 'config', 'lora', 'r')}, "
             f"`alpha`={F.plain('cond1_train', 'config', 'lora', 'alpha')}, "
             f"`dropout`={F.d('cond1_train', 'config', 'lora', 'dropout', nd=1)}) |")
    L.append(f"| 대상 모듈 | {', '.join('`' + m + '`' for m in cfg['lora']['target_modules'])} |")
    L.append(f"| 학습 가능 파라미터 | {F.n('cond1_train', 'trainable_params')} / "
             f"{F.n('cond1_train', 'total_params')} |")
    L.append(f"| 시퀀스 길이 | {F.n('cond1_train', 'config', 'seq_len')} |")
    L.append(f"| 배치 | per-device {F.plain('cond1_train', 'config', 'per_device_batch')} × "
             f"grad accum {F.plain('cond1_train', 'config', 'grad_accum')} |")
    L.append(f"| 학습률 / 워밍업 / 클립 | {F.d('cond1_train', 'config', 'lr', nd=5)} / "
             f"{F.plain('cond1_train', 'config', 'warmup_steps')} 스텝 / "
             f"{F.d('cond1_train', 'config', 'grad_clip', nd=1)} |")
    L.append(f"| 시드 | {F.plain('cond1_train', 'config', 'seed')} |")
    L.append(f"| 스텝 | {F.plain('cond1_train', 'steps_completed')} (Cond-1) / "
             f"{F.plain('cond2_train', 'steps_completed')} (Cond-2) |")
    L.append(f"| 실제 소요 | {F.calc('hours', [('cond1_train', 'wall_sec')], nd=1)}시간 / "
             f"{F.calc('hours', [('cond2_train', 'wall_sec')], nd=1)}시간 |")
    L.append(f"| 최종 손실 | {F.d('cond1_train', 'loss_last', nd=3)} / "
             f"{F.d('cond2_train', 'loss_last', nd=3)} |")
    L.append(f"| GPU | `{F.s('cond1_train', 'gpu_name')}`, 드라이버 "
             f"`{F.s('cond1_train', 'driver_version')}`, 최대 메모리 "
             f"{F.d('cond1_train', 'peak_mem_gib', nd=1)} GiB |")
    L.append("")
    L.append("**시퀀스 패킹은 블록 대각 마스크로 격리된다.** 한 시퀀스에 여러 예제를 채우면 토큰이 "
             "이웃 예제를 볼 수 있다. 마스크가 그것을 막는지 확인했다 — 패킹된 상태와 단독 상태의 "
             f"argmax 일치율 {F.pct('cond1_train', 'packing_isolation_check', 'argmax_agreement_masked_vs_alone', nd=1)}, "
             f"최대 로짓 차이 {F.d('cond1_train', 'packing_isolation_check', 'max_abs_logit_diff_masked_vs_alone', nd=2)}"
             f"(마스크 없이 순진하게 패킹하면 "
             f"{F.d('cond1_train', 'packing_isolation_check', 'max_abs_logit_diff_naive_vs_alone', nd=2)}까지 벌어진다).")
    L.append("")
    L.append(f"**한 에폭이 아니다.** 채팅 템플릿 오버헤드 때문에 "
             f"{F.plain('cond1_train', 'steps_completed')}스텝은 데이터의 "
             f"{F.pct('cond1_train', 'epoch_fraction', nd=1)}만 본다"
             f"(예제 {F.n('cond1_train', 'examples_seen')} / "
             f"{F.n('cond1_train', 'examples')}). `epoch_fraction`으로 기록하며 에폭이라고 부르지 않는다.")
    L.append("")
    L.append("**재현성 주장의 범위**: " + F.s("cond1_train", "reproducibility_claim"))
    L.append("")

    # ============================================================ 평가
    L.append("## 평가")
    L.append("")
    L.append("### 설계")
    L.append("")
    L.append("- **디코딩 두 가지**: 제약 디코딩(문법 강제)과 자유 생성. 자유 생성은 스키마 유효율을 "
             "따로 보고한다.")
    L.append(f"- **생성 길이는 손으로 정하지 않는다**: `{F.s('baseline_run', 'max_tokens_rule')}`. "
             "임의의 상한은 스키마 유효율을 \"내가 정한 상한의 측정\"으로 바꿔 버린다.")
    L.append(f"- **결정론**: `VLLM_BATCH_INVARIANT=1`로 두 번 완주해 출력이 바이트 단위로 같음을 확인했다"
             f"(Gate {F.plain('refs', 'gates', 'evaluation_determinism')}, sha256 `{F.get('gate4', 'outputs', 'sha256')[:16]}…`, "
             f"차이 난 항목 {F.plain('gate4', 'outputs', 'n_differing')}건).")
    L.append("- **채점에 언어모델을 쓰지 않는다.** 완전 일치와 스키마 파싱, 그리고 CVSS의 경우 "
             "규격의 공식을 컨테이너에서 실행한 결과다.")
    L.append(f"- **다중 비교 보정**: Holm-Bonferroni. 패밀리는 "
             + ", ".join(f"`{k}`({F.plain('compare', 'families', k, 'size')})" for k in sorted(F.get("compare", "families")))
             + "로 사전 정의되어 있고, 각 비교는 자기 패밀리 크기와 함께 보고된다.")
    L.append(f"- **판정 규칙**: {F.s('compare', 'design')}")
    L.append("")

    # ---------------------------------------------------- 도메인, 제약 디코딩
    L.append("### 도메인 과제 — 제약 디코딩")
    L.append("")
    L.append("| 과제 / 세트 | Cond-0 | Cond-1 | Cond-2 |")
    L.append("|---|---|---|---|")
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            base = ("compare", "domain", k, "rates")
            L.append(f"| `{t}` / {SPLIT_KO[sp]} "
                     f"| {_rate(F, *base, 'baseline')} "
                     f"| {_rate(F, *base, 'cond1')} "
                     f"| {_rate(F, *base, 'cond2')} |")
    L.append("")
    L.append("구간은 1,000회 부트스트랩의 95% 구간이며 **서술용이다.** 두 조건은 같은 항목에 답하므로 "
             "판정은 짝지은 검정이 한다. 주변 구간이 겹치는 것과 차이가 없는 것은 다른 진술이다.")
    L.append("")
    L.append("| 과제 / 세트 | 비교 | 차이 | 쌍 차이 95% 구간 | McNemar p | Holm p | 패밀리 | 판정 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            for pr in PAIRS:
                base = ("compare", "domain", k, "pairs", pr, "accuracy")
                L.append(f"| `{t}` / {SPLIT_KO[sp]} " + _pairrow(F, PAIR_KO[pr], *base)[1:])
    L.append("")
    L.append("**Cond-1이 도메인에서 앞서는 것은 발견이 아니라 설계의 귀결이다.** 동일 토큰 예산을 "
             "유지했으므로 Cond-2는 도메인 데이터를 "
             f"{F.pct('datasets', 'decisions', 'conditions', 'cond2', 'replay_fraction_achieved', nd=0)}만큼 "
             "덜 본다. 리플레이의 비용은 이 표에 있고, 이득이 있다면 일반 능력 절에 있다.")
    L.append("")

    # ---------------------------------------------------- 자유 생성
    L.append("### 자유 생성과 스키마 유효율")
    L.append("")
    L.append(f"| 과제 / 세트 | Cond-0 정확도 | Cond-1 | Cond-2 | Cond-0 스키마 유효율 | Cond-1 | Cond-2 | "
             f"검출 가능 최소차(비짝지음)[^{MDD_FOOTNOTE}] |")
    L.append("|---|---|---|---|---|---|---|---|")
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "free")
            r = ("compare", "domain", k, "rates")
            s = ("compare", "domain", k, "schema_valid")
            L.append(f"| `{t}` / {SPLIT_KO[sp]} "
                     f"| {F.pct(*r, 'baseline', 'rate', nd=1)} | {F.pct(*r, 'cond1', 'rate', nd=1)} "
                     f"| {F.pct(*r, 'cond2', 'rate', nd=1)} "
                     f"| {F.pct(*s, 'baseline', 'rate', nd=1)} | {F.pct(*s, 'cond1', 'rate', nd=1)} "
                     f"| {F.pct(*s, 'cond2', 'rate', nd=1)} "
                     f"| {F.mdd(('compare', 'domain', k, 'mdd_points_unpaired'), (*r, 'baseline', 'rate'), (*r, 'baseline', 'n'), nd=1)} |")
    L.append("")
    boundary = [cell(t, sp, "free") for t in SCORED for sp in SPLITS
                if at_boundary(F.R, ["compare", "domain", cell(t, sp, "free"), "rates", "baseline", "rate"],
                               ["compare", "domain", cell(t, sp, "free"), "rates", "baseline", "n"])]
    L.append(f"[^{MDD_FOOTNOTE}]: 검출 가능 최소차(MDD)는 이항 비율의 정규근사로 계산된다. "
             "비율이 `0`이나 `1`에서 표준오차 세 배 이내로 가까우면 그 근사는 무너지고, 공식은 "
             "실험이 결코 분간할 수 없는 크기의 수를 돌려준다. 그런 칸은 값을 출판하지 않고 "
             "**n/a (비율이 경계값)**로 적는다. 이번 결과에서 해당하는 칸은 "
             + ", ".join(f"`{k}`" for k in boundary) +
             "이며, 모두 베이스 모델의 자유 생성 정확도가 사실상 0이기 때문이다. "
             "짝지은 MDD는 관측된 불일치율에서 나오므로 같은 문제를 겪지 않는다.")
    L.append("")
    L.append("자유 생성에서 베이스 모델이 거의 0을 받는 것은 능력의 부재가 아니라 **형식의 부재**다. "
             "산문으로 답하기 때문에 완전 일치가 실패한다. 제약 디코딩 열과 나란히 읽어야 하며, "
             "이 차이 자체가 \"구조화 출력 능력\"이 무엇을 뜻하는지에 대한 측정이다.")
    L.append("")

    # ---------------------------------------------------- 일반 능력
    L.append("### 일반 능력 — 두 벤치마크가 서로 다른 답을 준다")
    L.append("")
    L.append("**이것이 이 카드의 핵심 결과이며, 하나를 고르지 않는다.**")
    L.append("")
    for g in ("hellaswag", "mmlu"):
        L.append(f"#### `{g}`")
        L.append("")
        L.append("| 조건 | 정확도 | n |")
        L.append("|---|---|---|")
        for c in ("baseline", "cond1", "cond2"):
            base = ("compare", "general", g, "pairs", "cond1 vs baseline",
                    "marginal_b" if c == "baseline" else "marginal_a")
            if c == "cond2":
                base = ("compare", "general", g, "pairs", "cond2 vs baseline", "marginal_a")
            L.append(f"| {COND_SHORT[c]} | {F.pct(*base, 'rate', nd=1)} "
                     f"{F.ci_abs(*base, 'ci95', nd=1, scale=100, unit='%')} | {F.n(*base, 'n')} |")
        L.append("")
        L.append("| 비교 | 차이 | 쌍 차이 95% 구간 | McNemar p | Holm p | 패밀리 | 판정 |")
        L.append("|---|---|---|---|---|---|---|")
        for pr in PAIRS:
            base = ("compare", "general", g, "pairs", pr)
            L.append(_pairrow(F, PAIR_KO[pr], *base))
        L.append("")
        L.append(f"짝지은 MDD {F.abspp('compare', 'general', g, 'mdd_points_paired', nd=1)}, "
                 f"비짝지음 MDD {F.abspp('compare', 'general', g, 'mdd_points_unpaired', nd=1)}. "
                 "짝지은 설계를 비짝지음 기준으로 재면 실제로 검출한 크기의 차이를 "
                 "\"검출 불가\"로 부르게 된다.")
        L.append("")
    L.append("**읽는 법.** `hellaswag`에서는 리플레이가 작동했다 — Cond-2가 Cond-1보다 앞서고 "
             "Holm 보정 뒤에도 남으며, Cond-2는 베이스와 구별되지 않는다(망각 없음). "
             "`mmlu`에서는 작동하지 않았다 — Cond-2가 베이스보다 떨어지고 그 하락은 검출되며, "
             "Cond-1의 하락보다 크다.")
    L.append("")
    L.append("두 벤치마크가 서로 다른 답을 준다. **방어할 수 있는 문장은 하나뿐이다: 리플레이의 효과는 "
             "무엇을 일반 능력으로 정의하느냐에 달렸다.** 대화체 리플레이가 문장완성에 가깝고 "
             "지식 질의응답에는 그렇지 않다는 설명은 그럴듯하지만 **검정하지 않았다**. "
             "하나를 고르면 그것은 측정이 아니라 선택이다.")
    L.append("")
    if seed2_doc.have(F):
        L.append(seed2_doc.finding_clause(F))
    else:
        L.append("**이 결과는 시드 하나에서 나왔다.** "
                 f"시드 `{F.plain('cond1_train', 'config', 'seed')}` 단일 실행이며, 두 번째 시드 "
                 f"`{F.plain('refs', 'seed2', 'seed')}`는 이 문서를 만드는 시점에 학습 중이었다"
                 f"(`{F.s('refs', 'seed2', 'status')}`). 위 판정들은 리플레이 효과와 시드 분산을 "
                 "분리하지 못한다 — 이것은 한계 절의 항목이 아니라 **결과 문장 자체의 일부다.** "
                 f"판단 기준은 이미 고정되어 있다: {F.s('refs', 'seed2', 'interpretation_rule', 'agreement')}")
    L.append("")
    L.extend(seed2_doc.general_block(F))

    # ---------------------------------------------------- 오염 계층
    L.append("### 오염 계층별 점수")
    L.append("")
    L.append("평가 항목은 학습 데이터와의 13-gram 커버리지에 따라 **0 / 낮음 / 높음** 세 계층으로 "
             "나뉜다. 커버리지는 거르는 데 쓰지 않고 측정해서 붙인다(`docs/engineering-rules.md` 규칙 "
             f"{F.plain('refs', 'engineering_rules', 'no_unevidenced_threshold_deletes_data')}).")
    L.append("")
    L.append("| 과제 / 세트 | 계층 | Cond-1 정확도 | n |")
    L.append("|---|---|---|---|")
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            for st in ("zero", "low", "high"):
                base = ("cond1", "domain", k, "by_stratum", st, "accuracy_over_all_items")
                L.append(f"| `{t}` / {SPLIT_KO[sp]} | `{st}` "
                         f"| {F.pct(*base, 'rate', nd=1)} "
                         f"{F.ci_abs(*base, 'ci95', nd=1, scale=100, unit='%')} "
                         f"| {F.n(*base, 'n')} |")
    L.append("")
    L.append("계층 간 차이는 **오염일 수도, 그 항목이 쉬운 것일 수도 있다.** 이 표는 그 구분을 "
             "내리지 않는다. 내릴 수 없기 때문이다. 다만 걸러 버렸다면 이 질문 자체가 불가능해졌을 것이다.")
    L.append("")

    # ---------------------------------------------------- 암기 탐침
    L.append("### 암기 탐침 — 결론이 아니라 상한")
    L.append("")
    L.append("근사 중복으로 평가 세트에서 제거된 항목들을 학습 쪽에서 다시 찾아, 각 조건이 "
             "**실제로 학습한 텍스트**에 대해 소속을 다시 계산하고, 난이도를 맞춘 대조 항목과 "
             "짝지어 비교한다. 바닥선(Cond-0)도 **같은 항목들 위에서** 다시 계산한다.")
    L.append("")
    L.append("| 조건 | 디코딩 | 학습에 존재 | 대조 짝 | 바닥선 차이 | 조건 차이 | 바닥선 대비 | MDD |")
    L.append("|---|---|---|---|---|---|---|---|")
    for c in ("cond1", "cond2"):
        for dec in ("constrained", "free"):
            base = ("probe", "conditions", c, "modes", dec)
            L.append(f"| {COND_SHORT[c]} | {DEC_KO[dec]} "
                     f"| {F.n('probe', 'conditions', c, 'n_probe_in_training')} "
                     f"| {F.n('probe', 'conditions', c, 'n_with_matched_control')} "
                     f"| {F.pp(*base, 'floor_baseline', 'diff', nd=1)} "
                     f"| {F.pp(*base, 'condition', 'diff', nd=1)} "
                     f"| {F.pp(*base, 'above_floor', nd=1)} "
                     f"| ±{F.abspp(*base, 'condition', 'mdd_points', nd=1)} |")
    L.append("")
    L.append("**암기는 검출되지 않았다.** 이것은 \"암기가 없다\"는 주장이 아니라 **상한**이다. "
             f"{F.plain('cond1_train', 'steps_completed')}스텝, "
             f"데이터의 {F.pct('cond1_train', 'epoch_fraction', nd=1)}, "
             f"LoRA `r`={F.plain('cond1_train', 'config', 'lora', 'r')}에서, "
             f"짝 {F.n('probe', 'conditions', 'cond1', 'n_with_matched_control')}개와 "
             f"{F.n('probe', 'conditions', 'cond2', 'n_with_matched_control')}개의 탐침이 "
             "대략 10퍼센트포인트 이상의 근사 중복 암기를 배제한다. 그보다 작은 암기는 "
             "이 표본으로 분간할 수 없다 — MDD 열이 그 크기다.")
    L.append("")
    L.append("두 조건의 탐침 집합은 서로 다르므로(각자 학습한 것이 다르다) **합치지 않았다.** "
             f"탐침 소속은 `{F.s('probe_sets', 'threshold_source')}`로 다시 계산했고, "
             f"그 방법과 P5 판본의 차이는 `{F.s('probe_sets', 'note')}`로 기록되어 있다.")
    L.append("")

    # ============================================================ 한계
    L.append("## 한계")
    L.append("")
    L.append("부드럽게 적지 않는다. 아래가 이 카드의 나머지를 믿을 만하게 만드는 이유다.")
    L.append("")
    L.append("- **근사 중복 임계값은 보정되지 않았다.** "
             f"임계값 {F.d('datasets', 'contamination', 'index', 'near_threshold', nd=2)}는 "
             "P2 보정에서 채택되었으나, 그 실험의 재현율 열은 표본 설계를 다시 진술한 것에 지나지 않는다는 "
             "사실이 뒤에 드러났다. 재보정은 수행되지 않았고, **평가 세트는 그 임계값 위에 서 있다.**")
    if seed2_doc.have(F):
        L.append(f"- **시드 두 개.** {F.s('refs', 'seed2', 'interpretation_rule', 'limit')} "
                 "결론은 위 결과 절에 있다.")
    else:
        L.append("- **시드 하나.** 위 결과 절에 적은 그대로다. 리플레이 효과와 시드 분산이 분리되지 않는다.")
    L.append(f"- **한 에폭이 아니다.** 데이터의 {F.pct('cond1_train', 'epoch_fraction', nd=1)}만 본다. "
             "더 오래 학습했을 때 무엇이 달라지는지는 측정되지 않았다.")
    L.append("- **비트 단위 재학습 재현성은 검증되지 않았다.** 시드·데이터 순서 해시·패킹 시드는 "
             "기록되어 있지만 재학습을 실제로 다시 돌려 비교하지는 않았다. 평가 쪽 결정론"
             f"(Gate {F.plain('refs', 'gates', 'evaluation_determinism')})은 검증되었다 — "
             "둘은 다른 주장이다.")
    L.append(f"- **`attack_technique`는 채점되지 않는다.** 평가 항목이 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_post_cutoff')}건과 "
             f"{F.n('datasets', 'tasks', 'attack_technique', 'by_split', 'eval_pre_cutoff')}건뿐이라 "
             "조건 간 비교에 쓸 수 없다.")
    L.append(f"- **불일치 CWE {F.n('datasets', 'decisions', 'cwe_ground_truth', 'buckets', 'contested')}건을 "
             "제외했다.** 두 권위 출처가 다른 라벨을 붙인 항목들이며, 이들이 정확히 어려운 항목일 "
             "가능성이 높다. 평가는 그만큼 쉬운 쪽으로 치우쳐 있다.")
    L.append("- **일반 능력 벤치마크는 문자 생성 방식으로 측정했다.** 로그우도 비교가 아니라 "
             "정답 문자를 생성하게 한다. 널리 보고되는 수치와 직접 비교할 수 없다.")
    L.append("- **보안 능력을 측정하지 않는다.** 약점 분류, 심각도 벡터 추론, 구조화 추출 — "
             "세 가지 좁은 능력이다. 이 카드를 보안 역량의 증거로 읽어서는 안 된다.")
    L.append("")

    # ============================================================ 라이선스
    L.append("## 라이선스 입장")
    L.append("")
    L.append("**네 개 보안 출처와 리플레이 출처 모두 모델 가중치에 대해 아무 말도 하지 않는다.** "
             "가중치 공개를 금지한 것이 아니라 언급하지 않는다. 따라서 가중치 공개는 허가가 아니라 "
             "그 침묵 위에 서 있으며, 법률 검토 없이 공개할 근거가 되지 못한다.")
    L.append("")
    L.append("| 출처 | 재배포 | 가중치 공개 | 상업적 이용 |")
    L.append("|---|---|---|---|")
    for sid in ("cve_list", "nvd", "cwe", "attack", "replay_oasst2"):
        lic = F.get("licenses", sid, "license")
        L.append(f"| `{sid}` | {lic['redistribution_status']} | {lic['model_publication_status']} "
                 f"| {lic['commercial_status']} |")
    L.append("")
    L.append("근거 문장, 확인일, 기각된 후보와 그 사유는 전부 `docs/LICENSES.md`에 있다.")
    L.append("")

    # ============================================================ 재현
    L.append("## 재현")
    L.append("")
    L.append("`docs/REPRODUCE.md`에 빈 체크아웃에서 시작하는 절차와 단계별 비용이 있다. "
             "원본 코퍼스는 재배포하지 않는다 — 핀과 해시만 배포한다.")
    L.append("")
    L.append(f"평가 하니스 코드 해시 `{F.get('cond1_run', 'harness_code_sha256')[:16]}…`, "
             f"데이터셋 매니페스트 해시 `{F.get('compare', 'dataset_manifest_sha256', 'cond1')[:16]}…`. "
             "두 값이 세 실행에서 모두 같다는 것이 \"같은 것을 같은 방법으로 쟀다\"의 기계적 정의다.")
    L.append("")
    return "\n".join(L) + "\n"
