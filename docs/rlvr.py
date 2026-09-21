# -*- coding: utf-8 -*-
"""The RLVR demonstration's entry in the model card, when one exists.

Short by design. The full record is `reports/rlvr.md`; what belongs in a model
card is that a third checkpoint exists, what was done to it, and what the
comparison against its starting point did and did not show.

Returns an empty list until the run has landed, so the card builds and
reproduces byte for byte either way.
"""

from __future__ import annotations

from docs.common import Fmt

VERDICT_KO = {"difference detected": "**차이 검출됨**", "no difference detected": "차이 검출되지 않음"}


def have(F: Fmt) -> bool:
    return bool(getattr(F.R, "rlvr", False))


def _pair_key(F: Fmt) -> str | None:
    for k in F.get("rlvr_compare", "pairs"):
        if "rlvr" in k and "cond2" in k:
            return k
    return None


def block(F: Fmt) -> list:
    if not have(F):
        return []
    L = ["### RLVR 시연 (검증 가능한 보상 기반 강화학습)", ""]
    L.append(f"**{F.s('rlvr_run', 'claim')}**")
    L.append("")
    L.append(f"`{F.s('rlvr_run', 'base_checkpoint')}`에서 출발해 `{F.s('rlvr_run', 'task')}` 과제에 "
             f"GRPO를 {F.plain('rlvr_run', 'steps_completed')}스텝 적용했다. 보상은 결정론적 검사 "
             "두 개의 합이며 — 스키마 유효성과 `cwe_id` 완전 일치 — **컨테이너도 서브프로세스도 "
             "쓰지 않는다.** 스키마 검사는 평가 하니스의 채점기를 수정 없이 그대로 쓴다.")
    L.append("")
    L.append("| 지표 | 처음 | 마지막 |")
    L.append("|---|---|---|")
    S = ("rlvr_run", "summary")
    L.append(f"| 보상 — 스키마 | {F.d(*S, 'reward_schema_first_decile', nd=3)} "
             f"| {F.d(*S, 'reward_schema_last_decile', nd=3)} |")
    L.append(f"| 보상 — 완전 일치 | {F.d(*S, 'reward_exact_first_decile', nd=3)} "
             f"| {F.d(*S, 'reward_exact_last_decile', nd=3)} |")
    L.append(f"| 생성 길이 (토큰) | {F.d(*S, 'completion_tokens_first_decile', nd=1)} "
             f"| {F.d(*S, 'completion_tokens_last_decile', nd=1)} |")
    L.append(f"| 그룹 붕괴율 | {F.pct(*S, 'group_collapse_fraction_mean', nd=1)} (전체 평균) "
             f"| {F.pct(*S, 'group_collapse_fraction_last_decile', nd=1)} |")
    L.append("")
    L.append("**두 보상 성분을 분리해 기록한 이유가 첫 두 줄에 있다.** 하나가 포화한 상태에서 "
             "다른 하나만 움직이는 것과 둘 다 움직이는 것은 서로 다른 결과이고, "
             "스칼라 하나로는 구분되지 않는다.")
    L.append("")

    pair = _pair_key(F)
    if pair:
        L.append("출발 체크포인트와의 비교는 P4 하니스를 **수정 없이** 돌려 짝지은 검정으로 했다.")
        L.append("")
        L.append("| 세트 | 차이 | 95% 구간 | Holm p | 판정 | 짝지은 MDD |")
        L.append("|---|---|---|---|---|---|")
        cells = F.get("rlvr_compare", "domain")
        for k in sorted(cells):
            if pair not in cells[k]["pairs"]:
                continue
            base = ("rlvr_compare", "domain", k, "pairs", pair, "accuracy")
            pd = base + ("paired_difference",)
            L.append(f"| `{k}` | {F.pp(*pd, 'diff', nd=1)} "
                     f"| {F.ci(*pd, 'ci95', nd=1, scale=100, unit='pp')} "
                     f"| {F.p(*base, 'mcnemar_p_holm')} "
                     f"| {VERDICT_KO[F.get(*base, 'verdict')]} "
                     f"| ±{F.abspp(*pd, 'mdd_points_paired', nd=1)} |")
        L.append("")
        detected = [k for k in cells if pair in cells[k]["pairs"]
                    and cells[k]["pairs"][pair]["accuracy"]["verdict"] == "difference detected"]
        if detected:
            L.append(f"차이가 검출된 세트가 있다. 그러나 시드 하나, 스텝 "
                     f"{F.plain('rlvr_run', 'steps_completed')}회의 결과이며, 이 카드가 위에서 보인 대로 "
                     "**도메인 과제의 조건 간 우열은 이 파이프라인에서 시드에 종속된다.** "
                     "RLVR의 효과로 읽으려면 두 번째 시드가 필요하고, 이 시연은 그 비용을 치르지 않았다.")
        else:
            L.append(f"**어느 세트에서도 차이가 검출되지 않았다.** 스텝 "
                     f"{F.plain('rlvr_run', 'steps_completed')}회와 시드 하나로 예상한 결과이며, "
                     "점 추정값이 양수인 칸이 있더라도 효과로 제시하지 않는다.")
        L.append("")
    L.append("전체 기록 — 설정, 보상 곡선, 길이 드리프트, 그룹 붕괴, 고보상 출력의 수동 검사 — 는 "
             "`reports/rlvr.md`에 있다.")
    L.append("")
    return L
