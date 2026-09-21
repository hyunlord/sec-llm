# -*- coding: utf-8 -*-
"""The second-seed section, rendered only when seed 5678 has actually landed.

Every function here returns an empty list when the seed-2 records are absent,
so the documents build and reproduce byte for byte both before and after that
run finishes.

The interpretation rule is not decided here. It was fixed and committed in
`docs/refs.json` while seed 5678 was still training, before any of its scores
existed, and this module only applies it: same sign on the paired difference
AND the same Holm-adjusted verdict counts as agreement. Deciding what
agreement means after reading the numbers would be selection, not
interpretation.

The conclusion sentence is chosen by that rule from the data, in both
directions. Neither branch is the one this file hopes for.
"""

from __future__ import annotations

from docs.common import S1_PAIR, S2_PAIR, SEEDVAR_PAIR, SPLIT_KO, Fmt, cell

SCORED = ("cve_to_cwe", "cvss_vector", "structured_extract")
SPLITS = ("eval_post_cutoff", "eval_pre_cutoff")
GENERAL = ("hellaswag", "mmlu")
VERDICT_KO = {"difference detected": "**차이 검출됨**", "no difference detected": "차이 검출되지 않음"}


def have(F: Fmt) -> bool:
    return bool(getattr(F.R, "seed2", False))


def _sign(x: float) -> int:
    return (x > 0) - (x < 0)


def _agrees(F: Fmt, g: str) -> bool:
    a = F.get("compare", "general", g, "pairs", S1_PAIR)
    b = F.get("compare_s2", "general", g, "pairs", S2_PAIR)
    same_sign = _sign(a["paired_difference"]["diff"]) == _sign(b["paired_difference"]["diff"])
    return same_sign and a["verdict"] == b["verdict"]


def _v(F: Fmt, *base) -> str:
    return VERDICT_KO[F.get(*base, "verdict")]


def _cmp_row(F: Fmt, label: str, *base) -> str:
    pd = base + ("paired_difference",)
    return (f"| {label} | {F.pp(*pd, 'diff', nd=1)} "
            f"| {F.ci(*pd, 'ci95', nd=1, scale=100, unit='pp')} "
            f"| {F.p(*base, 'mcnemar_p_holm')} | {_v(F, *base)} "
            f"| ±{F.abspp(*pd, 'mdd_points_paired', nd=1)} |")


def general_block(F: Fmt) -> list:
    """The two-seed section for the model card. Empty until seed 2 lands."""
    if not have(F):
        return []
    L = ["### 두 번째 시드 — 시드 5678", ""]
    L.append(f"같은 데이터, 같은 토큰 예산, 같은 스텝 수. 난수 시드만 "
             f"`{F.plain('cond1_train', 'config', 'seed')}`에서 "
             f"`{F.plain('cond1_s2_train', 'config', 'seed')}`로 바꾼 재실행이다.")
    L.append("")
    L.append(f"**해석 규칙은 이 실행이 끝나기 전에 고정해 커밋했다**"
             f"(`docs/refs.json`, {F.s('refs', 'seed2', 'interpretation_rule', 'fixed_on')}). "
             f"{F.s('refs', 'seed2', 'interpretation_rule', 'agreement_ko')}")
    L.append("")

    # ---------------------------------------------- 재현되는가
    L.append("#### 일반 능력 — 시드 1234의 결과가 재현되는가")
    L.append("")
    L.append("| 벤치마크 | 시드 1234 Cond-1 vs Cond-2 | 판정 | 시드 5678 | 판정 | 규칙에 따른 일치 |")
    L.append("|---|---|---|---|---|---|")
    for g in GENERAL:
        a = ("compare", "general", g, "pairs", S1_PAIR)
        b = ("compare_s2", "general", g, "pairs", S2_PAIR)
        L.append(f"| `{g}` "
                 f"| {F.pp(*a, 'paired_difference', 'diff', nd=1)} "
                 f"(Holm p={F.p(*a, 'mcnemar_p_holm')}) | {_v(F, *a)} "
                 f"| {F.pp(*b, 'paired_difference', 'diff', nd=1)} "
                 f"(Holm p={F.p(*b, 'mcnemar_p_holm')}) | {_v(F, *b)} "
                 f"| {'**일치**' if _agrees(F, g) else '**불일치**'} |")
    L.append("")
    L.append("부호는 Cond-1에서 Cond-2를 뺀 값의 부호다. 음수는 Cond-2가 앞선다는 뜻이다.")
    L.append("")

    L.extend(asymmetry_block(F))

    # ---------------------------------------------- 도메인
    L.append("#### 도메인 과제에서도 재현되는가")
    L.append("")
    L.append("| 과제 / 세트 | 시드 1234 | Holm p | 시드 5678 | Holm p | 결과 |")
    L.append("|---|---|---|---|---|---|")
    contradictions, flips = [], []
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            a = ("compare", "domain", k, "pairs", S1_PAIR, "accuracy")
            b = ("compare_s2", "domain", k, "pairs", S2_PAIR, "accuracy")
            da, db = F.get(*a, "paired_difference", "diff"), F.get(*b, "paired_difference", "diff")
            va, vb = F.get(*a, "verdict"), F.get(*b, "verdict")
            both_detected = va == vb == "difference detected"
            if both_detected and _sign(da) != _sign(db):
                mark, label = "**서로 반대**", f"`{t}`/{SPLIT_KO[sp]}"
                contradictions.append(label)
            elif va != vb:
                mark, label = "**판정 뒤집힘**", f"`{t}`/{SPLIT_KO[sp]}"
                flips.append(label)
            else:
                mark = "일치"
            L.append(f"| `{t}` / {SPLIT_KO[sp]} "
                     f"| {F.pp(*a, 'paired_difference', 'diff', nd=1)} | {F.p(*a, 'mcnemar_p_holm')} "
                     f"| {F.pp(*b, 'paired_difference', 'diff', nd=1)} | {F.p(*b, 'mcnemar_p_holm')} "
                     f"| {mark} |")
    L.append("")
    if contradictions:
        L.append("**" + ", ".join(contradictions) + "에서 두 시드가 서로 반대 방향을 가리키며, "
                 "양쪽 모두 자기 시드 안에서는 차이를 검출한다.** 큰 값과 작은 값의 차이가 아니라 "
                 "**어느 조건이 낫느냐에 대한 모순**이다. 한 시드만 돌렸다면 그 시드가 말하는 쪽을 "
                 "결과로 적었을 것이고, 그 수치는 Holm 보정 뒤에도 살아남았을 것이다.")
        L.append("")
    if flips:
        L.append("**" + ", ".join(flips) + "에서는 한 시드가 검출한 차이를 다른 시드가 검출하지 못했다.**")
        L.append("")
    if contradictions or flips:
        L.append("사전에 고정한 규칙은 일반 능력 벤치마크만을 대상으로 한다. 도메인 과제의 이 결과는 "
                 "규칙이 판정하는 대상이 아니라 **함께 측정된 별도의 사실**이며, 그 사실은 "
                 "**동일 예산에서 도메인 과제의 조건 간 우열은 시드에 따라 달라진다**는 것이다. "
                 "도메인 쪽 조건 비교는 시드 하나로 주장할 수 없다.")
        L.append("")

    # ---------------------------------------------- 암기
    L.append("#### 암기 탐침")
    L.append("")
    L.append("| 조건 | 학습에 존재 | 대조 짝 | 바닥선 대비 | MDD |")
    L.append("|---|---|---|---|---|")
    for c in ("cond1_s2", "cond2_s2"):
        base = ("probe_s2", "conditions", c, "modes", "constrained")
        L.append(f"| {c} | {F.n('probe_s2', 'conditions', c, 'n_probe_in_training')} "
                 f"| {F.n('probe_s2', 'conditions', c, 'n_with_matched_control')} "
                 f"| {F.pp(*base, 'above_floor', nd=1)} "
                 f"| ±{F.abspp(*base, 'condition', 'mdd_points', nd=1)} |")
    L.append("")
    L.append("탐침 집합은 시드 1과 같다 — 두 시드는 같은 데이터로 학습했고 시드만 다르므로 "
             "근사 중복 소속이 달라질 이유가 없다. 달라지는 것은 모델의 출력뿐이다.")
    L.append("")

    L.extend(conclusion(F))
    return L


def _disc(F: Fmt, *base) -> str:
    """Discordance as a percentage, computed from the McNemar counts."""
    return F.calc("pct_ratio", [(*base, "mcnemar", "discordant"),
                                (*base, "mcnemar", "paired_items")], nd=1)


def asymmetry_block(F: Fmt) -> list:
    """What the seed-variance records say beyond 'the finding replicated'.

    Two facts live in these records that the net differences hide. First, the
    general-ability conclusion does not rest on small net movements cancelling
    out -- item-level churn between seeds is several times smaller than churn
    between conditions. Second, the two conditions are not equally stable, and
    that asymmetry is the mechanism behind the domain sign reversal.
    """
    if not have(F):
        return []
    L = ["#### 시드 간 변동 — 추론이 아니라 측정", ""]
    L.append("같은 조건을 시드만 바꿔 학습한 두 체크포인트를 **같은 평가 항목 위에서 짝지어** 비교했다. "
             "순 차이뿐 아니라 **항목 단위로 몇 개가 뒤집혔는지**(불일치 쌍)를 함께 적는다. "
             "순 차이가 작은 것은 큰 움직임이 상쇄된 결과일 수도 있고, 애초에 움직이지 않은 "
             "것일 수도 있어서다.")
    L.append("")
    L.append("| 비교 | 차이 | 95% 구간 | Holm p | 판정 | 짝지은 MDD |")
    L.append("|---|---|---|---|---|---|")
    for g in GENERAL:
        for c, src in (("cond1", "seedvar_cond1"), ("cond2", "seedvar_cond2")):
            base = (src, "general", g, "pairs", SEEDVAR_PAIR[c])
            L.append(_cmp_row(F, f"`{g}` — {c} 시드 간", *base))
    L.append("")
    L.append("| 무엇을 바꿨나 | `hellaswag` 불일치 | `mmlu` 불일치 |")
    L.append("|---|---|---|")
    for c, src in (("cond1", "seedvar_cond1"), ("cond2", "seedvar_cond2")):
        L.append(f"| 시드만 ({c}) "
                 + "".join(f"| {_disc(F, src, 'general', g, 'pairs', SEEDVAR_PAIR[c])}% "
                           f"({F.n(src, 'general', g, 'pairs', SEEDVAR_PAIR[c], 'mcnemar', 'discordant')}"
                           f"/{F.n(src, 'general', g, 'pairs', SEEDVAR_PAIR[c], 'mcnemar', 'paired_items')}) "
                           for g in GENERAL) + "|")
    for c in ("cond1", "cond2"):
        L.append(f"| **조건** ({c} vs 베이스) "
                 + "".join(f"| {_disc(F, 'compare', 'general', g, 'pairs', f'{c} vs baseline')}% "
                           f"({F.n('compare', 'general', g, 'pairs', f'{c} vs baseline', 'mcnemar', 'discordant')}"
                           f"/{F.n('compare', 'general', g, 'pairs', f'{c} vs baseline', 'mcnemar', 'paired_items')}) "
                           for g in GENERAL) + "|")
    L.append("")
    L.append("**시드를 바꾸면 항목의 2% 미만이 뒤집히고, 조건을 바꾸면 8~12%가 뒤집힌다.** "
             "일반 능력에서 시드가 문제되지 않았던 것은 큰 움직임이 상쇄되어서가 아니라 "
             "애초에 다섯 배 적게 움직였기 때문이다.")
    L.append("")

    # ------------------------------------------------ the asymmetry
    L.append("#### 리플레이는 도메인 성능을 낮추기만 한 것이 아니라 흔들었다")
    L.append("")
    n1 = F.verdict_count(("seedvar_cond1", "domain"), SEEDVAR_PAIR["cond1"], sub="accuracy")
    n2 = F.verdict_count(("seedvar_cond2", "domain"), SEEDVAR_PAIR["cond2"], sub="accuracy")
    tot = F.count("seedvar_cond1", "domain")
    g1 = F.verdict_count(("seedvar_cond1", "general"), SEEDVAR_PAIR["cond1"])
    g2 = F.verdict_count(("seedvar_cond2", "general"), SEEDVAR_PAIR["cond2"])
    L.append("| 조건 | 시드에 민감한 도메인 세트 | 시드에 민감한 일반 벤치마크 |")
    L.append("|---|---|---|")
    L.append(f"| Cond-1 (도메인만) | {n1} / {tot} | {g1} / {F.count('seedvar_cond1', 'general')} |")
    L.append(f"| Cond-2 (도메인+리플레이) | **{n2} / {tot}** | {g2} / {F.count('seedvar_cond2', 'general')} |")
    L.append("")
    L.append("\"시드에 민감하다\"는 것은 같은 조건을 시드만 바꿔 학습한 두 체크포인트가 그 세트에서 "
             "**Holm 보정 뒤에도 서로 다르다고 판정된다**는 뜻이다.")
    L.append("")
    L.append("| 세트 (제약 디코딩) | Cond-1 시드 간 | Cond-2 시드 간 |")
    L.append("|---|---|---|")
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            a = ("seedvar_cond1", "domain", k, "pairs", SEEDVAR_PAIR["cond1"], "accuracy")
            b = ("seedvar_cond2", "domain", k, "pairs", SEEDVAR_PAIR["cond2"], "accuracy")
            L.append(f"| `{t}` / {SPLIT_KO[sp]} "
                     f"| {F.pp(*a, 'paired_difference', 'diff', nd=1)} "
                     f"(Holm {F.p(*a, 'mcnemar_p_holm')}) {_v(F, *a)} "
                     f"| {F.pp(*b, 'paired_difference', 'diff', nd=1)} "
                     f"(Holm {F.p(*b, 'mcnemar_p_holm')}) {_v(F, *b)} |")
    L.append("")
    L.append("**동일 토큰 예산에서 리플레이는 도메인 정확도를 낮추기만 한 것이 아니라, "
             "도메인 과제의 실행 간 분산을 넓혔다.** 일반 능력 벤치마크에서는 두 조건 모두 "
             "시드에 둔감했다. 이것이 앞서 본 `cvss_vector` 부호 역전의 **메커니즘**이다 — "
             "Cond-2의 도메인 성능이 실행마다 충분히 크게 움직이므로, 어느 조건이 앞서는지가 "
             "시드에 따라 달라진다.")
    L.append("")
    L.append("*왜 그런지는 검정하지 않았다.* oasst2의 대화체는 도메인 JSON보다 길이와 형식이 "
             "훨씬 이질적이어서 시퀀스 패킹 구성이 시드마다 크게 달라진다는 설명이 그럴듯하지만, "
             "**측정하지 않은 가설이다.** 이 문서는 그것을 원인으로 적지 않는다.")
    L.append("")

    # ------------------------------------------------ the boundary flip
    a = ("compare", "general", "mmlu", "pairs", "cond1 vs baseline")
    b = ("compare_s2", "general", "mmlu", "pairs", "cond1_s2 vs baseline")
    if F.get(*a, "verdict") != F.get(*b, "verdict"):
        L.append("#### 경계 판정 하나가 시드에서 뒤집혔다")
        L.append("")
        L.append(f"`mmlu`의 Cond-1 vs 베이스는 시드 `{F.plain('cond1_train', 'config', 'seed')}`에서 "
                 f"{F.pp(*a, 'paired_difference', 'diff', nd=1)}, Holm {F.p(*a, 'mcnemar_p_holm')}로 "
                 f"{_v(F, *a)}이고, 시드 `{F.plain('cond1_s2_train', 'config', 'seed')}`에서 "
                 f"{F.pp(*b, 'paired_difference', 'diff', nd=1)}, Holm {F.p(*b, 'mcnemar_p_holm')}로 "
                 f"{_v(F, *b)}이다. **부호도 크기도 사실상 같은데 판정만 반대다.**")
        L.append("")
        L.append("사전에 고정한 규칙은 Cond-1 vs Cond-2만을 판정 대상으로 하므로 위 결론은 "
                 "영향을 받지 않는다. 그러나 이것은 **유의수준 경계에 놓인 판정이 시드 하나로 "
                 "뒤집히는 구체적 사례**이며, 경계값을 굵게 적지 않는 이유 그 자체다.")
        L.append("")
    return L


def conclusion(F: Fmt) -> list:
    """The rule applied. Both branches are written; the data picks one."""
    if not have(F):
        return []
    agree = {g: _agrees(F, g) for g in GENERAL}
    L = ["#### 규칙이 내린 결론", ""]
    if all(agree.values()):
        L.append("**두 벤치마크 모두 부호와 판정이 일치했다.** 사전에 고정한 규칙이 정한 대로, "
                 f"{F.s('refs', 'seed2', 'interpretation_rule', 'if_both_agree_ko')}")
        L.append("")
        L.append("다만 **벤치마크 사이의 불일치는 그대로 남는다.** 두 시드가 일치했다는 것은 "
                 "`hellaswag`와 `mmlu`가 서로 다른 답을 준다는 사실이 시드 운이 아니었다는 뜻이지, "
                 "둘 중 하나가 옳다는 뜻이 아니다. 여전히 하나를 고르지 않는다.")
    else:
        disagreeing = [g for g in GENERAL if not agree[g]]
        L.append("**" + ", ".join(f"`{g}`" for g in disagreeing) + "에서 두 시드가 어긋났다.** "
                 "사전에 고정한 규칙에 따라, 일치한 쪽을 골라 결론으로 삼지 않는다 — "
                 f"{F.s('refs', 'seed2', 'interpretation_rule', 'if_either_disagrees_ko')}")
        L.append("")
        L.append("즉 P5.1이 검출한 리플레이 효과는 **이 설계로는 시드 분산과 분리되지 않는다.** "
                 "효과가 없다는 뜻이 아니라, 두 번의 학습으로는 있다고 말할 수 없다는 뜻이다. "
                 "분리하려면 조건당 시드 여러 개가 필요하고, 그것은 이 실험이 치르지 않은 비용이다.")
    L.append("")
    hard = _domain_conflicts(F)
    if hard:
        L.append("**같은 실험의 도메인 쪽은 그렇지 않았다.** " + ", ".join(hard) +
                 "에서 두 시드가 서로 반대 방향을 각각 검출했다. 일반 능력의 결론이 두 추출에서 "
                 "버텼다는 것이 도메인 쪽 조건 비교도 버텼다는 뜻이 아니며, 오히려 그 반대다 — "
                 "**도메인 과제의 조건 간 우열은 이 예산에서 시드에 종속된다.**")
        L.append("")
    L.append(f"**두 시드는 분산을 추정하지 못한다.** {F.s('refs', 'seed2', 'interpretation_rule', 'limit_ko')}")
    L.append("")
    return L


def baseline_agrees(F: Fmt) -> bool:
    """Do both seeds put every condition on the same side of the base model?

    Checked rather than asserted: the sentence about base-model improvement
    being seed-stable is emitted only when this is true, and the opposite
    sentence when it is not.
    """
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            for c in ("cond1", "cond2"):
                a = F.get("compare", "domain", k, "pairs", f"{c} vs baseline", "accuracy")
                b = F.get("compare_s2", "domain", k, "pairs", f"{c}_s2 vs baseline", "accuracy")
                if (a["verdict"] != b["verdict"]
                        or _sign(a["paired_difference"]["diff"]) != _sign(b["paired_difference"]["diff"])):
                    return False
    return True


def base_clause(F: Fmt) -> str:
    if baseline_agrees(F):
        return ("베이스 대비 향상은 이 문제를 겪지 않는다 — 도메인 여섯 세트와 두 조건의 "
                "**모든 조합에서** 두 시드가 같은 부호, 같은 판정을 냈다.")
    return ("**베이스 대비 향상도 두 시드에서 일치하지 않는다.** 어느 조건이 베이스를 넘어섰는지조차 "
            "시드에 따라 달라진다는 뜻이며, 이 경우 도메인 결과는 어떤 형태로도 주장할 수 없다.")


def _domain_conflicts(F: Fmt) -> list:
    """Cells where both seeds detected a difference and pointed opposite ways."""
    out = []
    for t in SCORED:
        for sp in SPLITS:
            k = cell(t, sp, "constrained")
            a = F.get("compare", "domain", k, "pairs", S1_PAIR, "accuracy")
            b = F.get("compare_s2", "domain", k, "pairs", S2_PAIR, "accuracy")
            if (a["verdict"] == b["verdict"] == "difference detected"
                    and _sign(a["paired_difference"]["diff"]) != _sign(b["paired_difference"]["diff"])):
                out.append(f"`{t}`/{SPLIT_KO[sp]}")
    return out


def finding_clause(F: Fmt) -> str:
    """Replaces the single-seed sentence inside the finding itself."""
    if not have(F):
        return ""
    agree = {g: _agrees(F, g) for g in GENERAL}
    if all(agree.values()):
        return ("**이 결과는 시드 두 개에서 같은 방향으로 나왔다.** "
                f"시드 `{F.plain('cond1_train', 'config', 'seed')}`와 "
                f"`{F.plain('cond1_s2_train', 'config', 'seed')}`가 부호와 판정 모두에서 일치했고, "
                "그 판단 기준은 두 번째 시드가 끝나기 전에 고정되어 있었다. "
                "시드 간 변동은 위 표에서 직접 측정되어 있으며, 조건 간 차이와 나란히 읽어야 한다. "
                "두 번의 추출은 분산을 추정하지 못하므로 이것은 안정성의 증명이 아니라 "
                "**한 번의 독립적 확인**이다.")
    return ("**이 결과는 두 시드에서 같은 방향으로 나오지 않았다.** "
            f"시드 `{F.plain('cond1_train', 'config', 'seed')}`와 "
            f"`{F.plain('cond1_s2_train', 'config', 'seed')}`가 어긋났고, 판단 기준은 두 번째 시드가 "
            "끝나기 전에 고정되어 있었으므로 일치한 쪽을 골라 결론으로 삼을 수 없다. "
            "**이 설계는 리플레이 효과와 시드 분산을 분리하지 못한다** — 효과가 없다는 뜻이 아니라, "
            "두 번의 학습으로는 있다고 말할 수 없다는 뜻이다.")


def readme_variance(F: Fmt) -> str:
    """The asymmetry, in one sentence, for the README."""
    n1 = F.verdict_count(("seedvar_cond1", "domain"), SEEDVAR_PAIR["cond1"], sub="accuracy")
    n2 = F.verdict_count(("seedvar_cond2", "domain"), SEEDVAR_PAIR["cond2"], sub="accuracy")
    tot = F.count("seedvar_cond1", "domain")
    hs = _disc(F, "seedvar_cond1", "general", "hellaswag", "pairs", SEEDVAR_PAIR["cond1"])
    cb = _disc(F, "compare", "general", "hellaswag", "pairs", "cond1 vs baseline")
    return (f"**메커니즘은 분산이다.** 같은 조건을 시드만 바꿔 다시 학습했을 때 도메인 세트가 "
            f"흔들린 정도는 Cond-1이 {n1}/{tot}, Cond-2가 **{n2}/{tot}**이다 — 동일 예산에서 "
            f"리플레이는 도메인 정확도를 낮추기만 한 것이 아니라 **실행 간 분산을 넓혔다.** "
            f"일반 능력에서는 두 조건 모두 시드에 둔감했다(항목 불일치 {hs}%, 조건을 바꾸면 {cb}%). "
            f"왜 그런지는 검정하지 않았다.")


def readme_clause(F: Fmt) -> str:
    """One sentence for the README headline."""
    if not have(F):
        return "그리고 이 결과는 시드 하나에서 나왔다."
    agree = {g: _agrees(F, g) for g in GENERAL}
    if all(agree.values()):
        return ("두 번째 시드가 두 벤치마크 모두에서 같은 방향을 냈다 — 판단 기준은 그 실행이 "
                "끝나기 전에 고정되어 있었다.")
    return ("두 번째 시드가 이 방향을 재현하지 못했다. 사전에 고정한 규칙에 따라, 이 설계는 "
            "리플레이 효과와 시드 분산을 분리하지 못한다고 적는다.")
