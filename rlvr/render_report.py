# -*- coding: utf-8 -*-
"""reports/rlvr.md -- rendered from the run's own records, nothing recomputed.

Rule 1 applies here as everywhere: the stage that acted owns the record, and
this only renders it. Every figure comes from runs/rlvr/manifest.json,
reward_log.jsonl, reward_inspection.json, or the comparison record.

    python -m rlvr.render_report
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUN = REPO / "runs" / "rlvr"
OUT = REPO / "reports" / "rlvr.md"


def pct(x) -> str:
    return f"{100 * x:.1f}%"


def load():
    m = json.loads((RUN / "manifest.json").read_text())
    rows = [json.loads(x) for x in (RUN / "reward_log.jsonl").read_text().splitlines() if x.strip()]
    insp = json.loads((RUN / "reward_inspection.json").read_text()) \
        if (RUN / "reward_inspection.json").exists() else None
    cmp_path = REPO / "runs" / "compare_rlvr.json"
    cmp_rec = json.loads(cmp_path.read_text()) if cmp_path.exists() else None
    return m, rows, insp, cmp_rec


def verdict_ko(v: str) -> str:
    return "**차이 검출됨**" if v == "difference detected" else "차이 검출되지 않음"


def render() -> str:
    m, rows, insp, cmp_rec = load()
    s = m["summary"]
    L = ["# RLVR 시연 — 구조가 도는지에 대한 기록", ""]
    L.append("> `runs/rlvr/manifest.json`, `reward_log.jsonl`, `reward_inspection.json`, "
             "`runs/compare_rlvr.json`에서 **자동 생성**된다. `python -m rlvr.render_report`로 다시 만든다.")
    L.append("")

    # ---- the first paragraph, which is the whole point of the section
    L.append("## 이 문서가 주장하는 것과 주장하지 않는 것")
    L.append("")
    L.append("**이 실행은 RLVR 구조가 처음부터 끝까지 돈다는 것을 시연한다. 성능 향상을 주장하지 않는다.** "
             f"스텝 {m['steps_completed']}회, 시드 하나, 과제 하나다. 아래 수치가 좋아 보이더라도 "
             "그것은 관측이지 효과가 아니며, 짝지은 검정이 뒷받침하지 않는 한 향상으로 읽어서는 안 된다. "
             "나빠 보이는 경우도 마찬가지로 그대로 적는다 — 구조가 도는 것을 보이는 일에는 "
             "**잘 돌지 않을 때 그것을 보고하는 것**이 포함된다.")
    L.append("")

    # ---- setup
    L.append("## 설정")
    L.append("")
    L.append("| 항목 | 값 |")
    L.append("|---|---|")
    L.append(f"| 과제 | `{m['task']}` |")
    L.append(f"| 출발 체크포인트 | `{m['base_checkpoint']}` |")
    L.append(f"| 스텝 | {m['steps_completed']} / {m['steps_planned']} |")
    L.append(f"| 그룹 크기 | {m['config']['num_generations']} |")
    L.append(f"| 스텝당 생성 수 | {m['config']['per_device_train_batch_size'] * m['config']['gradient_accumulation_steps']} "
             f"(프롬프트 {m['config']['per_device_train_batch_size'] * m['config']['gradient_accumulation_steps'] // m['config']['num_generations']}개) |")
    L.append(f"| 온도 / top-p | {m['config']['temperature']} / {m['config']['top_p']} |")
    L.append(f"| 학습률 / KL 계수 | {m['config']['learning_rate']} / {m['config']['beta']} |")
    L.append(f"| LoRA | `r`={m['config']['lora']['r']}, `alpha`={m['config']['lora']['alpha']} |")
    L.append(f"| 생성 길이 상한 | {m['max_completion_length']} — {m['max_completion_length_derivation']} |")
    L.append(f"| 프롬프트 풀 | {m['prompt_pool']['selected']:,} / {m['prompt_pool']['records_in_file']:,}건, "
             f"시드 `{m['prompt_pool']['selection_seed']}` |")
    L.append(f"| 소요 | {m['wall_sec'] / 3600:.2f}시간 |")
    L.append("")
    L.append("**과제 선택은 취향이 아니라 Cond-0 측정이 강제했다.** GRPO는 그룹 안의 표본이 전부 맞거나 "
             "전부 틀리면 어드밴티지가 0이 되어 기울기를 만들지 못한다. 따라서 베이스 정확도가 중간쯤인 "
             "과제가 필요하고, `cve_to_cwe`만이 그 조건을 만족한다.")
    L.append("")

    # ---- verifier
    v = m["verifier"]
    L.append("## 검증자")
    L.append("")
    L.append(f"보상은 결정론적 검사 두 개의 합이다 — 스키마 유효성과 `cwe_id` 완전 일치, 각각 "
             f"{v['range_per_component'][0]:.0f}에서 {v['range_per_component'][1]:.0f}.")
    L.append("")
    L.append(f"**컨테이너도 컴파일러도 서브프로세스도 쓰지 않는다**(`subprocess_used: {str(v['subprocess_used']).lower()}`). "
             "CVSS 샌드박스는 규격의 공식을 실제로 실행해야 하는 평가 쪽에 있고, 거기서는 수만 건을 한 번 채점한다. "
             "보상 루프는 스텝마다 수십 건을 채점하므로 항목당 1초짜리 검증자를 쓰면 실행이 끝나지 않는다.")
    L.append("")
    L.append(f"스키마 검사는 `{v['scorer_path']}`를 **수정 없이 가져다 쓴다**"
             f"(sha256 `{v['scorer_sha256'][:16]}…`). 보상이 평가와 다른 판정을 쓰면 "
             "한 과녁을 최적화하고 다른 과녁으로 재는 일이 된다.")
    L.append("")
    L.append("**두 성분은 로그까지 분리해서 기록한다.** 스키마 보상이 포화하는 동안 완전 일치 보상이 "
             "제자리인 것과 둘 다 오르는 것은 서로 다른 결과이고, 스칼라 하나로는 구분되지 않는다.")
    L.append("")

    # ---- what happened
    L.append("## 무엇이 일어났나")
    L.append("")
    L.append("첫 10%와 마지막 10% 스텝의 평균이다.")
    L.append("")
    L.append("| 지표 | 처음 | 마지막 | 변화 |")
    L.append("|---|---|---|---|")
    for label, a, b in (
        ("보상 합계", s["reward_total_first_decile"], s["reward_total_last_decile"]),
        ("보상 — 스키마", s["reward_schema_first_decile"], s["reward_schema_last_decile"]),
        ("보상 — 완전 일치", s["reward_exact_first_decile"], s["reward_exact_last_decile"]),
        ("생성 길이 (토큰)", s["completion_tokens_first_decile"], s["completion_tokens_last_decile"]),
    ):
        L.append(f"| {label} | {a:.3f} | {b:.3f} | {b - a:+.3f} |")
    L.append("")

    # ---- length drift, stated either way
    L.append("### 길이 드리프트")
    L.append("")
    d = s["completion_tokens_last_decile"] - s["completion_tokens_first_decile"]
    rel = d / s["completion_tokens_first_decile"] if s["completion_tokens_first_decile"] else 0.0
    if abs(rel) < 0.10:
        L.append(f"**드리프트 없음.** 평균 생성 길이가 {s['completion_tokens_first_decile']:.1f}토큰에서 "
                 f"{s['completion_tokens_last_decile']:.1f}토큰으로 {d:+.1f}토큰({rel:+.1%}) 움직였다. "
                 "장황해지는 방식의 보상 해킹은 이 실행에서 관측되지 않았다.")
    else:
        L.append(f"**드리프트가 있다.** 평균 생성 길이가 {s['completion_tokens_first_decile']:.1f}토큰에서 "
                 f"{s['completion_tokens_last_decile']:.1f}토큰으로 {d:+.1f}토큰({rel:+.1%}) 움직였다. "
                 "장황해지는 방식의 보상 해킹이 가장 먼저 나타나는 자리가 여기이며, "
                 "아래 고보상 표본 검사와 함께 읽어야 한다.")
    L.append("")
    L.append(f"상한에 닿은 생성의 최대 비율은 **{pct(s['truncated_fraction_max'])}**이다. "
             + ("상한이 길이 측정을 구속하지 않았으므로 위 수치는 드리프트 자체를 읽은 것이다."
                if s["truncated_fraction_max"] < 0.02 else
                "**상한이 구속하고 있다** — 위 길이 수치는 드리프트를 과소평가하며, 그만큼 신뢰할 수 없다."))
    L.append("")

    # ---- group collapse
    L.append("### 그룹 붕괴")
    L.append("")
    gc = s["group_collapse_fraction_mean"]
    L.append(f"그룹 안의 모든 롤아웃이 같은 점수를 받아 어드밴티지가 0이 된 비율은 "
             f"전체 평균 **{pct(gc)}**, 마지막 10% 구간 **{pct(s['group_collapse_fraction_last_decile'])}**이다.")
    L.append("")
    if gc > 0.5:
        L.append("**절반 이상의 그룹이 붕괴했다.** 스텝의 상당수가 아무것도 가르치지 않았다는 뜻이고, "
                 "이는 과제 선택이 여전히 적절하지 않았다는 신호다. 베이스 정확도가 중간이어도 "
                 "**항목별로는** 쉬운 것과 불가능한 것으로 갈려 있으면 그룹은 붕괴한다. "
                 "이 실행의 유효 스텝 수는 명목 스텝 수보다 작다.")
    elif gc > 0.25:
        L.append("붕괴율이 무시할 수준은 아니다. 명목 스텝 수의 일부는 기울기를 만들지 못했고, "
                 "유효 스텝 수는 그만큼 적다.")
    else:
        L.append("대부분의 그룹이 어드밴티지를 만들었다. 과제 선택의 전제 — 베이스 정확도가 중간일 것 — "
                 "가 실제로 성립했다.")
    L.append("")

    # ---- manual inspection
    if insp:
        L.append("## 고보상 출력을 직접 읽었다")
        L.append("")
        L.append(f"스키마와 완전 일치를 모두 받은 생성 {insp['n_full_reward']:,}건을 모아 두고, "
                 f"형태를 기계적으로 분류한 뒤 가장 최근 {insp['inspected']}건을 사람이 읽었다. "
                 "보상 곡선은 \"검증자를 속이지 않고 풀었는가\"에 답하지 못한다. 무엇이 보상을 받았는지 "
                 "보는 것만이 답한다.")
        L.append("")
        L.append("| 출력 형태 | 건수 | 비율 |")
        L.append("|---|---|---|")
        for k, n in sorted(insp["shapes"].items(), key=lambda kv: -kv[1]):
            L.append(f"| {k} | {n:,} | {pct(n / insp['n_full_reward'])} |")
        L.append("")
        L.append(f"토큰 길이 중앙값 {insp['token_length']['median']}, 평균 "
                 f"{insp['token_length']['mean']}, 최대 {insp['token_length']['max']}.")
        L.append("")
        if insp["bare_json_fraction"] > 0.95 and insp["long_fraction"] < 0.05:
            L.append("**찾은 것: 없다.** 만점을 받은 생성은 거의 전부 키 하나짜리 JSON 객체 그대로였고, "
                     "정답보다 크게 긴 것도 드물었다. 검증자를 만족시키면서 과제를 풀지 않는 경로는 "
                     "이 실행에서 나타나지 않았다. 이것은 **검증자가 견고하다는 증명이 아니라, "
                     "이 실행에서는 시도되지 않았다는 관측**이다.")
        else:
            L.append(f"**찾은 것이 있다.** 만점 생성 중 키 하나짜리 JSON 객체는 "
                     f"{pct(insp['bare_json_fraction'])}뿐이고, 정답 길이의 세 배를 넘는 것이 "
                     f"{pct(insp['long_fraction'])}다. 나머지가 어떤 형태였는지는 위 표에 있으며, "
                     "검증자가 과제를 풀지 않고도 만족될 수 있는 경로를 보여 준다.")
        L.append("")

    # ---- evaluation
    L.append("## 평가")
    L.append("")
    if cmp_rec is None:
        L.append("평가 기록이 아직 없다.")
    else:
        pair = None
        for k in cmp_rec["pairs"]:
            if "rlvr" in k and "cond2" in k:
                pair = k
                break
        L.append(f"P4 하니스를 **수정 없이** 돌려 얻은 결과를, 같은 시드의 Cond-2와 "
                 "짝지은 검정으로 비교한다.")
        L.append("")
        L.append("| 세트 | Cond-2 | RLVR | 차이 | 95% 구간 | Holm p | 판정 | 짝지은 MDD |")
        L.append("|---|---|---|---|---|---|---|---|")
        for k in sorted(cmp_rec["domain"]):
            cellrec = cmp_rec["domain"][k]
            if pair not in cellrec["pairs"]:
                continue
            p = cellrec["pairs"][pair]["accuracy"]
            pd = p["paired_difference"]
            a, b = p["marginal_b"], p["marginal_a"]
            L.append(f"| `{k}` | {pct(a['rate'])} | {pct(b['rate'])} "
                     f"| {100 * pd['diff']:+.1f}pp "
                     f"| [{100 * pd['ci95'][0]:+.1f}, {100 * pd['ci95'][1]:+.1f}]pp "
                     f"| {p['mcnemar_p_holm']:.3g} | {verdict_ko(p['verdict'])} "
                     f"| ±{100 * pd['mdd_points_paired']:.1f}pp |")
        L.append("")
        detected = [k for k in cmp_rec["domain"]
                    if pair in cmp_rec["domain"][k]["pairs"]
                    and cmp_rec["domain"][k]["pairs"][pair]["accuracy"]["verdict"] == "difference detected"]
        if detected:
            L.append("차이가 검출된 세트가 있다. 그러나 **시드 하나, 스텝 "
                     f"{m['steps_completed']}회의 결과**이며, P6 A1이 보인 대로 이 파이프라인에서 "
                     "도메인 과제의 조건 간 우열은 시드에 종속된다. 이 수치를 RLVR의 효과로 읽으려면 "
                     "최소한 두 번째 시드가 필요하고, 그것은 이 시연이 치르지 않은 비용이다.")
        else:
            L.append("**어느 세트에서도 차이가 검출되지 않았다.** 사전에 예상한 결과이며, "
                     f"스텝 {m['steps_completed']}회와 시드 하나로는 짝지은 MDD보다 작은 변화만 "
                     "만들 수 있다. 점 추정값이 양수인 칸이 있더라도 **효과로 제시하지 않는다.**")
        L.append("")

    # ---- what this did not show
    L.append("## 보이지 못한 것")
    L.append("")
    L.append("- **성능 향상.** 위 검정이 뒷받침하지 않는다. 이 시연의 목적도 아니다.")
    L.append(f"- **수렴.** 스텝 {m['steps_completed']}회는 GRPO가 수렴했는지 판단할 수 있는 길이가 아니다.")
    L.append("- **다른 과제로의 일반화.** `cvss_vector`와 `structured_extract`는 베이스 정확도가 "
             "낮아 그룹이 대부분 전부-틀림으로 붕괴한다. 이 구조가 그 과제들에서도 도는지는 "
             "측정하지 않았다.")
    L.append("- **검증자의 견고성.** 고보상 표본에서 해킹이 관측되지 않았다는 것은 "
             "시도되지 않았다는 뜻이지 불가능하다는 뜻이 아니다.")
    L.append("- **재현성.** 롤아웃은 온도를 0보다 크게 두므로 이 실행은 바이트 단위로 재현되지 않는다. "
             "시드·데이터 순서·체크포인트 해시는 기록되어 있으나, 평가 쪽 Gate 4와 같은 종류의 "
             "보장은 여기에 없다.")
    L.append("")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT}")
