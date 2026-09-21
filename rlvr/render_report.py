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

import os

REPO = Path(__file__).resolve().parents[1]
# Overridable so the renderer can be exercised against fixtures before the run
# it renders exists. Defaults are the real paths; nothing else reads these.
RUN = Path(os.environ.get("RLVR_RUN_DIR") or (REPO / "runs" / "rlvr"))
OUT = Path(os.environ.get("RLVR_REPORT_OUT") or (REPO / "reports" / "rlvr.md"))


def pct(x) -> str:
    return f"{100 * x:.1f}%"


def load():
    m = json.loads((RUN / "train_manifest.json").read_text())
    rows = [json.loads(x) for x in (RUN / "reward_log.jsonl").read_text().splitlines() if x.strip()]
    insp = json.loads((RUN / "reward_inspection.json").read_text()) \
        if (RUN / "reward_inspection.json").exists() else None
    cmp_path = Path(os.environ.get("RLVR_COMPARE") or (REPO / "runs" / "compare_rlvr.json"))
    cmp_rec = json.loads(cmp_path.read_text()) if cmp_path.exists() else None
    prov = json.loads((RUN / "pool_provenance.json").read_text()) \
        if (RUN / "pool_provenance.json").exists() else None
    att = json.loads((RUN / "attempts.json").read_text()) \
        if (RUN / "attempts.json").exists() else None
    ent = [json.loads(x)["entropy"] for x in (RUN / "entropy.jsonl").read_text().splitlines()
           if x.strip()] if (RUN / "entropy.jsonl").exists() else []
    return m, rows, insp, cmp_rec, prov, ent, att


BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"


def spark(values, width=50) -> str:
    """A curve, binned to `width` columns. Shape is the point; the table below
    carries the numbers."""
    if not values:
        return ""
    step = max(1, len(values) / width)
    binned = []
    i = 0.0
    while int(i) < len(values):
        chunk = values[int(i): max(int(i) + 1, int(i + step))]
        binned.append(statistics.fmean(chunk))
        i += step
    lo, hi = min(binned), max(binned)
    if hi - lo < 1e-12:
        return BLOCKS[0] * len(binned)
    return "".join(BLOCKS[min(7, int(8 * (v - lo) / (hi - lo)))] for v in binned)


def axis(values, label, unit="") -> list:
    """First value to last, not min to max: a falling series must not be
    labelled as if it rose."""
    if not values:
        return []
    return [f"  {label:<22} {spark(values)}  {values[0]:.3f} \u2192 {values[-1]:.3f}{unit}"]


def verdict_ko(v: str) -> str:
    return "**차이 검출됨**" if v == "difference detected" else "차이 검출되지 않음"


def render() -> str:
    m, rows, insp, cmp_rec, prov, ent, att = load()
    s_ = m["summary"]
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

    # ---- (1) where the prompts came from
    if prov:
        o = prov["overlap"]
        L.append("## 프롬프트 풀의 출처")
        L.append("")
        L.append(f"롤아웃 프롬프트는 `{prov['pool_file']}`에서 뽑았다. 이 파일은 "
                 f"**출발 체크포인트 Cond-2가 학습한 바로 그 파일**이다. "
                 f"시드 `{prov['selection_seed']}`로 {prov['pool_size']:,}건을 "
                 f"{prov['file_size']:,}건 중에서 골랐다.")
        L.append("")
        L.append("| 겹침 | 건수 |")
        L.append("|---|---|")
        L.append(f"| Cond-2 학습 파일 안에 있는 풀 프롬프트 | **{o['cond2_training_file']:,} / {prov['pool_size']:,}** |")
        L.append(f"| Cond-1 학습 파일 안에 있는 풀 프롬프트 | {o['cond1_training_file']:,} / {prov['pool_size']:,} |")
        L.append(f"| 평가 세트(컷오프 이후)와 겹침 | {o['eval_post_cutoff']:,} |")
        L.append(f"| 평가 세트(컷오프 이전)와 겹침 | {o['eval_pre_cutoff']:,} |")
        L.append("")
        L.append("두 가지가 따라 나온다.")
        L.append("")
        L.append("- **아래 보상 곡선은 학습 데이터 위에서 측정된 것이다.** 출발 체크포인트가 이미 본 "
                 "프롬프트이므로, 보상이 오르는 것은 일반화의 증거가 아니라 본 것에 더 확실해졌다는 "
                 f"관측이다. Cond-2는 자기 데이터의 {prov['starting_checkpoint']['epoch_fraction']:.0%}를 "
                 "소비했으므로 풀의 대부분은 실제로 본 것이지만, 어느 항목이었는지는 패킹 순서에서 "
                 "복원되지 않는다.")
        L.append(f"- **평가 세트와는 한 건도 겹치지 않는다**({o['eval_post_cutoff']}건, "
                 f"{o['eval_pre_cutoff']}건). 뒤의 평가 비교는 이 프롬프트들로 오염되지 않았다. "
                 "이것은 설계가 아니라 확인이며, 확인했기 때문에 적는다.")
        L.append("")

        # ---- (2) the task-selection criterion was the wrong one
        ts = prov["task_selection_reference"]
        acc = ts["accuracy"]
        key_post = f"{m['task']}/eval_post_cutoff/constrained"
        key_pre = f"{m['task']}/eval_pre_cutoff/constrained"
        first = rows[: max(1, len(rows) // 10)]
        start_exact = statistics.fmean(r["reward_exact_mean"] for r in first)
        L.append("## 과제 선택 — 작업지시서가 든 근거는 틀렸다")
        L.append("")
        L.append(f"P6 작업지시서는 `{m['task']}`를 고른 근거로 **Cond-0의 정확도**를 들었다. "
                 "GRPO는 그룹이 전부 맞거나 전부 틀리면 어드밴티지가 0이 되므로 중간쯤의 정확도가 "
                 "필요하고, Cond-0 기준으로는 이 과제만 그 조건을 만족한다. 근거 자체는 맞다 — "
                 "**다만 잘못된 체크포인트의 정확도다.**")
        L.append("")
        L.append("| | 컷오프 이후 | 컷오프 이전 |")
        L.append("|---|---|---|")
        L.append(f"| Cond-0 (작업지시서가 본 수치) | {pct(acc['baseline'][key_post])} | {pct(acc['baseline'][key_pre])} |")
        L.append(f"| **Cond-2 (GRPO가 실제로 출발한 곳)** | **{pct(acc['cond2'][key_post])}** | **{pct(acc['cond2'][key_pre])}** |")
        L.append("")
        L.append(f"판단 기준이 되었어야 하는 것은 **출발 체크포인트가 실제로 롤아웃할 프롬프트에서 "
                 f"내는 정확도**다. 그 값은 이 실행의 처음 {len(first)}스텝 롤아웃에서 "
                 f"**{start_exact:.3f}**로 측정되었다(온도 {m['config']['temperature']}의 표본추출 기준). "
                 "Cond-0의 수치보다 높고, 학습 데이터라는 점까지 더하면 "
                 "그룹이 전부-정답으로 붕괴할 여지가 그만큼 크다.")
        L.append("")
        L.append("**이 오류는 작업지시서에서 왔고, 구현은 그대로 따랐다.** "
                 "`docs/engineering-rules.md` 규칙 6이 기록한 것과 같은 형태다 — "
                 "지시서에서 온 결함도 결함이며, 지시서를 따랐다는 것은 변명이 되지 않는다. "
                 "아래 그룹 붕괴 수치는 이 선택의 직접적 귀결이다.")
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
    L.append(f"| 소요 | {m['wall_sec'] / 3600:.2f}시간"
             + (f" ({m['wall_sec_note']})" if m.get("wall_sec_note") else "") + " |")
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
        ("보상 합계", s_["reward_total_first_decile"], s_["reward_total_last_decile"]),
        ("보상 — 스키마", s_["reward_schema_first_decile"], s_["reward_schema_last_decile"]),
        ("보상 — 완전 일치", s_["reward_exact_first_decile"], s_["reward_exact_last_decile"]),
        ("생성 길이 (토큰)", s_["completion_tokens_first_decile"], s_["completion_tokens_last_decile"]),
    ):
        L.append(f"| {label} | {a:.3f} | {b:.3f} | {b - a:+.3f} |")
    L.append("")

    # ---- (4) the curves
    L.append("### 스텝별 곡선")
    L.append("")
    L.append("```")
    L.extend(axis([r["reward_exact_mean"] for r in rows], "보상 — 완전 일치"))
    L.extend(axis([r["group_collapse_fraction"] for r in rows], "그룹 붕괴 비율"))
    L.extend(axis([r["group_reward_std_mean"] for r in rows], "그룹 내 보상 편차"))
    if ent:
        L.extend(axis(ent, "정책 엔트로피"))
    L.extend(axis([r["completion_tokens_mean"] for r in rows], "생성 길이(토큰)"))
    L.append("```")
    L.append("")
    band = max(1, len(rows) // 10)
    L.append("| 스텝 | 완전 일치 | 그룹 붕괴 | 그룹 내 편차 |"
             + (" 엔트로피 |" if ent else ""))
    L.append("|---|---|---|---|" + ("---|" if ent else ""))
    for i in range(0, len(rows), band):
        b = rows[i: i + band]
        row = (f"| {i + 1}–{i + len(b)} "
               f"| {statistics.fmean(x['reward_exact_mean'] for x in b):.3f} "
               f"| {statistics.fmean(x['group_collapse_fraction'] for x in b):.3f} "
               f"| {statistics.fmean(x['group_reward_std_mean'] for x in b):.3f} |")
        if ent:
            e = ent[i: i + band]
            if e:
                row += f" {statistics.fmean(e):.4f} |"
        L.append(row)
    L.append("")
    # peak of the exact-match reward, and what the collapse was doing there
    peaks = [(statistics.fmean(rows[i:i + band][j]["reward_exact_mean"]
                               for j in range(len(rows[i:i + band]))), i)
             for i in range(0, len(rows), band) if rows[i:i + band]]
    best, at = max(peaks)
    blk = rows[at: at + band]
    L.append(f"**보상은 {at + 1}–{at + len(blk)}스텝 구간에서 {best:.3f}로 정점을 찍는다.** "
             f"그 구간의 그룹 붕괴는 "
             f"{statistics.fmean(x['group_collapse_fraction'] for x in blk):.3f}, "
             f"마지막 구간에서는 "
             f"{statistics.fmean(x['group_collapse_fraction'] for x in rows[-band:]):.3f}이다. "
             "보상이 정점을 지나 내려오는 것과 붕괴가 올라가는 것은 같은 현상의 두 얼굴이다 — "
             "그룹이 만장일치가 되면 어드밴티지가 0이 되어 그 스텝은 아무것도 가르치지 않고, "
             "남은 기울기는 이미 확신한 방향을 더 뾰족하게 만드는 데만 쓰인다.")
    L.append("")

    # ---- length drift, stated either way
    L.append("### 길이 드리프트")
    L.append("")
    d = s_["completion_tokens_last_decile"] - s_["completion_tokens_first_decile"]
    rel = d / s_["completion_tokens_first_decile"] if s_["completion_tokens_first_decile"] else 0.0
    if abs(rel) < 0.10:
        L.append(f"**드리프트 없음.** 평균 생성 길이가 {s_['completion_tokens_first_decile']:.1f}토큰에서 "
                 f"{s_['completion_tokens_last_decile']:.1f}토큰으로 {d:+.1f}토큰({rel:+.1%}) 움직였다. "
                 "장황해지는 방식의 보상 해킹은 이 실행에서 관측되지 않았다.")
    else:
        L.append(f"**드리프트가 있다.** 평균 생성 길이가 {s_['completion_tokens_first_decile']:.1f}토큰에서 "
                 f"{s_['completion_tokens_last_decile']:.1f}토큰으로 {d:+.1f}토큰({rel:+.1%}) 움직였다. "
                 "장황해지는 방식의 보상 해킹이 가장 먼저 나타나는 자리가 여기이며, "
                 "아래 고보상 표본 검사와 함께 읽어야 한다.")
    L.append("")
    L.append(f"상한에 닿은 생성의 최대 비율은 **{pct(s_['truncated_fraction_max'])}**이다. "
             + ("상한이 길이 측정을 구속하지 않았으므로 위 수치는 드리프트 자체를 읽은 것이다."
                if s_["truncated_fraction_max"] < 0.02 else
                "**상한이 구속하고 있다** — 위 길이 수치는 드리프트를 과소평가하며, 그만큼 신뢰할 수 없다."))
    L.append("")

    # ---- (3) group collapse, three layers, not one
    L.append("### 그룹 붕괴 — 원인은 세 층이다")
    L.append("")
    gc = s_["group_collapse_fraction_mean"]
    band = max(1, len(rows) // 10)
    first_gc = statistics.fmean(x["group_collapse_fraction"] for x in rows[:band])
    last_gc = statistics.fmean(x["group_collapse_fraction"] for x in rows[-band:])
    L.append(f"그룹 안의 롤아웃 여덟 개가 모두 같은 점수를 받아 어드밴티지가 0이 된 비율은 "
             f"전체 평균 **{pct(gc)}**, 처음 구간 {pct(first_gc)}에서 마지막 구간 "
             f"**{pct(last_gc)}**까지 올라갔다. 그만큼의 스텝이 기울기를 만들지 못했다는 뜻이고, "
             "이 실행의 유효 스텝 수는 명목 스텝 수보다 상당히 작다.")
    L.append("")
    L.append("**원인을 하나로 돌리지 않는다.** 세 가지가 같은 방향으로 겹쳐 있고, "
             "이 실행만으로는 각각의 기여를 분리할 수 없다.")
    L.append("")
    L.append("**(a) 프롬프트가 출발 체크포인트에게 쉽다.** 풀은 Cond-2가 학습한 파일 그 자체이고"
             "(위 출처 절), 처음 구간의 완전 일치 보상이 이미 "
             f"{statistics.fmean(x['reward_exact_mean'] for x in rows[:band]):.3f}이다. "
             "이미 아는 문제에 여덟 번 답하면 여덟 개가 같은 답이 되기 쉽다. "
             "이것이 과제 선택 오류가 실제로 나타난 자리다.")
    L.append("")
    if ent:
        L.append(f"**(b) 과제의 출력 엔트로피가 원래 낮다.** 생성물은 "
                 f"`{{\"cwe_id\": \"CWE-NNN\"}}` 형태로 고정되어 있어 실제로 선택이 일어나는 "
                 f"토큰은 사실상 하나다. 정책 엔트로피는 **1스텝에서 이미 {ent[0]:.4f}**이며, "
                 "학습이 시작되기 전부터 낮다. 단일 결정 분류 과제에서 표본 여덟 개가 갈리려면 "
                 "모델이 그 하나의 결정에서 실제로 망설여야 하는데, 그런 항목은 많지 않다.")
        L.append("")
        L.append(f"**(c) KL 항이 없다(`beta: {m['config']['beta']}`).** 정책을 기준 모델 근처에 "
                 f"붙들어 두는 힘이 없으므로 분포는 계속 뾰족해진다. 엔트로피가 "
                 f"{ent[0]:.4f}에서 {statistics.fmean(ent[-band:]):.4f}로 "
                 f"{ent[0] / max(statistics.fmean(ent[-band:]), 1e-9):.1f}배 줄어든 것이 그 궤적이다. "
                 "이 설정은 내가 골랐고, 대가는 여기 나타났다.")
    else:
        L.append(f"**(b) 과제의 출력 엔트로피가 원래 낮다.** 생성물이 고정된 JSON 형태여서 "
                 "실제 선택이 일어나는 토큰이 사실상 하나다.")
        L.append("")
        L.append(f"**(c) KL 항이 없다(`beta: {m['config']['beta']}`).** 정책을 기준 근처에 "
                 "붙들어 두는 힘이 없어 분포가 계속 뾰족해진다.")
    L.append("")
    L.append("**(c)만으로 귀속하는 것은 틀린 설명이다.** KL 항을 켰다면 엔트로피 감소는 느려졌겠지만, "
             "(a)와 (b)는 그대로 남는다 — 이미 학습한 쉬운 프롬프트에서 단일 결정 과제의 "
             "여덟 표본이 갈리게 만들지는 못한다. 반대로 (a)만 고쳤어도 (c)는 남는다. "
             "**세 층을 분리하려면 각각을 바꾼 실행이 필요하고, 이 시연은 그것을 하지 않았다.**")
    L.append("")
    if gc > 0.5:
        L.append(f"결론적으로 **과제 선택은 이 출발점에 대해 적절하지 않았다.** "
                 f"Cond-0 기준으로는 중간 난이도였지만 Cond-2 기준으로는 아니었고, "
                 f"붕괴율 {pct(gc)}는 그 사실의 직접적 측정이다.")
    else:
        L.append("붕괴율이 절반을 넘지는 않았다. 대부분의 스텝은 어드밴티지를 만들었다.")
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

    # ---- the attempt that did not produce this checkpoint
    if att and (att.get("attempt_1") or att.get("attempt_2")):
        L.append("## 이 체크포인트를 만들지 못한 시도")
        L.append("")
        L.append("위 수치는 세 번째 실행의 것이다. 앞의 두 번은 지우지 않고 남겼다.")
        L.append("")
        a1 = att.get("attempt_1")
        if a1:
            L.append(f"### 1차 — 학습 {a1['steps_logged']}스텝을 마친 뒤 저장 단계에서 죽었다")
            L.append("")
            L.append(f"종료 코드 {a1['exit_code']}"
                     + (f"(시그널 {a1['signal']}, SIGKILL)" if a1.get("signal") else "")
                     + f". 학습 자체는 {a1['train_runtime_sec'] / 3600:.2f}시간 동안 정상적으로 "
                     f"끝났고, 죽은 지점은 **{a1['died_at']}**이다.")
            L.append("")
            L.append("**원인**: `merge_and_unload()`가 살아 있는 트레이너 위에 — 가중치, "
                     "옵티마이저 상태, 생성 버퍼가 모두 상주한 채로 — 모델 전체 사본을 하나 더 "
                     "만들고, 샤드를 쓰는 도중 메모리 상한에 걸렸다. 모든 학습 스텝이 끝난 "
                     "**뒤**였다.")
            L.append("")
            L.append("**고친 방식**: 학습 직후 어댑터와 매니페스트를 먼저 쓰고, 그 사이에 실패할 "
                     "수 있는 작업을 두지 않는다. 병합은 학습 상태가 사라진 별도 프로세스에서 "
                     "하고, 어댑터 체크포인트를 50스텝마다 남긴다. "
                     "(영문 원문은 `runs/rlvr/attempts.json`의 `cause`·`fix` 필드에 있다.)")
            L.append("")
            L.append("**메모리 상한을 올리지 않았다.** 올려서 통과시키는 것은 결함을 가리는 것이고, "
                     "결함은 상한이 낮다는 것이 아니라 **값비싼 산출물을 값싼 것보다 늦게 "
                     "저장했다**는 것이다. 두 시간이 저장 단계에서 사라졌다. "
                     "`docs/engineering-rules.md` 규칙 7이 이 사건에서 나왔다.")
            L.append("")
        a2 = att.get("attempt_2")
        if a2:
            L.append(f"### 2차 — {a2['steps_logged']}스텝에서 호스트가 재부팅됐다")
            L.append("")
            L.append("**이쪽은 이 코드의 결함이 아니다.** 전원 또는 호스트 수준의 사건이었고, "
                     "같은 사이트의 리눅스 두 대가 동시에 테일넷에서 사라졌다. 종료 표식은 "
                     "기록되지 않았다. 근거는 보상 로그가 중간에서 멈춘 것, 아래 부팅 시각이 "
                     "실행 시작보다 몇 시간 뒤라는 것, 그리고 학습 로그가 있던 `/tmp`가 그 뒤 "
                     "비어 있었다는 것이다. **로그 파일의 mtime은 근거가 아니다** — 보존하지 않고 "
                     "복사했으므로, 뒷받침할 수 없는 주장은 하지 않는다.")
            L.append("")
            L.append("**복구**: 1차 이후 추가한 50스텝 간격 어댑터 체크포인트에서 재개했다. "
                     "옵티마이저·스케줄러·RNG 상태가 복원되었고, 텍스트 로그가 사라진 뒤의 "
                     "앞 절반 엔트로피 계열은 체크포인트의 `trainer_state.json`에서 복구했다. "
                     f"재개에 사용한 체크포인트는 `{m.get('resumed_from')}`이고"
                     f"(학습 매니페스트의 `resumed_from`에 기록), 호스트 부팅 시각은 "
                     f"`{a2['host_booted_at']}`이다. 현재 디스크에 남아 있는 체크포인트는 "
                     + ", ".join(f"`{c}`" for c in a2.get("checkpoints_present_now", []))
                     + "이며, 이는 재개 이후 새로 쓰이고 오래된 것이 정리된 결과다 — "
                     "복구 시점의 목록이 아니다.")
            L.append("")
            L.append("**1차의 수정이 2차를 구했다.** 50스텝 간격 어댑터 체크포인트는 저장 순서 "
                     "결함을 고치며 넣은 보험이었고, 그것이 없었다면 정전으로 두 번째 실행도 "
                     "통째로 사라졌을 것이다.")
            L.append("")
        L.append("두 시도의 보상 로그는 `runs/rlvr_attempt1/`과 `runs/rlvr_attempt2_partial/`에 있다.")
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
