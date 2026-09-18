# -*- coding: utf-8 -*-
"""Render docs/determinism.md (Korean) from env/gate0.json.

Generated rather than hand-written on purpose: this document's entire job is to
say what is and is not reproducible *on this machine*, and a hand-maintained
version drifts away from the measurement the first time anyone re-runs the gate.
The policy prose below branches on the measured result rather than assuming one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402


def _yn(v):
    return "예" if v is True else ("아니오" if v is False else "측정 안 됨")


def render(gate, out_path=None):
    c6 = (gate.get("checks", {}).get("06", {}) or {}).get("data", {}) or {}
    c5 = (gate.get("checks", {}).get("05", {}) or {}).get("data", {}) or {}
    rows = {(r["batch_invariant"], r["mode"]): r for r in (c6.get("summary_rows") or [])}
    seq_off = rows.get((False, "sequential"), {})
    con_off = rows.get((False, "concurrent"), {})
    seq_on = rows.get((True, "sequential"), {})
    con_on = rows.get((True, "concurrent"), {})
    cost = c6.get("batch_invariant_throughput_cost") or {}
    measured = bool(c6.get("summary_rows"))

    L = []
    L.append("# 재현성(결정성) — 이 프로젝트에서 무엇이 재현되고 무엇이 재현되지 않는가\n")
    L.append("> 이 문서는 `env/gate0.json`의 체크 06 결과로부터 **자동 생성**된다. "
             "손으로 고치지 말고 `make env-check` 또는 `make report`로 다시 만들 것.\n")

    if not measured:
        L.append("## 상태\n")
        L.append("아직 측정되지 않았다. `make env-check`를 실행해 체크 06을 완료해야 이 문서가 채워진다.\n")
        out = Path(out_path) if out_path else (C.REPO / "docs" / "determinism.md")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(L) + "\n", encoding="utf-8")
        return out

    s = c6.get("sampling", {})
    cfg = c6.get("vllm_config", {})

    L.append("## 0. 결론 먼저\n")
    L.append(f"- **순차 실행에서 그리디 디코딩은 바이트 단위로 재현되는가: {_yn(seq_off.get('byte_identical'))}**")
    L.append(f"- **동시 실행(배치 구성이 달라지는 상황)에서 재현되는가: {_yn(con_off.get('byte_identical'))}**")
    L.append(f"- **`VLLM_BATCH_INVARIANT=1`을 켜면 동시 실행에서도 재현되는가: {_yn(con_on.get('byte_identical'))}**")
    L.append("")

    L.append("## 1. 왜 그리디인데도 결과가 달라지는가\n")
    L.append("`temperature=0`은 **샘플링**의 무작위성만 제거한다. 매 스텝 argmax를 취하더라도, "
             "그 argmax에 들어가는 logit 값 자체가 비트 단위로 같아야 출력이 같아진다.\n")
    L.append("vLLM 같은 연속 배칭(continuous batching) 서버에서는 같은 프롬프트라도 "
             "**같이 묶여 들어간 다른 요청들**에 따라 배치 크기와 모양이 달라진다. "
             "배치 모양이 달라지면 GEMM 커널의 타일링·분할 전략이 바뀌고, 부동소수점 덧셈의 "
             "**리덕션 순서**가 바뀐다. 부동소수점 덧셈은 결합법칙이 성립하지 않으므로 "
             "(`(a+b)+c ≠ a+(b+c)`) logit의 최하위 비트가 흔들린다. "
             "두 후보 토큰의 logit이 충분히 가까운 지점에서 이 흔들림이 argmax를 뒤집으면, "
             "그 시점부터 생성은 완전히 다른 경로로 갈라진다.\n")
    L.append("따라서 이 문제는 **시드로 해결되지 않는다.** 시드는 이미 고정되어 있다. "
             "필요한 것은 배치 구성과 무관하게 동일한 리덕션 순서를 쓰는 커널, 즉 배치 불변 커널이다.\n")

    L.append("## 2. 측정 방법\n")
    L.append(f"- 모델: `{c6.get('model')}`")
    L.append(f"- vLLM 설정: `{cfg.get('name')}` (추가 인자 `{cfg.get('extra_args') or '없음'}`)")
    L.append(f"- 샘플링: `temperature={s.get('temperature')}`, `top_p={s.get('top_p')}`, "
             f"`seed={s.get('seed')}`, `max_tokens={s.get('max_tokens')}`")
    L.append(f"- **순차**: 동일 프롬프트를 한 번에 하나씩 {c6.get('repeats_per_round')}회, "
             f"{c6.get('rounds')} 라운드 반복 후 전부 바이트 비교")
    fillers = []
    for cell in (c6.get("matrix") or {}).values():
        fillers = (cell.get("concurrent") or {}).get("filler_prompts") or fillers
    L.append(f"- **동시**: 동일 프롬프트 {c6.get('repeats_per_round')}개를 동시에 발사하고, "
             f"여기에 무관한 필러 프롬프트 {len(fillers)}개를 함께 인플라이트로 넣어 "
             "라운드마다 배치 구성이 달라지도록 했다. 필러는 라운드마다 순서를 돌리고 길이도 다르게 주어 "
             "스케줄러가 실제로 다른 배치를 만들도록 강제했다.")
    L.append("")
    L.append("동시 실행 쪽이 본질이다. 배치 구성이 리덕션 순서를 바꾸고, 거기서 그리디 디코딩의 재현성이 무너진다.\n")

    L.append("## 3. 측정 결과 (4분면 전체)\n")
    L.append("| VLLM_BATCH_INVARIANT | 실행 모드 | 바이트 동일 | 서로 다른 출력 수 | 샘플 수 |")
    L.append("|---|---|---|---|---|")
    for (bi, mode), label in (
        ((False, "sequential"), ("0 (끔)", "순차")),
        ((False, "concurrent"), ("0 (끔)", "동시")),
        ((True, "sequential"), ("1 (켬)", "순차")),
        ((True, "concurrent"), ("1 (켬)", "동시")),
    ):
        r = rows.get((bi, mode), {})
        if r.get("samples"):
            L.append(f"| {label[0]} | {label[1]} | **{_yn(r.get('byte_identical'))}** | "
                     f"{r.get('distinct_outputs')} | {r.get('samples')} |")
        else:
            L.append(f"| {label[0]} | {label[1]} | 측정 실패 — {r.get('unmeasured_reason', '사유 미기록')} | - | 0 |")
    L.append("")

    if cost.get("slowdown_x"):
        L.append("### 배치 불변 커널의 비용\n")
        L.append(f"- 동시 라운드 벽시계 시간: {cost['concurrent_round_wall_off_sec']}초 → "
                 f"{cost['concurrent_round_wall_on_sec']}초 (**{cost['slowdown_x']}배**)")
        L.append(f"- 순차 평균 지연: {cost['sequential_latency_off_sec']}초 → {cost['sequential_latency_on_sec']}초")
        L.append("")

    L.append("## 4. 이 프로젝트의 정책\n")
    if con_on.get("byte_identical") is True and con_off.get("byte_identical") is not True:
        L.append("**평가 실행에는 `VLLM_BATCH_INVARIANT=1`을 켠다.** 동시 실행에서도 바이트 동일성이 "
                 "확보되는 것이 측정으로 확인되었다. 처리량 손해는 위 표에 적힌 만큼이며, "
                 "평가 결과가 재현되지 않는 쪽이 더 비싸다.")
        L.append("")
        L.append("- **평가·리포트 생성**: `VLLM_BATCH_INVARIANT=1`. 숫자가 재현되어야 한다.")
        L.append("- **개발 중 대화형 사용·대량 생성**: 꺼도 된다. 처리량을 택한다.")
    elif con_off.get("byte_identical") is True:
        L.append("이 장비/이 빌드에서는 **배치 불변 커널 없이도 동시 실행에서 바이트 동일성이 관측되었다.** "
                 "다만 이것은 보장이 아니라 관측이다. 배치 크기 상한, 모델, vLLM 버전이 바뀌면 다시 무너질 수 있으므로 "
                 "평가 파이프라인은 여전히 아래 규칙을 따른다.")
        L.append("")
        L.append("- 평가 결과를 기록할 때는 vLLM 버전·설정·`max_num_seqs`를 함께 기록한다.")
        L.append("- 스택을 올릴 때마다 체크 06을 다시 돌린다.")
    elif con_on.get("samples") == 0:
        L.append(f"**`VLLM_BATCH_INVARIANT=1`을 이 설정과 함께 쓸 수 없다.** "
                 f"사유: {con_on.get('unmeasured_reason')}")
        L.append("")
        L.append("둘 중 하나를 고르지 않고 두 선택지를 모두 남긴다. 어느 쪽을 택할지는 평가 작업지시서에서 결정한다.\n")
        L.append("- **선택지 A — 동시성을 포기한다.** 평가 실행을 `max_num_seqs=1`로 직렬화하면 "
                 "배치 구성이 항상 동일해지므로 배치 불변 커널 없이도 재현된다. 비용은 처리량이다.")
        L.append("- **선택지 B — 바이트 동일성을 포기하고 의미 동일성으로 내려간다.** 동시 실행을 유지하되, "
                 "평가 지표를 바이트 비교가 아니라 파싱된 JSON 필드 단위 비교로 정의하고, "
                 "같은 입력을 n회 반복해 지표의 분산을 함께 보고한다.")
    else:
        L.append("동시 실행에서 바이트 동일성이 확보되지 않았고, 배치 불변 커널로도 해결되지 않았다. "
                 "평가 지표는 바이트 비교가 아니라 파싱된 출력의 필드 단위 비교로 정의하고, "
                 "반복 실행의 분산을 함께 보고한다.")
    L.append("")

    L.append("## 5. 학습 쪽 재현성은 별개 문제다\n")
    L.append("위 내용은 전부 **추론** 이야기다. 학습의 재현성은 다른 축이며 이 게이트에서 측정하지 않았다. "
             "LoRA 학습을 비트 단위로 재현하려면 시드 고정만으로는 부족하고 "
             "(`torch.use_deterministic_algorithms(True)`, `CUBLAS_WORKSPACE_CONFIG`, "
             "데이터로더 워커 시드, 그래디언트 누적 순서까지 고정해야 하며 속도 손해가 있다) "
             "해당 결정은 학습 작업지시서에서 별도로 다룬다.\n")

    L.append("## 6. 재측정 방법\n")
    L.append("```bash\nmake env-check          # 전체 게이트\n"
             "python scripts/env_check/06_determinism.py   # 체크 06만\n"
             "make report             # gate0.json으로부터 보고서와 이 문서를 재생성\n```\n")
    L.append("스택(vLLM, torch, 모델)을 올릴 때마다 다시 돌려야 한다. 위 표의 값은 이 조합에 대해서만 유효하다.\n")

    out = Path(out_path) if out_path else (C.REPO / "docs" / "determinism.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    gate = json.loads((C.ENV_DIR / "gate0.json").read_text())
    print(render(gate))
