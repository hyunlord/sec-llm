# -*- coding: utf-8 -*-
"""Render reports/env-report.md (Korean) from env/gate0.json.

The report has to stand on its own: someone who was not present must be able to
act on it without opening the JSON. So every claim here carries its number or
its verbatim error text.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

MARK = {"pass": "✅ 통과", "warn": "⚠️ 경고", "fail": "❌ 실패", "missing": "⛔ 미실행"}

CHECK_TITLES_KO = {
    "01": "장비 인벤토리",
    "02": "torch ABI 스모크",
    "03": "어텐션 백엔드 (sdpa vs flash_attention_2)",
    "04": "생성 정상성",
    "05": "vLLM 서빙",
    "06": "재현성 (결정성)",
    "07": "LoRA 스텝 비용",
    "08": "샌드박스 프로브",
}


def _fence(text, lang=""):
    if not text:
        return "_(없음)_"
    return f"```{lang}\n{str(text).rstrip()}\n```"


def _yn(v):
    if v is True:
        return "예"
    if v is False:
        return "아니오"
    return "측정 안 됨"


VERDICT_KO = {
    "occurred": "발생함",
    "did_not_occur": "발생하지 않음",
    "unknown": "판정 불가",
    "unavailable_no_wheel": "해당 없음 — 사용 자체가 불가",
    "kernel_unsupported_on_sm121": "발생함 (커널 수준 실패)",
    "loads_but_output_corrupted": "발생함 (출력 손상)",
    "worked": "발생하지 않음",
    "failed_other": "판정 불가 (예상 밖 실패)",
}


def _v(verdict):
    """Plain label. The call sites wrap the whole `판정: ...` phrase in bold."""
    return VERDICT_KO.get(verdict, str(verdict))


def _failure_modes_section(fm):
    L = []
    L.append("## 1. 알려진 4대 실패 모드 — 이 장비에서의 판정\n")
    L.append("각 항목은 **그 판정을 담당하는 체크가 실제로 실행되어 증거를 만들어낸 경우에만** 판정을 적는다. "
             "설치가 성공했다거나 옆 체크가 통과했다는 것은 증거가 아니며, 증거가 없으면 '판정 불가'라고 적는다.\n")

    # ---- (1) CUDA 12 wheel on CUDA 13 runtime --------------------------
    a = fm.get("cuda12_wheel_on_cuda13_runtime", {})
    ev = a.get("evidence", {})
    L.append("### (1) CUDA 12 대상 휠을 CUDA 13 런타임에 올렸을 때의 segfault / `undefined symbol`\n")
    L.append(f"- **판정: {_v(a.get('verdict'))}** (체크 02)")
    if a.get("reason"):
        L.append(f"- 사유: {a['reason']}")
    if ev:
        L.append(f"- torch `{ev.get('torch')}` (링크된 CUDA 런타임 `{ev.get('cuda_runtime_linked')}`), 드라이버 `{ev.get('driver')}`")
        L.append(f"- torch가 담고 있는 아키텍처: `{ev.get('arch_list')}`")
        L.append(f"- 실제 디바이스 `{ev.get('device_sm')}` — 네이티브 cubin 포함 여부: **{_yn(ev.get('device_sm_in_arch_list'))}**, "
                 f"PTX 항목: **{ev.get('ptx_entries') or '없음'}**")
        L.append("")
        L.append(f"**아키텍처 호환 방식: `{ev.get('compat_mode')}`**")
        L.append("")
        L.append(f"> {ev.get('compat_explanation')}")
        L.append("")
        num = ev.get("numeric") or []
        if num:
            L.append("**수치 정확도 (fp64 CPU 기준값 대비)**")
            L.append("")
            L.append("| dtype | 통과 | 최대 절대오차 | 최대 상대오차 | 허용 상대오차 |")
            L.append("|---|---|---|---|---|")
            for d in num:
                if d.get("error"):
                    L.append(f"| `{d.get('dtype')}` | ❌ | — | — | `{d.get('error')}` |")
                else:
                    L.append(f"| `{d.get('dtype')}` | {'✅' if d.get('ok') else '❌'} | "
                             f"{d.get('max_abs_err'):.4g} | {d.get('max_rel_err'):.4g} | {d.get('rel_tolerance')} |")
            L.append("")
        fc = ev.get("first_call") or {}
        if fc and not fc.get("error"):
            L.append(f"- **첫 커널 호출 지연**: 컨텍스트 생성 {fc.get('context_init_sec')}초, "
                     f"첫 matmul {fc.get('first_matmul_sec')}초, 두 번째 matmul {fc.get('second_matmul_sec')}초 "
                     f"({fc.get('first_call_overhead_x')}배)")
            fx = ev.get("first_call_explanation") or {}
            if fx:
                L.append(f"  - 원인 귀속: **`{fx.get('attribution')}`** — {fx.get('detail','')}")
        tp = ev.get("throughput") or {}
        if tp.get("achieved_tflops_bf16"):
            L.append(f"- **실측 bf16 GEMM 처리량: {tp['achieved_tflops_bf16']} TFLOPS** "
                     f"(참고치 {tp['reference_tflops_bf16_dense']} TFLOPS의 {tp['fraction_of_reference']:.1%}). "
                     + ("⚠️ 큰 미달 — 커널 선택이 일반 경로로 떨어지고 있을 수 있다."
                        if tp.get("large_shortfall") else "일반 경로 폴백 정황은 없다."))
            L.append(f"  - 참고치 근거: {tp.get('reference_basis')}")
        warns = ev.get("first_op_warnings")
        if warns:
            L.append("- 첫 디바이스 연산 중 CUDA가 내보낸 커널/PTX 경고(원문):")
            L.append(_fence("\n".join(warns)))
        else:
            L.append("- 첫 디바이스 연산 중 `no kernel image` / PTX JIT 관련 메시지: 없음")
    L.append("")
    if a.get("verdict") == "did_not_occur":
        L.append("- **대응**: PyTorch `cu130` 휠 인덱스(`UV_TORCH_BACKEND=cu130`)로 설치한 환경에서 "
                 "fp32·bf16 디바이스 연산이 모두 fp64 기준값과 허용오차 내로 일치했다. "
                 "이후 단계에서 torch를 PyPI 기본 인덱스로 재설치하지 말 것 — `env/versions.lock`의 `+cu130` 빌드를 유지한다.")
        if ev.get("compat_mode") == "family_binary_compat":
            L.append("- **재검증 의무**: 이 빌드에는 PTX 폴백이 없다. 즉 네이티브 cubin도 PTX도 없이 "
                     "Blackwell 계열 바이너리 호환성에 의존하고 있으므로, torch나 CUDA를 올릴 때마다 "
                     "**체크 02를 반드시 다시 돌린 뒤** 신뢰할 것.")
    elif a.get("verdict") == "occurred":
        L.append("- **대응**: 환경을 CUDA 13 대상 휠로 재구성한다. 개별 패키지 핀으로 우회하지 않는다.")
    L.append("")

    # ---- (2) flash-attn -------------------------------------------------
    b = fm.get("flash_attn_no_sm121_kernel", {})
    ev = b.get("evidence", {})
    L.append("### (2) `flash-attn`이 Blackwell sm_121용 커널을 제공하지 않음\n")
    L.append(f"- **판정: {_v(b.get('verdict'))}** (체크 03)")
    if b.get("claim"):
        L.append(f"- {b['claim']}")
    if ev:
        L.append(f"- flash-attn import 가능 여부: **{_yn(ev.get('installed'))}**, 실패 분류: `{ev.get('failure_class')}`")
        wp = ev.get("wheel_probe") or {}
        if wp:
            L.append(f"- 사전 빌드 휠 존재 여부(해석 전용, 다운로드·빌드 없음): **{_yn(wp.get('wheel_available'))}** — {wp.get('verdict')}")
            L.append(f"  - 사용한 명령: `{wp.get('method')}`")
            if wp.get("stderr") or wp.get("stdout"):
                L.append("  - 리졸버 출력:")
                L.append(_fence((wp.get("stderr") or wp.get("stdout"))[:1200]))
        if ev.get("error"):
            L.append("- transformers가 낸 오류(원문):")
            L.append(_fence(ev["error"]))
        if ev.get("corrupted"):
            L.append("- 로드는 되었으나 출력이 손상되었다:")
            L.append(_fence(ev.get("output_sample")))
    L.append("")
    if b.get("verdict") == "unavailable_no_wheel":
        L.append("> ⚠️ **증거의 한계를 분명히 한다.** 이것은 *가용성* 판정이지 *커널 동작* 판정이 아니다. "
                 "flash-attn 2.x가 sm_121에서 올바른 출력을 내는지는 **시험하지 않았고**, 그에 대한 판정을 내리지 않는다. "
                 "시험하려면 학습 호스트에서 소스 빌드를 해야 하는데, 그것은 이 프로젝트가 금지한 행위다(아래 사건 참조).")
        L.append("")
    inc = ev.get("source_build_incident") or {}
    if inc:
        L.append("**기록: 소스 빌드 시도 사건**")
        L.append("")
        L.append(f"- 일자: {inc.get('date')}")
        L.append(f"- 무엇을 했나: {inc.get('what')}")
        L.append(f"- 결과: {inc.get('outcome')}")
        L.append(f"- 왜 플랫폼에 대한 증거인가: {inc.get('why_it_matters')}")
        L.append(f"- 채택한 규칙: {inc.get('rule_adopted')}")
        L.append("")
        L.append("자세한 내용은 `docs/hardware-notes.md` 참조.")
        L.append("")
    L.append(f"- 이 체크가 무언가를 컴파일했는가: **{_yn(ev.get('compiled_anything'))}**")
    L.append("- **대응**: 학습과 HF 추론 모두 `attn_implementation=\"sdpa\"`로 고정한다. "
             "체크 03의 결과와 무관하게 이것이 프로젝트 기본값이며, 체크는 그 이유를 기록할 뿐 결정하지 않는다.")
    L.append("")

    # ---- (3) vLLM graph capture ----------------------------------------
    c = fm.get("vllm_cuda_graph_capture_fails", {})
    ev = c.get("evidence", {})
    L.append("### (3) aarch64 + CUDA 13 빌드에서 vLLM의 CUDA 그래프 캡처 실패\n")
    L.append(f"- **판정: {_v(c.get('verdict'))}** (체크 05)")
    if c.get("reason"):
        L.append(f"- 사유: {c['reason']}")
    if ev:
        L.append(f"- 기본 설정(그래프 캡처 켜짐) 준비 완료: **{_yn(ev.get('default_ready'))}**"
                 + (f" — {ev.get('default_startup_result')}" if ev.get("default_startup_result") else ""))
        L.append(f"- `--enforce-eager`(그래프 캡처 꺼짐) 준비 완료: **{_yn(ev.get('enforce_eager_ready'))}**")
        if ev.get("default_log_tail"):
            L.append("- 기본 설정 실패 시 기동 로그 꼬리:")
            L.append(_fence(ev["default_log_tail"]))
    L.append("")

    # ---- (4) determinism ------------------------------------------------
    d = fm.get("greedy_not_byte_reproducible_under_concurrency", {})
    ev = d.get("evidence", {})
    L.append("### (4) 배치 불변 커널 없이는 그리디 디코딩이 바이트 단위로 재현되지 않음\n")
    L.append(f"- **판정: {_v(d.get('verdict'))}** (체크 06)")
    if d.get("reason"):
        L.append(f"- 사유: {d['reason']}")
    if ev:
        L.append(f"- 순차 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **{_yn(ev.get('sequential_byte_identical_bi_off'))}**")
        L.append(f"- 동시 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **{_yn(ev.get('concurrent_byte_identical_bi_off'))}**")
        L.append(f"- 동시 / `VLLM_BATCH_INVARIANT=1` — 바이트 동일: **{_yn(ev.get('concurrent_byte_identical_bi_on'))}**"
                 + (f" ({ev.get('concurrent_bi_on_unmeasured_reason')})" if ev.get("concurrent_bi_on_unmeasured_reason") else ""))
        t = ev.get("throughput_cost")
        if t and t.get("slowdown_x"):
            L.append(f"- 배치 불변 커널의 처리량 비용: 동시 라운드 벽시계 {t['concurrent_round_wall_off_sec']}초 → "
                     f"{t['concurrent_round_wall_on_sec']}초 (**{t['slowdown_x']}배**)")
    L.append("- 자세한 내용과 프로젝트 정책은 `docs/determinism.md` 참조.")
    L.append("")
    return L


def render(gate, out_path=None):
    s = gate["summary"]
    checks = gate["checks"]
    head = s.get("headline", {})
    L = []

    L.append("# P0 환경 검증 보고서 (Gate 0)\n")
    L.append(f"- 대상 장비: **{s.get('host')}** (DGX Spark, GB10 Grace-Blackwell)")
    L.append(f"- 대상 모델: `{s.get('model')}`")
    L.append(f"- 생성 시각: {s.get('generated_at')}")
    L.append(f"- **게이트 통과 여부: {'✅ 통과' if s.get('gate_passed') else '❌ 미통과'}**\n")

    L.append("## 0. 한 문단 요약\n")
    gpu = head.get("gpu") or "GPU"
    L.append(
        f"{gpu}({head.get('compute_capability')}) 위에서 torch `{head.get('torch')}` / CUDA "
        f"`{head.get('cuda_runtime')}` 스택이 정상 동작한다. "
        + (f"vLLM은 `{head.get('vllm_default_config')}` 설정으로 서빙 가능하다. " if head.get("vllm_default_config") else "")
        + (
            f"LoRA 학습은 옵티마이저 스텝당 **{head.get('sec_per_optimizer_step')}초**, "
            f"**{head.get('tokens_per_second')} tokens/s**, 최대 할당 메모리 **{head.get('peak_allocated_gib')} GiB**로 측정되었다. "
            if head.get("sec_per_optimizer_step")
            else ""
        )
        + (
            "이를 근거로 1 에폭 소요 시간은 "
            + ", ".join(f"{int(k):,}건 → 약 {v}시간" for k, v in (head.get("epoch_hours") or {}).items())
            + "로 추정된다. "
            if head.get("epoch_hours")
            else ""
        )
        + f"작업 볼륨 여유 공간은 {head.get('free_disk_gib')} GiB다."
    )
    L.append("")

    L.append("## 체크 결과 한눈에 보기\n")
    L.append("| # | 체크 | 결과 | 소요(초) |")
    L.append("|---|------|------|----------|")
    for cid in sorted(checks):
        r = checks[cid]
        L.append(
            f"| {cid} | {CHECK_TITLES_KO.get(cid, r['name'])} | {MARK.get(r['status'], r['status'])} | "
            f"{r.get('runner_duration_sec') or r.get('duration_sec')} |"
        )
    L.append("")

    L.append("### Gate 0 통과 조건 대조\n")
    L.append("| 체크 | 요구 조건 | 상태 | 충족 |")
    L.append("|------|-----------|------|------|")
    for cid, v in (s.get("gate_requirements") or {}).items():
        L.append(f"| {cid} | {v['requirement']} | {MARK.get(v['status'], v['status'])} | {'✅' if v['met'] else '❌'} |")
    L.append("")

    # --- safeguards ------------------------------------------------------
    sg = s.get("safeguards") or {}
    if sg:
        L.append("## 0.5. 안전장치가 실제로 작동하는가 — 측정 결과\n")
        L.append("설정만 되어 있고 강제되지 않는 안전장치는 없는 것보다 나쁘다. "
                 "보호 장치처럼 읽히는 가정 위에 하네스 전체가 세워지기 때문이다. 그래서 측정했다.\n")
        mc = sg.get("memory_ceiling", {})
        ev = mc.get("evidence", {})
        L.append(f"### 메모리 상한이 살아 있는가: **{'예 — 강제됨' if mc.get('enforced') else '아니오'}** (`{mc.get('verdict')}`)\n")
        L.append(f"- 1 GiB 스코프 안에서 2 GiB 할당 → 종료 코드 `{ev.get('scope_returncode')}` (137 = SIGKILL)")
        L.append(f"- 대조군(스코프 없이 동일 할당) 성공: **{_yn(ev.get('control_succeeded'))}**")
        L.append(f"- 스코프 내부 `memory.max` 실측값: `{ev.get('memory_max_inside_scope')}`")
        L.append(f"- 해석: {mc.get('interpretation')}\n")
        cc = sg.get("cgroup_coverage", {})
        L.append(f"### 이 상한이 무엇을 덮는가: **`{cc.get('verdict')}`**\n")
        L.append(f"- CUDA 디바이스 할당도 cgroup에 계상되는가: **{_yn(cc.get('covers_device_memory'))}**")
        L.append(f"- 해석: {cc.get('interpretation')}\n")
        nb = sg.get("no_source_build", {})
        L.append(f"### 소스 빌드 금지 강제: **{_yn(nb.get('active'))}**\n")
        L.append(f"- `PIP_ONLY_BINARY={nb.get('PIP_ONLY_BINARY')!r}`, 저장소 `pip.conf` 존재: {_yn(nb.get('repo_pip_conf_present'))}")
        L.append("- grep으로는 이것을 증명할 수 없다. pip는 소스 배포본을 만나면 빌드하고, 우리 코드의 "
                 "어떤 문자열도 그 사실을 말해주지 않는다. 그래서 환경에서 강제한다.\n")
        oom = sg.get("oom_protection") or {}
        L.append(f"### 사용자 공간 OOM 데몬: **{_yn(oom.get('userspace_oom_daemon'))}**\n")
        L.append(f"- `systemd-oomd`: `{oom.get('systemd_oomd_active')}`, `earlyoom` 설치됨: {_yn(oom.get('earlyoom_present'))}")
        L.append("")

    L.extend(_failure_modes_section(s.get("known_failure_modes", {})))

    L.append("## 2. 체크별 상세\n")

    c1 = checks.get("01", {}).get("data", {})
    if c1:
        L.append("### 01 — 장비 인벤토리\n")
        h, t = c1.get("host", {}), c1.get("torch", {})
        L.append(f"- 아키텍처 `{h.get('machine')}`, 커널 `{h.get('kernel')}`, CPU {h.get('cpu_count')} 코어")
        L.append(f"- GPU: `{c1.get('gpu_query')}`")
        L.append(f"- torch `{t.get('version')}` / CUDA 런타임 `{t.get('cuda_runtime_linked')}` / cuDNN `{t.get('cudnn')}`")
        L.append(f"- 컴퓨트 능력 `{t.get('compute_capability')}`, GPU 가시 메모리 `{t.get('memory')}`")
        L.append(f"- 호스트 메모리(GiB): `{c1.get('host_memory_gib')}`")
        d = c1.get("disk", {})
        L.append(f"- **여유 디스크**: 저장소 볼륨 {d.get('repo', {}).get('free_gib')} GiB, "
                 f"HF 캐시 볼륨 {d.get('hf_cache', {}).get('free_gib')} GiB "
                 f"(7B 베이스 + LoRA 3회분 기준 여유 {'충분' if c1.get('disk_headroom_ok') else '부족'})")
        L.append(f"- Docker: `{c1.get('docker_version')}`")
        L.append("")

    c2 = checks.get("02", {}).get("data", {})
    if c2:
        L.append("### 02 — torch ABI 스모크\n")
        L.append(f"- 디바이스: `{c2.get('device_name')}` `{c2.get('device_sm')}`, "
                 f"torch `{c2.get('torch_version')}` / CUDA `{c2.get('cuda_runtime_linked')}` / 드라이버 `{c2.get('driver_version')}`")
        L.append(f"- `get_arch_list()`: `{c2.get('arch_list')}`")
        L.append(f"- PTX(`compute_*`) 항목: **{c2.get('ptx_entries') or '없음'}** → 호환 방식 `{c2.get('compat_mode')}`")
        L.append(f"- 정확도 검증 행렬 크기: {c2.get('correctness_matrix_size')}×{c2.get('correctness_matrix_size')}, "
                 "디바이스 결과를 **fp64 CPU 기준값**과 비교")
        L.append("")
        L.append("| dtype | 통과 | 최대 절대오차 | 최대 상대오차 | 허용 상대오차 | 디바이스 matmul | fp64 CPU 기준 |")
        L.append("|---|---|---|---|---|---|---|")
        for r in c2.get("dtypes", []):
            if r.get("error"):
                L.append(f"| `{r['dtype']}` | ❌ | — | — | — | — | `{r['error']}` |")
                continue
            L.append(f"| `{r['dtype']}` | {'✅' if r.get('ok') else '❌'} | {r.get('max_abs_err'):.4g} | "
                     f"{r.get('max_rel_err'):.4g} | {r.get('rel_tolerance')} | "
                     f"{r.get('device_matmul_sec')}초 | {r.get('cpu_reference_sec')}초 |")
        L.append("")
        for r in c2.get("dtypes", []):
            if r.get("aux_ops"):
                L.append(f"- `{r['dtype']}` 보조 연산(softmax·layer_norm·리덕션·D2H): `{r['aux_ops']}`")
        fc = c2.get("first_call") or {}
        if fc and not fc.get("error"):
            L.append(f"- 첫 호출 지연: 컨텍스트 {fc.get('context_init_sec')}초 / 첫 matmul {fc.get('first_matmul_sec')}초 "
                     f"/ 두 번째 {fc.get('second_matmul_sec')}초 ({fc.get('first_call_overhead_x')}배), "
                     f"JIT 정황 {_yn(fc.get('suggests_jit_compile'))}")
        tp = c2.get("throughput") or {}
        if tp.get("achieved_tflops_bf16"):
            L.append(f"- 정상상태 bf16 처리량: **{tp['achieved_tflops_bf16']} TFLOPS** "
                     f"({tp['matrix_size']}×{tp['matrix_size']}, 워밍업 {tp['warmup']} 후 {tp['iterations']}회 평균 "
                     f"{tp['sec_per_matmul']}초) — 참고치의 {tp['fraction_of_reference']:.1%}")
        elif tp.get("error"):
            L.append(f"- 처리량 측정 실패: `{tp['error']}`")
        if c2.get("first_op_stderr"):
            L.append("- 첫 디바이스 연산 중 캡처된 stderr(fd 2, 원문):")
            L.append(_fence(c2["first_op_stderr"][:2000]))
        L.append(f"- 최대 할당 메모리: {c2.get('peak_allocated_gib')} GiB")
        L.append("")

    c3 = checks.get("03", {}).get("data", {})
    if c3:
        L.append("### 03 — 어텐션 백엔드\n")
        L.append(f"- 이 체크가 컴파일한 것: **{_yn(c3.get('compiled_anything'))}**")
        wp = c3.get("wheel_probe") or {}
        if wp:
            L.append(f"- 사전 빌드 휠 해석(다운로드 {_yn(wp.get('downloaded'))}, 빌드 {_yn(wp.get('built'))}): "
                     f"**{_yn(wp.get('wheel_available'))}** — {wp.get('verdict')}")
        L.append(f"- 최종 판정: `{c3.get('flash_attn_verdict')}`")
        L.append("")
        for impl in ("sdpa", "flash_attention_2"):
            r = c3.get(impl, {})
            L.append(f"**`{impl}`**")
            L.append(f"- 로드 성공: {_yn(r.get('loaded'))}, 생성 성공: {_yn(r.get('generated'))}"
                     + (f", 실패 분류 `{r.get('failure_class')}`" if r.get("failure_class") and r.get("failure_class") != "none" else ""))
            if r.get("error"):
                L.append("- 오류(그대로):")
                L.append(_fence(r["error"]))
            else:
                L.append(f"- 실제 적용된 구현: `{r.get('resolved_impl')}`, 손상 판정: {_yn(r.get('corrupted'))}")
                L.append("- 출력:")
                L.append(_fence(r.get("output")))
            L.append("")

    c4 = checks.get("04", {}).get("data", {})
    if c4:
        L.append("### 04 — 생성 정상성 (sdpa, 그리디 128토큰)\n")
        L.append(f"- 정상 출력 {c4.get('clean_count')}/{c4.get('total_count')}건")
        L.append("")
        L.append("| 프롬프트 | 언어 | 손상 | 치환·제어문자 비율 | 최장 반복 n-gram |")
        L.append("|---|---|---|---|---|")
        for g in c4.get("generations", []):
            m = g.get("metrics", {})
            L.append(f"| `{g['id']}` | {g['lang']} | {_yn(g['corrupted'])} | {m.get('ratio_bad')} | {m.get('max_repeat_ngram')} |")
        L.append("")
        for g in c4.get("generations", []):
            L.append(f"**{g['id']}** — 프롬프트: {g['prompt']}")
            L.append(_fence(g.get("output")))
            if g.get("json_parsed") is not None:
                L.append(f"- JSON 파싱: {_yn(g.get('json_parsed'))}" + (f", 키 `{g.get('json_keys')}`" if g.get("json_parsed") else f", 오류 `{g.get('json_error')}`"))
            L.append("")

    c5 = checks.get("05", {}).get("data", {})
    if c5:
        L.append("### 05 — vLLM 서빙\n")
        L.append("| 설정 | 준비 완료 | 기동(초) | 128토큰 완료(초) |")
        L.append("|---|---|---|---|")
        for a in c5.get("attempts", []):
            L.append(f"| `{a['name']}` ({a.get('note')}) | {_yn(a.get('ready'))} | {a.get('startup_seconds')} | {a.get('completion_latency_sec', '-')} |")
        L.append("")
        pd = c5.get("project_default")
        if pd:
            L.append(f"- **프로젝트 기본 vLLM 설정: `{pd['name']}`** (추가 인자: `{pd['extra_args'] or '없음'}`)")
        else:
            L.append("- ❌ 사용 가능한 vLLM 설정을 찾지 못했다.")
        for a in c5.get("attempts", []):
            if not a.get("ready") and a.get("log_tail"):
                L.append(f"\n`{a['name']}` 실패 로그 꼬리:")
                L.append(_fence(a["log_tail"]))
        L.append("")

    c6 = checks.get("06", {}).get("data", {})
    if c6:
        L.append("### 06 — 재현성 매트릭스\n")
        L.append(f"- 샘플링: temperature `{c6['sampling']['temperature']}`, top_p `{c6['sampling']['top_p']}`, "
                 f"seed `{c6['sampling']['seed']}`, max_tokens `{c6['sampling']['max_tokens']}`")
        L.append(f"- 라운드당 동일 프롬프트 {c6.get('repeats_per_round')}회 × {c6.get('rounds')} 라운드")
        L.append("")
        L.append("| VLLM_BATCH_INVARIANT | 모드 | 바이트 동일 | 서로 다른 출력 수 | 샘플 수 |")
        L.append("|---|---|---|---|---|")
        for r in c6.get("summary_rows", []):
            bi = "1 (켬)" if r["batch_invariant"] else "0 (끔)"
            mode = "동시" if r["mode"] == "concurrent" else "순차"
            if r["samples"]:
                L.append(f"| {bi} | {mode} | **{_yn(r['byte_identical'])}** | {r['distinct_outputs']} | {r['samples']} |")
            else:
                L.append(f"| {bi} | {mode} | 측정 실패 — {r.get('unmeasured_reason')} | - | 0 |")
        L.append("")
        t = c6.get("batch_invariant_throughput_cost")
        if t and t.get("slowdown_x"):
            L.append(f"- 배치 불변 커널 비용: 동시 라운드 벽시계 {t['concurrent_round_wall_off_sec']}초 → {t['concurrent_round_wall_on_sec']}초 (**{t['slowdown_x']}배**), "
                     f"순차 평균 지연 {t['sequential_latency_off_sec']}초 → {t['sequential_latency_on_sec']}초")
        for lbl, cell in (c6.get("matrix") or {}).items():
            if not cell.get("server_ready"):
                L.append(f"\n`{lbl}` 서버 기동 실패 로그 꼬리:")
                L.append(_fence(cell.get("log_tail")))
        L.append("\n> 동시 실행에서의 바이트 동일성은 **Gate 0 통과 조건이 아니다**. 측정하고 문서화하는 것이 조건이다.")
        L.append("")

    c7 = checks.get("07", {}).get("data", {})
    if c7:
        L.append("### 07 — LoRA 스텝 비용\n")
        ch = c7.get("chosen")
        if not ch:
            L.append("- ❌ 20스텝을 완주한 설정이 없다.")
        else:
            cfg = ch["config"]
            L.append(f"- **처음으로 들어맞은 설정**: batch `{cfg['batch']}` × grad_accum `{cfg['grad_accum']}` "
                     f"(유효 배치 {cfg['batch']*cfg['grad_accum']}), seq_len `{cfg['seq_len']}`, "
                     f"LoRA `r={cfg['lora_r']}` / `alpha={ch['lora_alpha']}`")
            L.append(f"- 대상 모듈: `{', '.join(ch['target_modules'])}`")
            L.append(f"- 학습 파라미터 {ch['trainable_params']:,} / 전체 {ch['total_params']:,} "
                     f"({100*ch['trainable_params']/ch['total_params']:.4f}%)")
            L.append(f"- **옵티마이저 스텝당 {ch['sec_per_optimizer_step']}초** (워밍업 {ch['warmup_steps_excluded']}스텝 제외, 총 {ch['steps']}스텝)")
            L.append(f"- **{ch['tokens_per_second']} tokens/s**, {ch['examples_per_second']} examples/s")
            L.append(f"- **최대 메모리: 할당 {ch['peak_allocated_gib']} GiB / 예약 {ch['peak_reserved_gib']} GiB**")
            L.append("")
            L.append("**1 에폭 소요 시간 외삽 — Phase 5 계획의 근거 수치**\n")
            L.append("| 학습 예제 수 | 옵티마이저 스텝 | 예상 소요 |")
            L.append("|---|---|---|")
            for n, v in ch["epoch_extrapolation"].items():
                L.append(f"| {int(n):,} | {v['optimizer_steps']} | **약 {v['hours']} 시간** |")
            L.append("")
        failed = [a for a in c7.get("attempts", []) if not a.get("ok")]
        if failed:
            L.append("단계적 하향 이력:")
            for a in failed:
                L.append(f"- `{a['config']}` → {a.get('error')}")
            L.append("")
        else:
            L.append("- 단계적 하향 없이 최초 설정에서 통과했다 (OOM 없음).")
            L.append("")
        L.append("- 스모크 산출 체크포인트는 삭제했다. 이 체크는 쓸 수 있는 어댑터를 만들지 않는다.")
        L.append("")

    c8 = checks.get("08", {}).get("data", {})
    if c8:
        L.append("### 08 — 샌드박스 프로브\n")
        L.append(f"- Docker: `{c8.get('docker')}`")
        L.append(f"- 격리 플래그: `{' '.join(c8.get('isolation_flags', []))}`")
        L.append(f"- 컨테이너 기동: {_yn(c8.get('container_started'))}")
        L.append(f"- 루트 파일시스템 읽기 전용 강제: {_yn(c8.get('read_only_enforced'))}")
        L.append(f"- `/tmp` tmpfs 쓰기 가능: {_yn(c8.get('tmpfs_writable'))}")
        L.append(f"- **외부 네트워크 차단 실증: {_yn(c8.get('network_blocked'))}** (ICMP 차단: {_yn(c8.get('ping_blocked'))})")
        L.append(f"- 실행 후 컨테이너 소멸 확인: {_yn(c8.get('container_destroyed'))}")
        L.append("- 이것은 Phase 4 평가 샌드박스를 위한 **프로브일 뿐**이며, 샌드박스 하네스 구축은 이 작업지시서 범위 밖이다.")
        L.append("")

    L.append("## 3. 체크별 기록 사항 (원문 노트)\n")
    for cid in sorted(checks):
        r = checks[cid]
        if not r.get("notes"):
            continue
        L.append(f"**{cid} {CHECK_TITLES_KO.get(cid, r['name'])}**")
        for n in r["notes"]:
            L.append(f"- {n}")
        L.append("")

    L.append("## 4. 의존성 고정\n")
    L.append("- 이 환경에서 확인된 전체 패키지 목록은 `env/versions.lock`에 있다 (`pip freeze` 전량).")
    L.append("- torch는 PyPI 기본 인덱스가 아니라 PyTorch `cu130` 휠 인덱스에서 설치했다. "
             "재현 시 `UV_TORCH_BACKEND=cu130` 또는 `--extra-index-url https://download.pytorch.org/whl/cu130`을 반드시 사용한다.")
    L.append("- 기계 판독용 원본 결과: `env/gate0.json`. 각 체크의 원시 stdout: `logs/<번호>_<이름>.log`.")
    L.append("")

    L.append("## 5. 이 작업지시서가 하지 않은 것\n")
    L.append("- 실제 코퍼스(CVE / NVD / CWE / ATT&CK)를 내려받지 않았다.")
    L.append("- 20스텝 스모크 외의 학습 파이프라인을 작성하지 않았다.")
    L.append("- 평가 하네스와 샌드박스 하네스를 만들지 않았다. 이후 작업지시서의 몫이다.")
    L.append("- 모델 가중치·데이터셋·체크포인트를 저장소에 커밋하지 않았다.")
    L.append("")

    out = Path(out_path) if out_path else (C.REPO / "reports" / "env-report.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    gate = json.loads((C.ENV_DIR / "gate0.json").read_text())
    print(render(gate))
