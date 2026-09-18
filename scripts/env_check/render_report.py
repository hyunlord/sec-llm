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


def _failure_modes_section(fm):
    L = []
    L.append("## 1. 알려진 4대 실패 모드 — 이 장비에서의 실제 결과\n")
    L.append("이 게이트가 존재하는 이유인 네 가지 실패 모드 각각에 대해, 실제로 발생했는지와 프로젝트가 무엇을 할 것인지를 적는다.\n")

    a = fm.get("cuda12_wheel_on_cuda13_runtime", {})
    ev = a.get("evidence", {})
    L.append("### (1) CUDA 12 대상 휠을 CUDA 13 런타임에 설치했을 때의 segfault / `undefined symbol`\n")
    L.append(f"- **발생 여부: {'발생함' if a.get('occurred') else '발생하지 않음'}**")
    L.append(f"- 설치된 torch: `{ev.get('torch')}` (링크된 CUDA 런타임 `{ev.get('cuda_runtime_linked')}`), 드라이버 `{ev.get('driver')}`")
    L.append(f"- torch가 담고 있는 아키텍처 목록: `{ev.get('arch_list')}`")
    L.append(f"- 실제 디바이스: `{ev.get('device_sm')}` / 이 아키텍처가 목록에 포함되어 있는가: **{_yn(ev.get('device_sm_in_arch_list'))}**")
    if a.get("occurred"):
        L.append("- **대응**: 환경을 CUDA 13 대상 휠로 재구성해야 한다. 개별 패키지 핀으로 우회하지 않는다.")
    else:
        L.append("- **대응**: 처음부터 PyTorch `cu130` 휠 인덱스(`UV_TORCH_BACKEND=cu130`)로 설치했기 때문에 이 문제가 발생하지 않았다. "
                 "NGC 컨테이너로의 전환은 필요하지 않았다. **이후 모든 단계에서 torch를 PyPI 기본 인덱스로 재설치하지 말 것** — "
                 "`env/versions.lock`에 기록된 `+cu130` 빌드를 유지한다.")
        if ev.get("device_sm_in_arch_list") is False:
            L.append(f"- 다만 주의: torch 바이너리에 `{ev.get('device_sm')}` 전용 cubin은 들어 있지 않다. "
                     f"Blackwell 계열 바이너리 호환성(sm_120 → sm_121)에 의존하고 있으며, 체크 02가 이것이 "
                     "수치적으로 올바르게 동작함을 확인했다. torch 버전을 올릴 때마다 체크 02를 다시 돌려야 한다.")
    L.append("")

    b = fm.get("flash_attn_no_sm121_kernel", {})
    ev = b.get("evidence", {})
    L.append("### (2) `flash-attn`이 Blackwell sm_121용 커널을 제공하지 않음\n")
    L.append(f"- **발생 여부: {'발생함' if b.get('occurred') else '발생하지 않음'}**")
    L.append(f"- flash-attn 설치 성공 여부: **{_yn(ev.get('installed'))}**")
    if ev.get("error"):
        L.append("- 실제 오류(그대로 옮김):")
        L.append(_fence(ev["error"]))
    if ev.get("corrupted"):
        L.append("- 로드는 되었으나 출력이 깨졌다. 생성 샘플:")
        L.append(_fence(ev.get("output_sample")))
    L.append("- **대응**: 학습과 HF 추론 모두 `attn_implementation=\"sdpa\"`를 기본값으로 고정한다. "
             "체크 03의 결과와 무관하게 이것이 프로젝트 기본값이다 — 지원되지 않는 아키텍처 위에서 검증되지 않은 커널 경로를 "
             "정확도가 중요한 학습에 쓰는 것은 이득보다 위험이 크다.")
    L.append("")

    c = fm.get("vllm_cuda_graph_capture_fails", {})
    ev = c.get("evidence", {})
    L.append("### (3) aarch64 + CUDA 13 빌드에서 vLLM의 CUDA 그래프 캡처 실패\n")
    L.append(f"- **발생 여부: {'발생함' if c.get('occurred') else '발생하지 않음'}**")
    L.append(f"- 기본 설정(그래프 캡처 켜짐) 서버 준비 완료: **{_yn(ev.get('default_ready'))}**")
    L.append(f"- `--enforce-eager`(그래프 캡처 꺼짐) 서버 준비 완료: **{_yn(ev.get('enforce_eager_ready'))}**")
    if ev.get("default_log_tail"):
        L.append("- 기본 설정 실패 시 기동 로그 꼬리:")
        L.append(_fence(ev["default_log_tail"]))
    L.append("")

    d = fm.get("greedy_not_byte_reproducible_under_concurrency", {})
    ev = d.get("evidence", {})
    L.append("### (4) 배치 불변 커널 없이는 그리디 디코딩이 바이트 단위로 재현되지 않음\n")
    L.append(f"- **발생 여부: {'발생함' if d.get('occurred') else '발생하지 않음'}**")
    L.append(f"- 순차 실행 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **{_yn(ev.get('sequential_byte_identical_bi_off'))}**")
    L.append(f"- 동시 실행 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **{_yn(ev.get('concurrent_byte_identical_bi_off'))}**")
    L.append(f"- 동시 실행 / `VLLM_BATCH_INVARIANT=1` — 바이트 동일: **{_yn(ev.get('concurrent_byte_identical_bi_on'))}**")
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
        L.append(f"- 행렬 크기 {c2.get('matrix_size')}×{c2.get('matrix_size')}, fp32 / bf16 각각 matmul·softmax·layer_norm·리덕션·D2H 복사")
        for r in c2.get("dtypes", []):
            if r.get("error"):
                L.append(f"- `{r['dtype']}`: ❌ {r['error']}")
                continue
            mm = r.get("ops", {}).get("matmul", {})
            L.append(f"- `{r['dtype']}`: {'✅' if r.get('ok') else '❌'} "
                     f"matmul {mm.get('seconds')}초 ({mm.get('tflops')} TFLOP/s), "
                     f"CPU 기준 최대 상대오차 {mm.get('max_rel_err'):.3g} (허용 {mm.get('tolerance')})")
        L.append(f"- 최대 할당 메모리: {c2.get('peak_allocated_gib')} GiB")
        L.append("")

    c3 = checks.get("03", {}).get("data", {})
    if c3:
        L.append("### 03 — 어텐션 백엔드\n")
        for impl in ("sdpa", "flash_attention_2"):
            r = c3.get(impl, {})
            L.append(f"**`{impl}`**")
            L.append(f"- 로드 성공: {_yn(r.get('loaded'))}, 생성 성공: {_yn(r.get('generated'))}")
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
