# P0 환경 검증 보고서 (Gate 0)

- 대상 장비: **aitopatom-d6bb** (DGX Spark, GB10 Grace-Blackwell)
- 대상 모델: `Qwen/Qwen2.5-7B-Instruct`
- 생성 시각: 2026-09-18T23:26:00+0900
- **게이트 통과 여부: ✅ 통과**

## 0. 한 문단 요약

NVIDIA GB10(sm_121) 위에서 torch `2.13.0+cu130` / CUDA `13.0` 스택이 정상 동작한다. vLLM은 `default` 설정으로 서빙 가능하다. LoRA 학습은 옵티마이저 스텝당 **129.5145초**, **506.0 tokens/s**, 최대 할당 메모리 **47.85 GiB**로 측정되었다. 이를 근거로 1 에폭 소요 시간은 10,000건 → 약 22.49시간, 30,000건 → 약 67.46시간, 60,000건 → 약 134.91시간로 추정된다. 작업 볼륨 여유 공간은 1097.67 GiB다.

## 체크 결과 한눈에 보기

| # | 체크 | 결과 | 소요(초) |
|---|------|------|----------|
| 01 | 장비 인벤토리 | ✅ 통과 | 4.1 |
| 02 | torch ABI 스모크 | ✅ 통과 | 4.0 |
| 03 | 어텐션 백엔드 (sdpa vs flash_attention_2) | ✅ 통과 | 80.04 |
| 04 | 생성 정상성 | ✅ 통과 | 103.3 |
| 05 | vLLM 서빙 | ✅ 통과 | 238.2 |
| 06 | 재현성 (결정성) | ✅ 통과 | 578.8 |
| 07 | LoRA 스텝 비용 | ✅ 통과 | 2678.1 |
| 08 | 샌드박스 프로브 | ✅ 통과 | 5.0 |

### Gate 0 통과 조건 대조

| 체크 | 요구 조건 | 상태 | 충족 |
|------|-----------|------|------|
| 02 | device tensor ops succeed in fp32 and bf16 | ✅ 통과 | ✅ |
| 04 | three non-corrupted generations on the sdpa path | ✅ 통과 | ✅ |
| 05 | at least one vLLM configuration reaches ready state and serves a completion | ✅ 통과 | ✅ |
| 06 | all four determinism cells reported with an explicit verdict | ✅ 통과 | ✅ |
| 07 | seconds per step and three epoch extrapolations, no OOM at the chosen config | ✅ 통과 | ✅ |

## 0.5. 안전장치가 실제로 작동하는가 — 측정 결과

설정만 되어 있고 강제되지 않는 안전장치는 없는 것보다 나쁘다. 보호 장치처럼 읽히는 가정 위에 하네스 전체가 세워지기 때문이다. 그래서 측정했다.

### 메모리 상한이 살아 있는가: **예 — 강제됨** (`live`)

- 1 GiB 스코프 안에서 2 GiB 할당 → 종료 코드 `-9` (137 = SIGKILL)
- 대조군(스코프 없이 동일 할당) 성공: **예**
- 스코프 내부 `memory.max` 실측값: `1073741824`
- 해석: The 2 GiB allocation was killed inside a 1 GiB scope, the same allocation succeeded unscoped, and memory.max inside the scope reads 1073741824. The ceiling is enforced.

### 이 상한이 무엇을 덮는가: **`host_ram_only`**

- CUDA 디바이스 할당도 cgroup에 계상되는가: **아니오**
- 해석: A 16 GiB device allocation survived inside a 8G scope, so CUDA device memory is NOT charged to the process cgroup. The ceiling bounds host RAM only. That is the failure the 2026-09-18 incident actually was -- a host-side compiler -- so the protection that matters is in place; GPU-side over-allocation is bounded separately by the CUDA allocator cap in check 07.

### 소스 빌드 금지 강제: **예**

- `PIP_ONLY_BINARY=':all:'`, 저장소 `pip.conf` 존재: 예
- grep으로는 이것을 증명할 수 없다. pip는 소스 배포본을 만나면 빌드하고, 우리 코드의 어떤 문자열도 그 사실을 말해주지 않는다. 그래서 환경에서 강제한다.

### 사용자 공간 OOM 데몬: **아니오**

- `systemd-oomd`: `inactive`, `earlyoom` 설치됨: 아니오

## 1. 알려진 4대 실패 모드 — 이 장비에서의 판정

각 항목은 **그 판정을 담당하는 체크가 실제로 실행되어 증거를 만들어낸 경우에만** 판정을 적는다. 설치가 성공했다거나 옆 체크가 통과했다는 것은 증거가 아니며, 증거가 없으면 '판정 불가'라고 적는다.

### (1) CUDA 12 대상 휠을 CUDA 13 런타임에 올렸을 때의 segfault / `undefined symbol`

- **판정: 발생하지 않음** (체크 02)
- torch `2.13.0+cu130` (링크된 CUDA 런타임 `13.0`), 드라이버 `580.126.09`
- torch가 담고 있는 아키텍처: `['sm_80', 'sm_90', 'sm_100', 'sm_110', 'sm_120']`
- 실제 디바이스 `sm_121` — 네이티브 cubin 포함 여부: **아니오**, PTX 항목: **없음**

**아키텍처 호환 방식: `family_binary_compat`**

> no cubin for sm_121 and no PTX entry in arch_list -- the stack is relying on CUDA 13 Blackwell family-level binary compatibility (sm_120 cubins loaded onto an sm_121 part)

**수치 정확도 (fp64 CPU 기준값 대비)**

| dtype | 통과 | 최대 절대오차 | 최대 상대오차 | 허용 상대오차 |
|---|---|---|---|---|
| `float32` | ✅ | 0.001041 | 3.005e-06 | 0.0001 |
| `bfloat16` | ✅ | 1.31 | 0.003783 | 0.05 |

- **첫 커널 호출 지연**: 컨텍스트 생성 0.1739초, 첫 matmul 0.1514초, 두 번째 matmul 9.7e-05초 (1560.8배)
  - 원인 귀속: **`first launch is not materially slower than steady state`** — 
- **실측 bf16 GEMM 처리량: 95.95 TFLOPS** (참고치 125.0 TFLOPS의 76.8%). 일반 경로 폴백 정황은 없다.
  - 참고치 근거: derived from NVIDIA's headline 1 PFLOP FP4-with-sparsity figure (1000 / 2 sparsity / 2 FP4->FP8 / 2 FP8->BF16); a reference point for spotting a generic-kernel fallback, not a datasheet quote
- 첫 디바이스 연산 중 `no kernel image` / PTX JIT 관련 메시지: 없음

- **대응**: PyTorch `cu130` 휠 인덱스(`UV_TORCH_BACKEND=cu130`)로 설치한 환경에서 fp32·bf16 디바이스 연산이 모두 fp64 기준값과 허용오차 내로 일치했다. 이후 단계에서 torch를 PyPI 기본 인덱스로 재설치하지 말 것 — `env/versions.lock`의 `+cu130` 빌드를 유지한다.
- **재검증 의무**: 이 빌드에는 PTX 폴백이 없다. 즉 네이티브 cubin도 PTX도 없이 Blackwell 계열 바이너리 호환성에 의존하고 있으므로, torch나 CUDA를 올릴 때마다 **체크 02를 반드시 다시 돌린 뒤** 신뢰할 것.

### (2) `flash-attn`이 Blackwell sm_121용 커널을 제공하지 않음

- **판정: 해당 없음 — 사용 자체가 불가** (체크 03)
- flash_attention_2 is unusable here because no prebuilt wheel exists and this project does not compile on the training host. Whether its kernels would work on sm_121 was NOT tested -- no verdict on the kernel itself.
- flash-attn import 가능 여부: **아니오**, 실패 분류: `not_installed`
- 사전 빌드 휠 존재 여부(해석 전용, 다운로드·빌드 없음): **아니오** — no prebuilt wheel for this platform (aarch64 / CUDA 13 / cp312 / sm_121); the index offers source distributions only
  - 사용한 명령: `uv pip install --dry-run --only-binary=:all: flash-attn`
  - 리졸버 출력:
```
× No solution found when resolving dependencies:
  ╰─▶ Because all versions of flash-attn have no usable wheels and you require
      flash-attn, we can conclude that your requirements are unsatisfiable.

      hint: Wheels are required for `flash-attn` because building from source
      is disabled for all packages (i.e., with `--no-build`)
```
- transformers가 낸 오류(원문):
```
FlashAttention2 has been toggled on, but it cannot be used due to the following error: the package for FlashAttention2 doesn't seem to be installed.
```

> ⚠️ **증거의 한계를 분명히 한다.** 이것은 *가용성* 판정이지 *커널 동작* 판정이 아니다. flash-attn 2.x가 sm_121에서 올바른 출력을 내는지는 **시험하지 않았고**, 그에 대한 판정을 내리지 않는다. 시험하려면 학습 호스트에서 소스 빌드를 해야 하는데, 그것은 이 프로젝트가 금지한 행위다(아래 사건 참조).

**기록: 소스 빌드 시도 사건**

- 일자: 2026-09-18
- 무엇을 했나: A flash-attn source build (flash-attn==2.8.3.post1, MAX_JOBS=16, --no-build-isolation) was started on the DGX Spark while the gate was being prepared.
- 결과: The parallel nvcc jobs exhausted the shared 128 GiB unified memory pool. The host stopped responding to SSH and ICMP within roughly two minutes, stayed down for over an hour, and required a physical power cycle. No check result survived.
- 왜 플랫폼에 대한 증거인가: On Grace-Blackwell the GPU and the host share one physical memory pool, so a host-side compile is not isolated from GPU work the way it is on a discrete-GPU x86 server. A CUDA allocator ceiling does not help, because the compiler never allocates through CUDA.
- 채택한 규칙: No source compilation on the training host. Wheels only. If a package has no wheel for this platform, the absence is the finding.

자세한 내용은 `docs/hardware-notes.md` 참조.

- 이 체크가 무언가를 컴파일했는가: **아니오**
- **대응**: 학습과 HF 추론 모두 `attn_implementation="sdpa"`로 고정한다. 체크 03의 결과와 무관하게 이것이 프로젝트 기본값이며, 체크는 그 이유를 기록할 뿐 결정하지 않는다.

### (3) aarch64 + CUDA 13 빌드에서 vLLM의 CUDA 그래프 캡처 실패

- **판정: 발생하지 않음** (체크 05)
- 기본 설정(그래프 캡처 켜짐) 준비 완료: **예** — ready
- `--enforce-eager`(그래프 캡처 꺼짐) 준비 완료: **예**

### (4) 배치 불변 커널 없이는 그리디 디코딩이 바이트 단위로 재현되지 않음

- **판정: 발생함** (체크 06)
- 순차 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **아니오**
- 동시 / `VLLM_BATCH_INVARIANT` 끔 — 바이트 동일: **아니오**
- 동시 / `VLLM_BATCH_INVARIANT=1` — 바이트 동일: **예**
- 배치 불변 커널의 처리량 비용: 동시 라운드 벽시계 9.797초 → 10.512초 (**1.073배**)
- 자세한 내용과 프로젝트 정책은 `docs/determinism.md` 참조.

## 2. 체크별 상세

### 01 — 장비 인벤토리

- 아키텍처 `aarch64`, 커널 `6.14.0-1015-nvidia`, CPU 20 코어
- GPU: `NVIDIA GB10, 580.126.09, 12.1, [N/A], [N/A]`
- torch `2.13.0+cu130` / CUDA 런타임 `13.0` / cuDNN `92000`
- 컴퓨트 능력 `sm_121`, GPU 가시 메모리 `{'free_gib': 88.19, 'total_gib': 119.7}`
- 호스트 메모리(GiB): `{'MemTotal': 119.7, 'MemFree': 88.19, 'MemAvailable': 105.52}`
- **여유 디스크**: 저장소 볼륨 1097.67 GiB, HF 캐시 볼륨 1097.67 GiB (7B 베이스 + LoRA 3회분 기준 여유 충분)
- Docker: `Docker version 29.1.3, build f52814d`

### 02 — torch ABI 스모크

- 디바이스: `NVIDIA GB10` `sm_121`, torch `2.13.0+cu130` / CUDA `13.0` / 드라이버 `580.126.09`
- `get_arch_list()`: `['sm_80', 'sm_90', 'sm_100', 'sm_110', 'sm_120']`
- PTX(`compute_*`) 항목: **없음** → 호환 방식 `family_binary_compat`
- 정확도 검증 행렬 크기: 4096×4096, 디바이스 결과를 **fp64 CPU 기준값**과 비교

| dtype | 통과 | 최대 절대오차 | 최대 상대오차 | 허용 상대오차 | 디바이스 matmul | fp64 CPU 기준 |
|---|---|---|---|---|---|---|
| `float32` | ✅ | 0.001041 | 3.005e-06 | 0.0001 | 0.01초 | 0.344초 |
| `bfloat16` | ✅ | 1.31 | 0.003783 | 0.05 | 0.1918초 | 0.377초 |

- `float32` 보조 연산(softmax·layer_norm·리덕션·D2H): `{'softmax_rowsum_err': 0.0, 'layer_norm_std': 0.9999949932098389, 'reduction_finite': True, 'd2h_roundtrip_ok': True, 'ok': True}`
- `bfloat16` 보조 연산(softmax·layer_norm·리덕션·D2H): `{'softmax_rowsum_err': 0.0, 'layer_norm_std': 0.9999949932098389, 'reduction_finite': True, 'd2h_roundtrip_ok': True, 'ok': True}`
- 첫 호출 지연: 컨텍스트 0.1739초 / 첫 matmul 0.1514초 / 두 번째 9.7e-05초 (1560.8배), JIT 정황 측정 안 됨
- 정상상태 bf16 처리량: **95.95 TFLOPS** (8192×8192, 워밍업 5 후 20회 평균 0.01146초) — 참고치의 76.8%
- 최대 할당 메모리: 0.406 GiB

### 03 — 어텐션 백엔드

- 이 체크가 컴파일한 것: **아니오**
- 사전 빌드 휠 해석(다운로드 아니오, 빌드 아니오): **아니오** — no prebuilt wheel for this platform (aarch64 / CUDA 13 / cp312 / sm_121); the index offers source distributions only
- 최종 판정: `unavailable_no_wheel`

**`sdpa`**
- 로드 성공: 예, 생성 성공: 예
- 실제 적용된 구현: `sdpa`, 손상 판정: 아니오
- 출력:
```
Injection vulnerabilities
Authentication vulnerabilities
Configuration errors
```

**`flash_attention_2`**
- 로드 성공: 아니오, 생성 성공: 아니오, 실패 분류 `not_installed`
- 오류(그대로):
```
ImportError("FlashAttention2 has been toggled on, but it cannot be used due to the following error: the package for FlashAttention2 doesn't seem to be installed.")
```

### 04 — 생성 정상성 (sdpa, 그리디 128토큰)

- 정상 출력 3/3건

| 프롬프트 | 언어 | 손상 | 치환·제어문자 비율 | 최장 반복 n-gram |
|---|---|---|---|---|
| `en_prose` | en | 아니오 | 0.0 | 0 |
| `ko_prose` | ko | 아니오 | 0.0 | 0 |
| `json_schema` | en | 아니오 | 0.0 | 0 |

**en_prose** — 프롬프트: Explain in a short paragraph why input validation matters in web applications.
```
Input validation is crucial in web applications because it helps protect against a variety of security threats, such as cross-site scripting (XSS), SQL injection, and command injection attacks. By validating user inputs, developers can ensure that the data conforms to expected formats and constraints, thereby preventing malicious data from being processed or stored. This not only enhances the security of the application but also improves its reliability and performance. Proper validation also helps in maintaining data integrity and can prevent unexpected behavior or errors in the application logic.
```

**ko_prose** — 프롬프트: SQL 인젝션 취약점이 무엇인지 한국어로 간단히 설명해 주세요.
```
SQL 인젝션 취약점은 웹 애플리케이션이 사용자 입력을 SQL 쿼리에 직접 포함하여 처리하는 경우 발생할 수 있는 보안 문제입니다. 간단히 말해, 악의적인 사용자는 웹 폼이나 URL에서 특별히 설계된 입력을 제공하여 서버의 데이터베이스를 조작하거나 정보를 훔칠 수 있습니다.

예를 들어, 사용자가 로그인 페이지에서 아이디와 비밀번호를 입력해야 하는데, 악의적인 사용자는 다음과 같은 입력을 제공
```

**json_schema** — 프롬프트: Return ONLY a JSON object, no prose, with exactly these keys: "cwe_id" (string), "severity" (one of low/medium/high/critical), "summary" (string). Describe a stack-based buffer overflow.
```
{
  "cwe_id": "CWE-787",
  "severity": "high",
  "summary": "A stack-based buffer overflow occurs when a program writes beyond the bounds of a buffer allocated on the stack, overwriting adjacent memory locations, which can lead to code execution or program crashes."
}
```
- JSON 파싱: 예, 키 `['cwe_id', 'severity', 'summary']`

### 05 — vLLM 서빙

| 설정 | 준비 완료 | 기동(초) | 128토큰 완료(초) |
|---|---|---|---|
| `default` (CUDA graph capture enabled (vLLM default)) | 예 | 111.0 | 4.837 |
| `enforce_eager` (CUDA graph capture disabled) | 예 | 99.0 | 5.179 |

- **프로젝트 기본 vLLM 설정: `default`** (추가 인자: `없음`)

### 06 — 재현성 매트릭스

- 샘플링: temperature `0.0`, top_p `1.0`, seed `1234`, max_tokens `128`
- 라운드당 동일 프롬프트 5회 × 3 라운드

| VLLM_BATCH_INVARIANT | 모드 | 바이트 동일 | 서로 다른 출력 수 | 샘플 수 |
|---|---|---|---|---|
| 0 (끔) | 순차 | **아니오** | 2 | 15 |
| 0 (끔) | 동시 | **아니오** | 2 | 15 |
| 1 (켬) | 순차 | **예** | 1 | 15 |
| 1 (켬) | 동시 | **예** | 1 | 15 |

- 배치 불변 커널 비용: 동시 라운드 벽시계 9.797초 → 10.512초 (**1.073배**), 순차 평균 지연 9.448초 → 8.463초

> 동시 실행에서의 바이트 동일성은 **Gate 0 통과 조건이 아니다**. 측정하고 문서화하는 것이 조건이다.

### 07 — LoRA 스텝 비용

- **처음으로 들어맞은 설정**: batch `4` × grad_accum `4` (유효 배치 16), seq_len `4096`, LoRA `r=64` / `alpha=128`
- 대상 모듈: `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj`
- 학습 파라미터 161,480,704 / 전체 7,777,097,216 (2.0764%)
- **옵티마이저 스텝당 129.5145초** (워밍업 3스텝 제외, 총 20스텝)
- **506.0 tokens/s**, 0.124 examples/s
- **최대 메모리: 할당 47.85 GiB / 예약 54.85 GiB**

**1 에폭 소요 시간 외삽 — Phase 5 계획의 근거 수치**

| 학습 예제 수 | 옵티마이저 스텝 | 예상 소요 |
|---|---|---|
| 10,000 | 625.0 | **약 22.49 시간** |
| 30,000 | 1875.0 | **약 67.46 시간** |
| 60,000 | 3750.0 | **약 134.91 시간** |

- 단계적 하향 없이 최초 설정에서 통과했다 (OOM 없음).

- 스모크 산출 체크포인트는 삭제했다. 이 체크는 쓸 수 있는 어댑터를 만들지 않는다.

### 08 — 샌드박스 프로브

- Docker: `{'client_version': '29.1.3', 'server_version': '29.1.3', 'server_arch': 'arm64', 'server_os': 'linux'}`
- 격리 플래그: `--network=none --memory=512m --pids-limit=128 --read-only --tmpfs /tmp --security-opt no-new-privileges:true`
- 컨테이너 기동: 예
- 루트 파일시스템 읽기 전용 강제: 예
- `/tmp` tmpfs 쓰기 가능: 예
- **외부 네트워크 차단 실증: 예** (ICMP 차단: 예)
- 실행 후 컨테이너 소멸 확인: 예
- 이것은 Phase 4 평가 샌드박스를 위한 **프로브일 뿐**이며, 샌드박스 하네스 구축은 이 작업지시서 범위 밖이다.

## 3. 체크별 기록 사항 (원문 노트)

**01 장비 인벤토리**
- torch was not compiled with a cubin for sm_121; it ships ['sm_80', 'sm_90', 'sm_100', 'sm_110', 'sm_120'] and must rely on Blackwell family-level binary compatibility (sm_120 -> sm_121). Check 02 proves whether that actually works.
- memory ceiling probe: live -- The 2 GiB allocation was killed inside a 1 GiB scope, the same allocation succeeded unscoped, and memory.max inside the scope reads 1073741824. The ceiling is enforced.
- cgroup coverage probe: host_ram_only -- A 16 GiB device allocation survived inside a 8G scope, so CUDA device memory is NOT charged to the process cgroup. The ceiling bounds host RAM only. That is the failure the 2026-09-18 incident actually was -- a host-side compiler -- so the protection that matters is in place; GPU-side over-allocation is bounded separately by the CUDA allocator cap in check 07.
- NO userspace OOM daemon on this host: systemd-oomd is 'inactive' and earlyoom is absent. Installing one requires root and passwordless sudo is not available to this account, so it could not be enabled here. The kernel OOM killer does fire (the 2026-09-18 incident log shows 155 oom-kill events) but only after the host has already become unresponsive. Phase 5 runs far longer than this gate and should not start until this is addressed.

**02 torch ABI 스모크**
- failure mode (1) verdict: DID NOT OCCUR. Device ops in fp32 and bf16 both ran and matched an fp64 CPU reference within tolerance on sm_121.
- architecture compatibility: family_binary_compat -- no cubin for sm_121 and no PTX entry in arch_list -- the stack is relying on CUDA 13 Blackwell family-level binary compatibility (sm_120 cubins loaded onto an sm_121 part)
- no PTX fallback exists in this build, so every torch/CUDA upgrade must re-run check 02 before it is trusted -- family-level binary compatibility is not a guarantee the way a native cubin or a PTX entry is.
- achieved bf16 GEMM throughput 95.95 TFLOPS, 76.8% of the derived 125.0 TFLOPS reference
- installation route: torch from the PyTorch cu130 wheel index (UV_TORCH_BACKEND=cu130), matching the CUDA 13.0 runtime. No NGC container fallback and no source build were used.

**03 어텐션 백엔드 (sdpa vs flash_attention_2)**
- flash_attention_2 is unavailable on this platform because no prebuilt wheel exists for it, and this project does not build CUDA extensions on the training host. transformers raised: FlashAttention2 has been toggled on, but it cannot be used due to the following error: the package for FlashAttention2 doesn't seem to be installed.
- note the limit of this evidence: this is an availability finding, not a direct observation of sm_121 kernel behaviour. Whether flash-attn 2.x would produce correct output on sm_121 was NOT tested and no verdict is claimed.
- prebuilt wheel probe: no prebuilt wheel for this platform (aarch64 / CUDA 13 / cp312 / sm_121); the index offers source distributions only
- project default for training and HF inference: attn_implementation='sdpa'
- this check compiled nothing. A source build was attempted once on 2026-09-18 and took the host down; see docs/hardware-notes.md.

**04 생성 정상성**
- JSON-output prompt parsed as valid JSON: True keys=['cwe_id', 'severity', 'summary']
- heuristics are a tripwire, not a verdict -- full raw outputs are in logs/04_generation_sanity.log for human review

**05 vLLM 서빙**
- vLLM project default: default (extra args: none), startup 111.0s, 128-token completion 4.837s

**06 재현성 (결정성)**
- BI=0 / sequential: byte_identical=False (2 distinct over 15 samples)
- BI=0 / concurrent: byte_identical=False (2 distinct over 15 samples)
- BI=1 / sequential: byte_identical=True (1 distinct over 15 samples)
- BI=1 / concurrent: byte_identical=True (1 distinct over 15 samples)
- batch-invariant kernels cost 1.073x on concurrent round wall time (9.797s -> 10.512s)

**07 LoRA 스텝 비용**
- first configuration that fits: batch=4 x grad_accum=4 (effective 16), seq_len=4096, LoRA r=64 alpha=128
- 129.5145s per optimizer step, 506.0 tokens/s, peak allocated 47.85 GiB / reserved 54.85 GiB
- one epoch over 10,000 examples: 625.0 steps, ~22.49 h
- one epoch over 30,000 examples: 1875.0 steps, ~67.46 h
- one epoch over 60,000 examples: 3750.0 steps, ~134.91 h
- training checkpoint deleted; this smoke produces no usable adapter

**08 샌드박스 프로브**
- docker 29.1.3 on linux/arm64
- isolation flags verified: started=True, read_only=True, tmpfs=True, outbound_network_blocked=True, destroyed=True
- probe only -- the Phase 4 sandbox harness is out of scope for this work order

## 4. 의존성 고정

- 이 환경에서 확인된 전체 패키지 목록은 `env/versions.lock`에 있다 (`pip freeze` 전량).
- torch는 PyPI 기본 인덱스가 아니라 PyTorch `cu130` 휠 인덱스에서 설치했다. 재현 시 `UV_TORCH_BACKEND=cu130` 또는 `--extra-index-url https://download.pytorch.org/whl/cu130`을 반드시 사용한다.
- 기계 판독용 원본 결과: `env/gate0.json`. 각 체크의 원시 stdout: `logs/<번호>_<이름>.log`.

## 5. 이 작업지시서가 하지 않은 것

- 실제 코퍼스(CVE / NVD / CWE / ATT&CK)를 내려받지 않았다.
- 20스텝 스모크 외의 학습 파이프라인을 작성하지 않았다.
- 평가 하네스와 샌드박스 하네스를 만들지 않았다. 이후 작업지시서의 몫이다.
- 모델 가중치·데이터셋·체크포인트를 저장소에 커밋하지 않았다.

