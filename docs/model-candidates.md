# 기반 모델 후보 검토 (2026-09-20)

> P5가 도는 동안 작성한 **검토 자료**다. 결정이 아니며, 모델 교체는 별도 작업지시서와 게이트 재실행을 전제로 한다.
> 사실은 각 모델 카드·vLLM 이슈·이 DGX의 캐시에서 확인했고 출처는 끝에 있다. 확인하지 못한 것은 "미확인"으로 적었다.

## 1. 이 파이프라인이 모델에 요구하는 것

교체 후보를 고를 때 벤치마크 점수보다 먼저 통과해야 하는 조건들이다. 하나라도 어기면 지금까지의 방법론이 무너진다.

| # | 조건 | 왜 | 어기면 |
|---|---|---|---|
| C1 | **사전학습 데이터 컷오프 ≤ 2025-01-01** | 시간 분할의 전제. 컷오프 이후 평가 세트(2025년 이후 CVE)가 "모델이 못 본 데이터"여야 이전/이후 격차가 오염 추정치가 된다 | 시간 분할이 무의미해진다. `CUTOFF`를 2026-01-01로 옮기면 살릴 수 있으나 데이터셋 전체 재구축 |
| C2 | **vLLM 배치 불변 모드 지원** (`VLLM_BATCH_INVARIANT=1`) | Gate 0·Gate 4의 근거. 없으면 그리디 출력이 바이트 단위로 재현되지 않는다 (15회 중 2가지 출력) | Gate 4 통과 불가 → 모든 점수가 재현 불가 |
| C3 | 밀집(dense) 모델, 약 4B~14B | 스텝당 129.5초 예산(7.7B 기준)과 128GB 통합 메모리. MoE는 LoRA 학습이 복잡하고 vLLM 배치 불변이 fused-MoE에서 깨진다 (이슈 #57016) | 일정·재현성 둘 다 재검증 |
| C4 | 라이선스: 미세조정 + 파생 모델 재배포 허용, 보안 연구 금지 조항 없음 | 데이터 라이선스와 같은 기준(`model_publication_status`) | 결과물을 공개할 수 없다 |
| C5 | vLLM 0.29.0 레지스트리에 아키텍처 존재 | 평가 하네스가 그 버전에 고정 | 하네스 스택 재검증 |
| C6 | thinking 모드를 끌 수 있고, 끈 상태가 채팅 템플릿에 기록 가능 | 제약 디코딩·결정론·토큰 예산 | 자유/제약 격차 측정이 오염 |
| C7 | 텍스트 전용 경로가 있을 것 | 멀티모달 래퍼는 LoRA 대상 모듈·vLLM 경로를 복잡하게 한다 | 비전 타워를 수동으로 제외 |
| C8 | (선호) 한국어 | 리플레이에 한국어가 사실상 없다는 P3 발견 | — |

어떤 모델로 바꾸든 토크나이저가 바뀌므로 **데이터셋 매니페스트의 토큰 수·패킹 일정·서브샘플 예산 T는 전부 재계산**된다 (`make datasets` 재실행, 약 10분). 이것은 모든 후보에 공통이라 표에서 뺐다.

## 2. 후보 비교표

DGX 캐시 열은 `~/.cache/huggingface/hub`에 이미 있는지다 (있으면 다운로드 없이 게이트 재실행 가능).

| 모델 | 크기 | 공개 | 라이선스 | 데이터 컷오프 | 배치 불변 (C2) | 아키텍처 / vLLM 0.29 | thinking | 한국어 | DGX 캐시 | 판정 |
|---|---|---|---|---|---|---|---|---|---|---|
| **Qwen2.5-7B-Instruct** (현재) | 7.6B 밀집 | 2024-09 | Apache-2.0 | 2024-06 | **측정 완료, 통과** | Qwen2 / 지원 | 없음 | 보통 | ✔ | 기준 |
| **Gemma 4 12B** | 12.0B 밀집 | 2026-04 | Apache-2.0 | **2025-01** | 미측정 (표준 어텐션, 슬라이딩 윈도 혼합) | Gemma4ForCausalLM / 지원 | `<\|think\|>` 토큰으로 on/off | 140+ 언어 | ✔ (it 23G) | **A — 1순위 후보** |
| **Gemma 4 E4B** | 4.5B 유효 (8B 총) | 2026-04 | Apache-2.0 | 2025-01 | 미측정 | Gemma4 / 지원 | 동일 | 동일 | ✔ | A — 저비용 대안 |
| Gemma 4 31B | 30.7B 밀집 | 2026-04 | Apache-2.0 | 2025-01 | 미측정 | Gemma4 / 지원 | 동일 | 동일 | ✔ (59G) | C3 위반 (스텝 비용 ~4배) |
| **OLMo 3 7B** (Instruct/Think) | 7B 밀집 | 2025-12 | Apache-2.0 | **2024-12** | 미측정 (표준 어텐션) | Olmo3ForCausalLM / 지원 | Think는 별도 모델 | **영어 전용** | ✗ | **A — 오염 연구에 가장 깨끗함** (사전학습 데이터 Dolma 3 공개 → CVE 노출을 직접 검사 가능) |
| **Phi-4** | 14B 밀집 | 2024-12 | MIT | 2024-06 | 미측정 | Phi3ForCausalLM / 지원 | 없음 | 사실상 없음 (다국어 8%) | ✗ | A− — 컷오프·라이선스 최적, 한국어 없음, 비용 ~1.8배 |
| **A.X-4.0-Light** (SKT) | 7B 밀집 | 2025-07 | Apache-2.0 | **미확인** (Qwen2.5 기반 + 추가 학습) | Qwen2 아키텍처 → 현재와 동일 커널, 재측정만 | Qwen2ForCausalLM / 지원 | 없음 | **최적화됨** | ✗ | A− — 파이프라인 변경 최소. **컷오프 확인이 선행조건** (2025년 데이터 포함이면 C1 위반) |
| Ministral 3 8B | 8.4B + 0.4B 비전 | 2025-12 | Apache-2.0 | 미확인 (2025 추정) | 미측정 | Mistral3ForConditionalGeneration / 지원 | Reasoning은 별도 모델 | 다국어 | ✗ | B — 컷오프 미확인, 비전 인코더 분리 필요 |
| **Qwen3.5-9B** | 9B 밀집 (GDN 하이브리드) | 2026-02 | Apache-2.0 | 미공개 (2025 포함 확실) | **불가** — vLLM이 GDN 레이어에서 `batch_invariant mode is not supported for GDN_ATTN`로 시작을 거부 (이슈 #42960) | Qwen3_5 / 지원 | on/off 가능 | 201 언어 | ✔ (Base 18G) | **C2 위반 → 현재 불가.** vLLM이 GDN 배치 불변을 구현하면 재검토 |
| Qwen3.6 | 27B, 35B-A3B만 공개 | 2026 | 미확인 | 2026 추정 | 불가 (GDN) | Qwen3_5 계열 | — | — | GGUF만 | C2·C3 위반 |
| Qwen3-8B | 8.2B 밀집 | 2025-04 | Apache-2.0 | 2025-03 ~ 2025-06 | 미측정 (표준 어텐션) | Qwen3ForCausalLM / 지원 | on/off 가능 | 119 언어 | FP8만 | B — **C1 위반** (2025 데이터 포함). 컷오프를 2026-01로 옮기면 A |
| HyperCLOVAX-SEED-Omni-8B | 8B (11B 총, 옴니) | 2026-01 | 자체 라이선스 (MAU 1천만 이상·경쟁 서비스는 별도 허가, 파생물에 "HyperCLOVA X" 명칭 의무) | **2025-05** | 미측정 | HyperCLOVAXForCausalLM / 지원 | 미확인 | **한국어 우선** | ✗ | B — C1 위반, 명칭 의무, 옴니 아키텍처 |
| gpt-oss-20b | 21B MoE (3.6B 활성) | 2025-08 | Apache-2.0 | 2024-06 | **불가** — fused-MoE 경로가 배치 불변이 아님 (이슈 #57016) | GptOss / 지원 | Harmony 포맷 필수 | 영어 중심 | ✗ | C2·C3 위반 |
| EXAONE 4.5 | 33B만 | 2026 | **NC (비상업)** | 2024-12 | — | 지원 | on/off | 한/영 | ✗ | C3·C4 위반 |
| Kanana 2 | 30B-A3B MoE | 2025-12 | **CC-BY-NC-4.0** | 미확인 | 불가 (MoE) | Kanana V만 등록 | — | 한국어 | ✗ | C2·C3·C4 위반 |
| Llama 3.1 8B | 8B 밀집 | 2024-07 | Llama 커뮤니티 (파생물 명칭 의무) | 2023-12 | 미측정 | Llama / 지원 | 없음 | 제한적 | ✗ | 현재 모델보다 오래됨. 2025~26년에 소형 밀집 신모델 없음 (Llama 4는 109B+ MoE) |
| SmolLM3-3B | 3B 밀집 | 2025-07 | Apache-2.0 | 2025 추정 | 미측정 | SmolLM3 / 지원 | on/off | 6개 언어 (한국어 아님) | ✔ | 너무 작고 C1 미확인 |

## 3. 후보별 평가

### Gemma 4 12B — 1순위
- **컷오프 2025-01**이 우리 시간 분할(2025-01-01)과 거의 일치한다. 2025년 1월 한 달치 겹침은 `temporal.CUTOFF`를 2025-02-01로 한 달 옮기거나 그대로 두고 기록하면 된다.
- Apache-2.0, 사전학습(`google/gemma-4-12B`)과 it 버전 모두 공개, 한국어 포함, vLLM 0.29에 `Gemma4ForCausalLM` 텍스트 경로가 있다. it 모델은 이미 DGX에 있다.
- 비용: 파라미터 1.55배 → 스텝당 약 200초 추정(측정 필요). 157스텝이면 조건당 ~8.7시간, 평가 ~4시간.
- **반드시 측정할 것**: 슬라이딩 윈도 + 글로벌 어텐션 혼합에서 배치 불변이 유지되는지 (vLLM 문서의 검증 목록에 없음). Gate 0 체크 06을 그대로 다시 돌리면 된다. thinking은 시스템 프롬프트의 `<|think|>` 토큰으로 제어되므로 채팅 템플릿 해시에 그 상태가 기록된다.
- E4B는 같은 조건에서 비용이 절반 이하다. 12B가 예산을 넘기면 E4B로 내려가는 사다리가 자연스럽다.

### OLMo 3 7B — 오염 연구 관점의 최선
- 컷오프 2024-12로 C1을 깨끗이 만족하고, **사전학습 데이터(Dolma 3)가 공개**되어 있다. 이 프로젝트가 지금 "추정"만 하는 사전학습 오염을 **직접 검사**할 수 있는 유일한 후보다 — 평가 CVE 설명문을 사전학습 코퍼스에서 grep하면 이전/이후 격차의 원인이 확정된다.
- Apache-2.0, 표준 트랜스포머(LoRA·패킹 코드 그대로), Think 변형은 별도 체크포인트라 thinking 문제가 없다.
- 단점: **영어 전용**. 한국어 리플레이·한국어 지시 능력 논의는 포기해야 한다. 범용 성능은 Qwen3.5·Gemma 4보다 낮다.

### Phi-4 14B — 컷오프·라이선스는 최적, 언어가 걸림
- MIT, 컷오프 2024-06, 밀집. 다국어 8%로 한국어는 기대할 수 없다. 스텝 비용 ~1.8배.

### A.X-4.0-Light 7B — 파이프라인 변경이 가장 적은 한국어 후보
- Qwen2.5-7B에서 파생된 Qwen2 아키텍처라 학습·평가 코드가 그대로 돌고, 배치 불변도 같은 커널 경로다 (재측정은 필요). Apache-2.0, 한국어 최적화.
- **컷오프가 미공개**다. SKT의 추가 학습에 2025년 데이터가 들어갔다면 C1 위반이다. 카드에 질문하거나, 2025년 CVE 몇 개로 직접 노출 여부를 탐침해 보는 것이 선행조건이다. 컨텍스트 16k는 충분하다.

### Qwen3.5-9B — 성능은 최선, 현재 파이프라인에서는 불가
- 가장 최신이고 다국어·성능 모두 우수하며 DGX에 Base가 있다. 그러나 **Gated DeltaNet 하이브리드 아키텍처** 때문에 vLLM이 `VLLM_BATCH_INVARIANT=1`을 거부한다 (`RuntimeError: VLLM batch_invariant mode is not supported for GDN_ATTN`, 이슈 #42960). Gate 4를 통과할 방법이 없다.
- 추가로 컷오프가 2025년을 포함해 C1도 어긴다 (컷오프 이동으로 해결 가능). LoRA 대상 모듈도 GDN 레이어에 맞춰 다시 정해야 한다.
- vLLM이 GDN 배치 불변을 구현하는 시점에 재검토할 가치가 크다.

### 제외
- **Qwen3.6**: 27B/35B-A3B만 공개, GDN. **gpt-oss-20b**: MoE 배치 불변 미지원, MXFP4 역양자화 필요. **EXAONE 4.5**: 33B, 비상업 라이선스. **Kanana 2**: MoE, CC-BY-NC. **Llama**: 2025~26년에 소형 밀집 신모델 없음.

## 4. 교체 시 필요한 재실행 (어느 후보든 공통)

| 순서 | 작업 | 예상 시간 (12B 기준) |
|---|---|---|
| 1 | Gate 0 재실행 (체크 03~07: 어텐션 백엔드, 생성 정상성, vLLM, **결정론 행렬**, 스텝 비용) | 1시간 |
| 2 | `ingest/sources.lock.json`의 토크나이저 핀 교체 → `make datasets` (토큰 수·패킹·T·157스텝 재도출) | 15분 |
| 3 | 컷오프 결정 기록 (Gemma 4면 2025-02-01 여부) | — |
| 4 | Gate 4 (평가 2회) + Cond-0 기준선 | ~8시간 |
| 5 | P5 재실행 (학습 2조건 + 평가 2회 + 탐침) | ~25시간 |

합계 약 1.5~2일의 DGX 시간. 지금 P5의 결과(리플레이 효과 유무)는 방법론으로서 그대로 유효하고, 새 모델에서 같은 질문을 다시 묻는 형태가 된다.

## 5. 권고

1. **P5는 Qwen2.5-7B로 끝낸다.** 지금 중단하면 학습 11시간이 버려지고, 얻는 것은 없다.
2. 다음 작업지시서에서 교체한다면 **Gemma 4 12B**를 1순위로, **E4B**를 예산 초과 시 대안으로 둔다. 선행조건은 배치 불변 측정 하나다.
3. 오염 연구를 더 밀어붙이려면 **OLMo 3 7B**를 병행 후보로 고려한다. 사전학습 데이터가 공개된 유일한 후보라 "추정"을 "측정"으로 바꿀 수 있다.
4. 한국어가 우선이면 **A.X-4.0-Light**의 컷오프를 먼저 확인한다.
5. **Qwen3.5/3.6은 vLLM의 GDN 배치 불변 지원 전까지 보류**한다. 이것은 성능 문제가 아니라 재현성 문제다.

## 출처

- Qwen3.5-9B / 9B-Base 모델 카드: https://huggingface.co/Qwen/Qwen3.5-9B , https://huggingface.co/Qwen/Qwen3.5-9B-Base
- Qwen3.6 (ollama 라이브러리): https://ollama.com/library/qwen3.6
- Qwen 컷오프 정리: https://aiknowledgecutoff.com/qwen , https://github.com/QwenLM/Qwen3/discussions/1093
- vLLM 배치 불변 — GDN 미지원: https://github.com/vllm-project/vllm/issues/42960 ; fused-MoE 미지원: https://github.com/vllm-project/vllm/issues/57016 ; 문서: https://docs.vllm.ai/en/latest/features/batch_invariance/
- Gemma 4: https://huggingface.co/google/gemma-4-12B , https://huggingface.co/google/gemma-4-12B-it , https://huggingface.co/google/gemma-4-E4B-it , https://blog.google/innovation-and-ai/technology/developers-tools/gemma-4/ , https://ai.google.dev/gemma/docs/core
- OLMo 3: https://huggingface.co/allenai/Olmo-3-7B-Instruct , https://arxiv.org/abs/2512.13961 , https://allenai.org/blog/olmo3
- Phi-4: https://huggingface.co/microsoft/phi-4
- A.X-4.0-Light: https://huggingface.co/skt/A.X-4.0-Light
- Ministral 3 8B: https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512 , https://mistral.ai/news/mistral-3/
- HyperCLOVA X SEED: https://huggingface.co/collections/naver-hyperclovax/hyperclova-x-seed , https://huggingface.co/naver-hyperclovax/HyperCLOVAX-SEED-Omni-8B (LICENSE 포함)
- EXAONE 4.5: https://huggingface.co/LGAI-EXAONE/EXAONE-4.5-33B
- Kanana 2: https://huggingface.co/collections/kakaocorp/kanana-2 , https://github.com/kakao/kanana-2/
- gpt-oss: https://huggingface.co/openai/gpt-oss-20b , https://github.com/openai/gpt-oss , https://unsloth.ai/docs/models/gpt-oss-how-to-run-and-fine-tune
- Llama 계열 현황: https://en.wikipedia.org/wiki/Llama_(language_model) , https://hidekazu-konishi.com/entry/open_weights_llm_release_history_and_timeline.html
- 이 DGX의 vLLM 0.29.0 레지스트리와 HF 캐시 목록: 2026-09-20 직접 조회
