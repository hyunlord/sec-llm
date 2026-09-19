# P4 평가 하네스 — 설계와 한계

> 설정값·핀·해시는 `runs/baseline/manifest.json`에서 읽어 렌더링한다. 재생성: `python -m eval.stats --run baseline --render-harness`.

## 이 하네스가 존재하는 이유

P5의 두 조건이 **다른지 아닌지**를 P5가 돌기 전에 판정할 수 있게 하는 것. 그러려면 숫자가 질문을 견뎌야 한다: 재현 가능하고, 오염 계층별로 나뉘어 있고, 못 보는 것을 솔직하게 말해야 한다.

## 타협 불가능한 실행 설정

Gate 0이 이 기계에서 측정한 두 사실 위에 세워져 있다. 그리디 디코딩은 `VLLM_BATCH_INVARIANT=1` 없이는 바이트 단위로 재현되지 않으며(순차 실행에서도 15회 중 2가지 출력), 배치 불변 커널은 1.073배 비용이 든다. 그리고 FlashInfer 샘플러는 시작할 때 JIT 컴파일하므로 `VLLM_USE_FLASHINFER_SAMPLER=0`이 필요하다.

| 설정 | 값 | 기록 위치 |
|---|---|---|
| `PIP_ONLY_BINARY` | `:all:` | 실행 매니페스트 `env` |
| `VLLM_BATCH_INVARIANT` | `1` | 실행 매니페스트 `env` |
| `VLLM_USE_FLASHINFER_SAMPLER` | `0` | 실행 매니페스트 `env` |
| 샘플링 | temperature 0.0, top_p 1.0, seed 1234 | `sampling` |
| vLLM 엔진 | {"gpu_memory_utilization": 0.45, "max_model_len": 8192, "max_num_seqs": 256, "seed": 1234} | `vllm_engine` (Gate 0 검사 05·06에서 검증된 값 그대로) |

**이 중 하나라도 매니페스트에 없는 실행은 무효이고, 채점기가 거부한다** — `eval/common.py`의 `check_manifest_settings`가 강제한다. 또한 실행의 첫 동작은 데이터셋 매니페스트 해시를 디스크와 대조하는 것이다. 드리프트한 데이터셋에 대해 계산한 점수는 점수가 없는 것보다 나쁘다.

## 네 개의 축

| 축 | 무엇을 재나 | 채점기 |
|---|---|---|
| 스키마 | 출력이 파싱되고 과제 JSON Schema를 통과하는가 | `jsonschema`, 기계적 |
| 과제 정확도 | 정확 일치 / 필드별 정확도 / 필드 정밀도·재현율 | 기계적 |
| 범용 능력 | 망각 검사: MMLU 부분집합, HellaSwag | 기계적 |
| 샌드박스 | CVSS v3.1 공식을 컨테이너에서 실행해 NVD 점수와 대조 | Docker, 기계적 |

**어떤 것도 언어 모델이 채점하지 않는다.** 정규화 규칙은 전부 선언되어 있다: 앞뒤 공백 제거와 마크다운 코드펜스 한 겹 제거뿐이며, 산문 속에서 JSON을 파내거나 따옴표를 고치지 않는다.

## 계층화

`zero: coverage==0; low: 0<coverage<=median(positive); high: coverage>median(positive)`

> recorded quartiles are deliberately not used: coverage is zero-inflated and quartile boundaries collapse, which makes quartile strata incomparable across evaluation sets

| 평가 세트 | 양수 중앙값(분할점) | zero | low | high |
|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 0.0514 | 72 | 4 | 3 |
| `attack_technique/eval_pre_cutoff` | 0.2472 | 44 | 18 | 17 |
| `cve_to_cwe/eval_post_cutoff` | 0.2 | 2,815 | 544 | 508 |
| `cve_to_cwe/eval_pre_cutoff` | 0.3514 | 2,018 | 999 | 997 |
| `cvss_vector/eval_post_cutoff` | 0.2 | 3,116 | 747 | 686 |
| `cvss_vector/eval_pre_cutoff` | 0.3448 | 2,496 | 1,205 | 1,203 |
| `structured_extract/eval_post_cutoff` | 0.2292 | 2,177 | 577 | 574 |
| `structured_extract/eval_pre_cutoff` | 0.381 | 936 | 686 | 685 |

계층 표가 답하는 두 질문: **정확도가 커버리지와 함께 오르는가**(그 격차가 암기다), 그리고 **컷오프 이후/이전 격차가 계층으로 설명되는가, 아니면 각 계층 안에서도 남는가**(zero 계층에서도 남으면 그 오염은 어휘적이지 않다).

## 통계 규칙

- 보고하는 모든 비율에 부트스트랩 1,000회 재표집, 95% 백분위 구간. **구간 없는 비율은 보고하지 않는다.**
- 조건 비교는 같은 항목을 짝지어 McNemar로 한다 (불일치쌍 25 미만이면 정확 이항검정).
- **구간이 겹치면 결론은 '차이 검출되지 않음'이다.** '경향', '약간 우세' 같은 표현을 쓰지 않는다. 이 판정 문자열은 하네스가 직접 출력하므로, 보고서가 숫자보다 강하게 쓰일 수 없다.
- 귀무 결과와 검정력 부족을 구분하기 위해 세트별 MDD(검출 가능한 최소 차이)를 함께 싣는다.

## 동시성은 처리량 설정이지 결과 설정이 아니다 (측정)

`cvss_vector/eval_post_cutoff/free, first 256 items, identical settings otherwise`에서 동시 시퀀스 상한만 바꾸고 나머지는 동일하게 두고 측정했다.

| `max_num_seqs` | 초 | 출력 토큰/초 | 출력 파일 sha256 |
|---|---|---|---|
| 16 | 245.1 | 212.6 | `53ef079b93cd0f0fbe3ea04d…` |
| 64 | 84.4 | 617.8 | `53ef079b93cd0f0fbe3ea04d…` |
| 256 | 41.8 | 1245.8 | `53ef079b93cd0f0fbe3ea04d…` |

**세 설정의 출력이 바이트 단위로 동일하다: True**. 처리량은 5.86배 차이가 난다. batch invariance makes the generated text independent of the concurrency cap across a 16x range, so the cap is a throughput setting and not a result setting. Gate 0 measured the property at batch size one; this measures it at evaluation scale.

그래서 이 하네스는 `max_num_seqs=256`을 쓴다 (Gate 0 참조값 16). 이 값은 매니페스트에 기록되고, Gate 4가 **실제로 쓰인 그 값에서** 재현성을 증명한다.

## 결정론 게이트 (Gate 4)

기준선 모델로 전체 평가를 **두 번** 돌려 모든 생성 출력이 바이트 단위로 같고 모든 점수가 같아야 통과한다. 하나라도 다르면 다른 항목을 보고하고 채점을 거부한다. Gate 0은 이 기계에서 배치 불변성 없이는 순차 실행조차 갈라진다는 것을 보였다. Gate 4는 그 해법이 **전체 평가 규모, 실제 배치 혼합에서도** 유지되는지를 증명한다.

## 이 하네스가 측정하지 못하는 것

이 절을 읽지 않고 이 저장소의 숫자를 인용하면 과대주장이 된다.

1. **보안 역량을 재지 않는다.** 취약점을 찾거나, 익스플로잇을 쓰거나, 사고를 분석하거나, 방어를 설계하는 능력에 대해 이 숫자들은 아무 말도 하지 않는다. 재는 것은 공개 취약점 데이터베이스의 **구조화 필드를 회수·추출하는 능력**이다.
2. **과제는 추론이 아니라 회수와 구조 추출이다.** `cve_to_cwe`는 분류, `cvss_vector`는 고정 어휘로의 사상, `structured_extract`는 CNA가 이미 채운 구조를 산문에서 되찾는 일이다. 어느 것도 다단계 추론을 요구하지 않는다.
3. **평가 세트에 CNA 편향이 있다.** 네 출처(CVE List V5, NVD, CWE, ATT&CK)에서 나왔고, 소수 CNA가 설명문의 큰 비중을 차지하며 그 CNA들은 템플릿을 쓴다. 학습 세트와의 CNA 총변동거리는 데이터셋 매니페스트에 기록되어 있다 (`reports/contamination.md`).
4. **`attack_technique`는 너무 작다.** 학습 738건, 평가 79/79건. 신뢰구간이 ±10퍼센트포인트를 넘는다. 매니페스트에 `scored: false`로 표시되어 있고, 서술적으로만 보고하며 **조건 간 비교에 절대 쓰지 않는다.**
5. **범용 능력 숫자는 리더보드와 비교할 수 없다.** 표준 MMLU/HellaSwag 프로토콜은 선택지별 로그 우도를 비교하지만 이 하네스는 모델이 생성한 글자를 읽는다. 조건 간 비교에는 유효하고 절대값 인용에는 무효다.
6. **컷오프 이전/이후 격차는 사전학습 오염의 *추정치*이지 측정치가 아니다.** 모델의 사전학습 데이터를 볼 수 없으므로 격차의 원인을 시점 이외의 요인(난이도 변화, CNA 구성 변화, CWE 라벨 출처 변화)과 완전히 분리할 수 없다. 그래서 `cwe_source`와 계층을 함께 싣는다.
7. **근접 중복 임계값 0.75는 아직 보정되지 않았다.** P2.1이 네 번 요청되고 전달되지 않았다. 데이터셋 매니페스트에 `P2 calibration (P2.1 not delivered)`로 기록되어 있다. 이 값이 바뀌면 평가 세트가 다시 만들어지고 **이 하네스가 만든 모든 숫자를 다시 계산해야 한다.** 이 결과는 최종이 아니다.
8. **단일 시드, 단일 체크포인트.** 그리디 디코딩이라 샘플링 분산은 없지만, 학습 시드에 따른 분산은 이 하네스가 재지 않는다. P5가 조건당 한 번씩만 학습한다면 조건 간 차이에는 학습 시드 분산이 섞여 있다.

## 산출물 구조

```
runs/<run_id>/manifest.json   설정·해시·버전·타이밍
runs/<run_id>/outputs.jsonl   모든 생성 원문 (재채점의 근거)
runs/<run_id>/scores.json     모든 점수와 구간
```

원문 출력을 실행마다 보관한다. 그것이 모든 점수의 증거이고, 다시 생성하지 않고 다시 채점할 수 있게 한다 (채점에 GPU가 필요 없다).

