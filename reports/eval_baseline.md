# P4 기준선 평가 결과 — Cond-0 (Qwen/Qwen2.5-7B-Instruct, 미세조정 없음)

> `runs/baseline/scores.json`과 `manifest.json`에 **기록된 값**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 (`docs/engineering-rules.md` 규칙 1). 재생성: `python -m eval.stats --run baseline --render`.

## 이 실행이 무엇이었나 (전부 매니페스트 기록)

| 항목 | 값 |
|---|---|
| 모델 | `Qwen/Qwen2.5-7B-Instruct` 커밋 `a09a35458c70` |
| 체크포인트 해시 | `2564ff2127caa0a9…` (11 파일) |
| 토크나이저 / 채팅 템플릿 | `38c75a3be3e7b110…` / `cd8e9439f0570856…` |
| 데이터셋 매니페스트 | `61c060f77d28f954…` (실행 시작 시 디스크와 대조 검증) |
| 출력 파일 | `outputs.jsonl` `3ac8e5c5b18b8405…`, 48,254 건 |
| `PIP_ONLY_BINARY` | `:all:` |
| `VLLM_BATCH_INVARIANT` | `1` |
| `VLLM_USE_FLASHINFER_SAMPLER` | `0` |
| 샘플링 | temperature 0.0, top_p 1.0, seed 1234 |
| vLLM 엔진 | {"gpu_memory_utilization": 0.45, "max_model_len": 8192, "max_num_seqs": 256, "seed": 1234} |
| 구조화 출력 백엔드 | `xgrammar` |
| 버전 | vLLM 0.29.0, torch 2.13.0+cu130, transformers 5.17.0 |
| GPU / 드라이버 | NVIDIA GB10 / 580.126.09 |
| 메모리 상한 | systemd-run --user --scope `MemoryMax=80G` |
| 생성 상한 | max_model_len - prompt tokens - 8, per item; no cap chosen by the harness |

**1회 전체 평가 통과 벽시계: 2.66 시간** (생성 2.63 h, 모델 로드 104.7s). P5는 이것을 조건마다 실행한다.

## 스키마 유효성과 정확도는 따로 본다

파싱되지 않은 출력은 틀린 답이 아니라 **다른 종류의 실패**다. 둘을 합치면 조건이 형식을 잃었는지 지식을 잃었는지 구분할 수 없다. 그래서 스키마 유효율과 정확도를 따로 싣고, 정확도는 **스키마 유효 출력만**을 분모로 한 값과 **전체 항목**을 분모로 한 값을 모두 싣는다.

| 과제/분할/디코딩 | 채점 | 항목 | 파싱 | 스키마 유효 | 정확도(유효 분모) | 정확도(전체 분모) | 절단 |
|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff/constrained` | **아니오** | 79 | 100.0% | **100.0%** [100.0–100.0] n=79 | **0.0%** [0.0–0.0] n=79 | **0.0%** [0.0–0.0] n=79 | 0 |
| `attack_technique/eval_post_cutoff/free` | **아니오** | 79 | 100.0% | **92.4%** [86.1–97.5] n=79 | **0.0%** [0.0–0.0] n=73 | **0.0%** [0.0–0.0] n=79 | 0 |
| `attack_technique/eval_pre_cutoff/constrained` | **아니오** | 79 | 100.0% | **100.0%** [100.0–100.0] n=79 | **0.0%** [0.0–0.0] n=79 | **0.0%** [0.0–0.0] n=79 | 0 |
| `attack_technique/eval_pre_cutoff/free` | **아니오** | 79 | 100.0% | **92.4%** [86.1–97.5] n=79 | **0.0%** [0.0–0.0] n=73 | **0.0%** [0.0–0.0] n=79 | 0 |
| `cve_to_cwe/eval_post_cutoff/constrained` | 예 | 3,867 | 100.0% | **100.0%** [100.0–100.0] n=3,867 | **39.0%** [37.6–40.7] n=3,867 | **39.0%** [37.6–40.7] n=3,867 | 0 |
| `cve_to_cwe/eval_post_cutoff/free` | 예 | 3,867 | 97.8% | **72.5%** [71.1–73.9] n=3,867 | **42.8%** [41.0–44.7] n=2,802 | **31.0%** [29.6–32.6] n=3,867 | 1 |
| `cve_to_cwe/eval_pre_cutoff/constrained` | 예 | 4,014 | 100.0% | **100.0%** [100.0–100.0] n=4,014 | **51.1%** [49.6–52.6] n=4,014 | **51.1%** [49.6–52.6] n=4,014 | 0 |
| `cve_to_cwe/eval_pre_cutoff/free` | 예 | 4,014 | 97.4% | **72.8%** [71.4–74.2] n=4,014 | **54.9%** [53.2–56.7] n=2,923 | **40.0%** [38.5–41.5] n=4,014 | 0 |
| `cvss_vector/eval_post_cutoff/constrained` | 예 | 4,549 | 100.0% | **100.0%** [100.0–100.0] n=4,549 | **18.0%** [16.9–19.1] n=4,549 | **18.0%** [16.9–19.1] n=4,549 | 0 |
| `cvss_vector/eval_post_cutoff/free` | 예 | 4,549 | 33.5% | **0.2%** [0.0–0.3] n=4,549 | **28.6%** [0.0–57.1] n=7 | **0.0%** [0.0–0.1] n=4,549 | 17 |
| `cvss_vector/eval_pre_cutoff/constrained` | 예 | 4,904 | 100.0% | **100.0%** [100.0–100.0] n=4,904 | **24.2%** [23.0–25.4] n=4,904 | **24.2%** [23.0–25.4] n=4,904 | 0 |
| `cvss_vector/eval_pre_cutoff/free` | 예 | 4,904 | 33.9% | **0.1%** [0.0–0.3] n=4,904 | **0.0%** [0.0–0.0] n=7 | **0.0%** [0.0–0.0] n=4,904 | 23 |
| `structured_extract/eval_post_cutoff/constrained` | 예 | 3,328 | 99.8% | **99.8%** [99.6–99.9] n=3,328 | **9.4%** [8.3–10.4] n=3,321 | **9.3%** [8.4–10.4] n=3,328 | 7 |
| `structured_extract/eval_post_cutoff/free` | 예 | 3,328 | 98.1% | **87.5%** [86.4–88.5] n=3,328 | **10.3%** [9.3–11.5] n=2,911 | **9.0%** [8.1–10.1] n=3,328 | 16 |
| `structured_extract/eval_pre_cutoff/constrained` | 예 | 2,307 | 99.8% | **99.8%** [99.7–100.0] n=2,307 | **8.5%** [7.4–9.6] n=2,303 | **8.5%** [7.4–9.6] n=2,307 | 4 |
| `structured_extract/eval_pre_cutoff/free` | 예 | 2,307 | 97.6% | **85.6%** [84.0–86.8] n=2,307 | **9.6%** [8.3–10.9] n=1,974 | **8.2%** [7.2–9.4] n=2,307 | 3 |

괄호 안은 95% 부트스트랩 구간 (1,000회 재표집, 고정 시드). 구간 없는 비율은 보고하지 않는다.

## 오염 계층별 결과 — 사분위가 아니라 zero / low / high

P3.2가 모든 평가 항목에 붙인 `train_ngram_coverage`를 쓴다. **기록된 사분위는 쓰지 않는다**: 커버리지가 0에 몰려 있어 (`cve_to_cwe/eval_post_cutoff`의 72.8%가 정확히 0) q25와 q50이 모두 0.0이 되고 세트 간 비교가 불가능하다. 대신 각 세트의 **양수 값 중앙값**을 분할점으로 쓴다 — 누가 정한 수준이 아니라 데이터에서 읽은 위치다.

| 과제/분할/디코딩 | 분할점 | zero (n) | low (n) | high (n) |
|---|---|---|---|---|
| `attack_technique/eval_post_cutoff/constrained` **[미채점]** | 0.0514 | **0.0%** [0.0–0.0] n=72 | **0.0%** [0.0–0.0] n=4 | **0.0%** [0.0–0.0] n=3 |
| `attack_technique/eval_post_cutoff/free` **[미채점]** | 0.0514 | **0.0%** [0.0–0.0] n=72 | **0.0%** [0.0–0.0] n=4 | **0.0%** [0.0–0.0] n=3 |
| `attack_technique/eval_pre_cutoff/constrained` **[미채점]** | 0.2472 | **0.0%** [0.0–0.0] n=44 | **0.0%** [0.0–0.0] n=18 | **0.0%** [0.0–0.0] n=17 |
| `attack_technique/eval_pre_cutoff/free` **[미채점]** | 0.2472 | **0.0%** [0.0–0.0] n=44 | **0.0%** [0.0–0.0] n=18 | **0.0%** [0.0–0.0] n=17 |
| `cve_to_cwe/eval_post_cutoff/constrained` | 0.2 | **37.9%** [36.1–39.6] n=2,815 | **35.7%** [31.8–39.9] n=544 | **49.0%** [44.9–53.3] n=508 |
| `cve_to_cwe/eval_post_cutoff/free` | 0.2 | **28.9%** [27.3–30.6] n=2,815 | **29.6%** [25.7–33.6] n=544 | **44.3%** [40.0–48.6] n=508 |
| `cve_to_cwe/eval_pre_cutoff/constrained` | 0.3514 | **49.1%** [46.9–51.1] n=2,018 | **52.4%** [49.3–55.4] n=999 | **54.1%** [51.0–57.2] n=997 |
| `cve_to_cwe/eval_pre_cutoff/free` | 0.3514 | **38.4%** [36.3–40.6] n=2,018 | **40.5%** [37.6–43.5] n=999 | **42.7%** [39.7–45.9] n=997 |
| `cvss_vector/eval_post_cutoff/constrained` | 0.2 | **15.4%** [14.1–16.7] n=3,116 | **18.1%** [15.3–20.9] n=747 | **29.7%** [26.5–33.1] n=686 |
| `cvss_vector/eval_post_cutoff/free` | 0.2 | **0.0%** [0.0–0.1] n=3,116 | **0.0%** [0.0–0.0] n=747 | **0.1%** [0.0–0.4] n=686 |
| `cvss_vector/eval_pre_cutoff/constrained` | 0.3448 | **22.0%** [20.4–23.7] n=2,496 | **26.5%** [23.9–29.0] n=1,205 | **26.3%** [23.8–28.8] n=1,203 |
| `cvss_vector/eval_pre_cutoff/free` | 0.3448 | **0.0%** [0.0–0.0] n=2,496 | **0.0%** [0.0–0.0] n=1,205 | **0.0%** [0.0–0.0] n=1,203 |
| `structured_extract/eval_post_cutoff/constrained` | 0.2292 | **4.6%** [3.7–5.5] n=2,177 | **18.2%** [15.1–21.3] n=577 | **18.5%** [15.2–21.6] n=574 |
| `structured_extract/eval_post_cutoff/free` | 0.2292 | **4.5%** [3.6–5.4] n=2,177 | **18.4%** [15.3–21.5] n=577 | **16.9%** [13.8–20.0] n=574 |
| `structured_extract/eval_pre_cutoff/constrained` | 0.381 | **2.5%** [1.5–3.4] n=936 | **11.1%** [8.7–13.6] n=686 | **14.0%** [11.5–16.6] n=685 |
| `structured_extract/eval_pre_cutoff/free` | 0.381 | **2.9%** [1.8–4.1] n=936 | **11.1%** [8.9–13.6] n=686 | **12.6%** [10.2–15.2] n=685 |

### 이 표를 Cond-0에서 읽는 법 — 여기서 커버리지 격차는 암기가 아니다

여섯 개 채점 세트 **전부**에서 커버리지가 높을수록 정확도가 높다. 그러나 **기준선 모델은 우리 학습 세트를 본 적이 없다.** 따라서 Cond-0에서 커버리지 계층이 재는 것은 암기가 아니라 **설명문이 얼마나 정형화되어 있는가**다 — 우리 코퍼스와 13-gram을 많이 공유하는 항목은 템플릿으로 쓰인 항목이고, 템플릿으로 쓰인 항목이 기준선에게 더 쉽다.

**그래서 이 표가 P5의 기준선이다.** 같은 항목, 같은 계층 경계로 미세조정 후를 재서 **high 계층이 zero 계층보다 더 많이 올랐다면 그 초과분이 암기의 측정값**이다. 여기서는 그 초과분을 잴 수 없고, 잴 수 있는 것은 출발점뿐이다. P3.2가 커버리지 높은 항목 2,483건을 지우는 대신 필드로 붙여 둔 덕분에 이 측정이 가능하다 — 삭제했다면 이 표 자체가 존재할 수 없다.

**high 계층은 일부 세트에서 얇다** (전체 커버리지 히스토그램은 [0.0,0.1)에 15,519건, [0.9,1.0)에 188건). 얇은 계층의 구간은 넓고, 넓은 구간은 점추정값처럼 읽어서는 안 된다.

## 컷오프 이후 vs 이전 — 이 파이프라인 자신의 사전학습 오염 추정치

| 과제/디코딩 | 이후 | 이전 | 격차(이전−이후) | 판정 | zero 계층 격차 |
|---|---|---|---|---|---|
| `attack_technique/constrained` **[미채점]** | **0.0%** [0.0–0.0] n=79 | **0.0%** [0.0–0.0] n=79 | 0.0% | **no difference detected** | 0.0% |
| `attack_technique/free` **[미채점]** | **0.0%** [0.0–0.0] n=79 | **0.0%** [0.0–0.0] n=79 | 0.0% | **no difference detected** | 0.0% |
| `cve_to_cwe/constrained` | **39.0%** [37.6–40.7] n=3,867 | **51.1%** [49.6–52.6] n=4,014 | 12.1% | **difference detected** | 11.2% |
| `cve_to_cwe/free` | **31.0%** [29.6–32.6] n=3,867 | **40.0%** [38.5–41.5] n=4,014 | 9.0% | **difference detected** | 9.5% |
| `cvss_vector/constrained` | **18.0%** [16.9–19.1] n=4,549 | **24.2%** [23.0–25.4] n=4,904 | 6.2% | **difference detected** | 6.6% |
| `cvss_vector/free` | **0.0%** [0.0–0.1] n=4,549 | **0.0%** [0.0–0.0] n=4,904 | -0.0% | **no difference detected** | -0.0% |
| `structured_extract/constrained` | **9.3%** [8.4–10.4] n=3,328 | **8.5%** [7.4–9.6] n=2,307 | -0.9% | **no difference detected** | -2.1% |
| `structured_extract/free` | **9.0%** [8.1–10.1] n=3,328 | **8.2%** [7.2–9.4] n=2,307 | -0.9% | **no difference detected** | -1.6% |

### 이 격차를 어디까지 말할 수 있나

기준선 모델은 우리 학습 세트를 보지 않았으므로 이 격차는 **우리 데이터의 누수가 아니다**. 남는 설명은 두 가지이고 이 하네스는 둘을 분리하지 못한다: (1) 모델이 사전학습에서 오래된 CVE를 이미 봤다, (2) 오래된 CVE가 그냥 더 쉽다 (CNA 구성, CWE 라벨 출처, 설명문 길이가 시간에 따라 다르다 — `datasets/CARD.md` 참조). **zero 계층에서도 격차가 거의 그대로 남는다는 사실**은 최소한 그 격차가 우리 코퍼스와의 어휘 중복으로는 설명되지 않는다는 것을 말해 준다.


컷오프 이전 세트가 더 높다면 그 차이는 모델이 사전학습에서 이미 본 CVE라는 뜻이다. **zero 계층에서도 격차가 남으면 그 오염은 어휘적(13-gram)이 아니다** — 즉 커버리지로는 잡히지 않는 형태의 사전 노출이다.

## 자유 생성 vs 스키마 제약 생성

| 과제/분할 | 자유 스키마유효 | 제약 스키마유효 | 형식 격차 | 정확도 격차 | McNemar p (형식) | 판정 |
|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` **[미채점]** | 92.4% | 100.0% | 7.6% | 0.0% | 0.0312 | **difference detected** |
| `attack_technique/eval_pre_cutoff` **[미채점]** | 92.4% | 100.0% | 7.6% | 0.0% | 0.0312 | **difference detected** |
| `cve_to_cwe/eval_post_cutoff` | 72.5% | 100.0% | 27.5% | 8.0% | 3.64e-233 | **difference detected** |
| `cve_to_cwe/eval_pre_cutoff` | 72.8% | 100.0% | 27.2% | 11.1% | 8.12e-239 | **difference detected** |
| `cvss_vector/eval_post_cutoff` | 0.2% | 100.0% | 99.8% | 18.0% | 0 | **difference detected** |
| `cvss_vector/eval_pre_cutoff` | 0.1% | 100.0% | 99.9% | 24.2% | 0 | **difference detected** |
| `structured_extract/eval_post_cutoff` | 87.5% | 99.8% | 12.3% | 0.3% | 2.69e-90 | **difference detected** |
| `structured_extract/eval_pre_cutoff` | 85.6% | 99.8% | 14.3% | 0.3% | 4.32e-73 | **difference detected** |

형식 격차는 **스키마 준수 중 디코더가 만들어낸 몫**이다. 정확도 격차가 0이 아니면 제약이 형식만이 아니라 내용도 바꿨다는 뜻이다.

## `cvss_vector` 필드별 정확도 (스키마 유효 출력 분모)

| 과제/분할/디코딩 | `attackComplexity` | `attackVector` | `availabilityImpact` | `baseScore` | `confidentialityImpact` | `integrityImpact` | `privilegesRequired` | `scope` | `userInteraction` | `vectorString` |
|---|---|---|---|---|---|---|---|---|---|---|
| `cvss_vector/eval_post_cutoff/constrained` | 92.0% | 85.6% | 59.5% | 12.5% | 65.2% | 63.3% | 69.6% | 77.1% | 79.7% | 19.3% |
| `cvss_vector/eval_post_cutoff/free` | 100.0% | 71.4% | 71.4% | 14.3% | 85.7% | 85.7% | 71.4% | 100.0% | 100.0% | 28.6% |
| `cvss_vector/eval_pre_cutoff/constrained` | 96.8% | 85.0% | 75.6% | 14.5% | 70.6% | 73.8% | 68.7% | 77.5% | 72.3% | 26.6% |
| `cvss_vector/eval_pre_cutoff/free` | 100.0% | 100.0% | 71.4% | 0.0% | 57.1% | 100.0% | 28.6% | 100.0% | 100.0% | 0.0% |

`scope`는 특히 중요하다 — 권한 가중치와 최종 점수를 함께 바꾼다. 8개 지표가 모두 맞고 벡터 문자열까지 같은 경우만 `whole_vector_exact`로 센다.

## `structured_extract` 필드별 정밀도 / 재현율

| 과제/분할/디코딩 | vendor P/R | product P/R | versions P/R | versions 집합일치 | impact P/R | impact 허위생성 |
|---|---|---|---|---|---|---|
| `structured_extract/eval_post_cutoff/constrained` | 52.2%/52.2% | 54.7%/54.7% | 13.7%/19.9% | 17.7% | 6.8%/25.4% | 2136 |
| `structured_extract/eval_post_cutoff/free` | 55.0%/55.0% | 57.3%/57.3% | 17.8%/21.4% | 19.2% | 7.8%/27.6% | 1822 |
| `structured_extract/eval_pre_cutoff/constrained` | 50.9%/50.9% | 39.3%/39.3% | 16.4%/19.3% | 17.9% | 0.1%/1.1% | 1686 |
| `structured_extract/eval_pre_cutoff/free` | 52.9%/52.9% | 42.8%/42.8% | 19.7%/21.8% | 20.2% | 0.1%/1.5% | 1434 |

`impact`는 정답이 null인 항목을 정확도 분모에서 제외한다 (`datasets/CARD.md` 지침). 정답이 null인데 값을 만들어낸 건수는 따로 센다 — 분모에서 빠졌다고 사라지지 않는다.

## 범용 능력 (망각 검사) — P5의 기준선

| 세트 | 항목 | 글자 추출률 | 정확도(추출 분모) | 정확도(전체 분모) | MDD |
|---|---|---|---|---|---|
| `hellaswag` (Rowan/hellaswag `218ec52e`) | 1,000 | 100.0% | **83.7%** [81.5–85.8] n=1,000 | **83.7%** [81.5–85.8] n=1,000 | ±4.6pp |
| `mmlu` (cais/mmlu `c30699e8`) | 1,000 | 100.0% | **71.2%** [68.4–74.3] n=1,000 | **71.2%** [68.4–74.3] n=1,000 | ±5.7pp |

이 숫자는 **공개 리더보드 점수와 비교할 수 없다**: 표준 프로토콜은 선택지별 로그 우도를 비교하지만 여기서는 모델이 생성한 글자를 읽는다. 조건 간 비교에는 유효하고, 절대값 인용에는 무효다. `reports/eval_harness.md` 참조.

## 샌드박스 축 — 실행으로 채점

| 그룹 | 항목 | 벡터 실행 성공 | 점수 일치(실행 분모) | 공식 자체검증 | 컨테이너 | 타임아웃 | 초 |
|---|---|---|---|---|---|---|---|
| `cvss_vector/eval_post_cutoff/constrained` | 4,549 | 100.0% | 21.3% | **100.0%** (4,549) | 1 | 0 | 0.32 |
| `cvss_vector/eval_post_cutoff/free` | 4,549 | 0.2% | 28.6% | **100.0%** (4,549) | 1 | 0 | 0.3 |
| `cvss_vector/eval_pre_cutoff/constrained` | 4,904 | 100.0% | 28.4% | **100.0%** (4,904) | 1 | 0 | 0.3 |
| `cvss_vector/eval_pre_cutoff/free` | 4,904 | 0.1% | 0.0% | **100.0%** (4,904) | 1 | 0 | 0.29 |

컨테이너: `python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff` `sha256:c62d7c95d6ea…`, 플래그 `--network=none --memory=512m --pids-limit=128 --read-only --tmpfs /tmp --security-opt no-new-privileges:true`, 타임아웃 30s.
**공식 자체검증**은 NVD 자신의 벡터로 점수를 계산해 NVD가 기록한 점수와 비교한 값이다. 이것이 100%가 아니면 위의 모델 점수 일치율은 공식 구현 오류를 모델 결과로 잘못 보고하는 것이 된다.

## 생성 비용 — P5가 이것을 세 번 돌린다

| 과제/분할/디코딩 | 출력 토큰 중앙값 | p99 | 최대 | 총 출력 토큰 | 상위 1%가 차지하는 비율 | 문맥 한계까지 간 항목 |
|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff/constrained` | 13 | 17 | 17 | 1,119 | 1.5% | 0 |
| `attack_technique/eval_post_cutoff/free` | 14 | 100 | 100 | 1,377 | 7.3% | 0 |
| `attack_technique/eval_pre_cutoff/constrained` | 13 | 17 | 17 | 1,103 | 1.5% | 0 |
| `attack_technique/eval_pre_cutoff/free` | 14 | 62 | 62 | 1,340 | 4.6% | 0 |
| `cve_to_cwe/eval_post_cutoff/constrained` | 14 | 14 | 15 | 52,722 | 1.0% | 0 |
| `cve_to_cwe/eval_post_cutoff/free` | 13 | 150 | 8,034 | 68,222 | 22.7% | 1 |
| `cve_to_cwe/eval_pre_cutoff/constrained` | 14 | 14 | 15 | 54,612 | 1.1% | 0 |
| `cve_to_cwe/eval_pre_cutoff/free` | 13 | 136 | 346 | 64,154 | 12.0% | 0 |
| `cvss_vector/eval_post_cutoff/constrained` | 115 | 117 | 119 | 526,470 | 1.0% | 0 |
| `cvss_vector/eval_post_cutoff/free` | 426 | 1,107 | 8,080 | 2,025,126 | 8.5% | 17 |
| `cvss_vector/eval_pre_cutoff/constrained` | 115 | 118 | 119 | 567,705 | 1.0% | 0 |
| `cvss_vector/eval_pre_cutoff/free` | 424 | 1,144 | 8,095 | 2,182,998 | 10.0% | 23 |
| `structured_extract/eval_post_cutoff/constrained` | 52 | 200 | 8,072 | 260,653 | 23.7% | 7 |
| `structured_extract/eval_post_cutoff/free` | 57 | 1,993 | 8,060 | 434,968 | 44.1% | 16 |
| `structured_extract/eval_pre_cutoff/constrained` | 49 | 185 | 8,101 | 163,467 | 22.6% | 4 |
| `structured_extract/eval_pre_cutoff/free` | 54 | 365 | 8,066 | 193,935 | 26.1% | 3 |

1회 통과 벽시계 **2.66 시간** 중 생성이 2.63 시간이다. **비용은 꼬리에서 나온다**: 자유 생성에서 상위 1% 항목이 전체 출력 토큰의 상당 부분을 차지한다. 제약 생성은 문법이 조기 종료를 강제하므로 같은 항목 수에 훨씬 적은 토큰을 쓴다. P5가 조건마다 한 번씩 돌릴 때의 예산은 이 표에서 나온다.

## 검출 가능한 최소 차이 (MDD)

귀무 결과와 검정력 부족을 구분하기 위해, 각 세트의 n에서 유의수준 0.05·검정력 0.80으로 검출 가능한 최소 차이를 싣는다. 짝지은 McNemar 검정은 이보다 검정력이 높으므로 아래 값은 **보수적 상한**이다.

| 과제/분할/디코딩 | n | 정확도 | MDD | zero MDD | low MDD | high MDD |
|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff/constrained` **[미채점]** | 79 | 0.0% | ±0.0pp | ±0.0pp | ±0.0pp | ±0.0pp |
| `attack_technique/eval_post_cutoff/free` **[미채점]** | 79 | 0.0% | ±0.0pp | ±0.0pp | ±0.0pp | ±0.0pp |
| `attack_technique/eval_pre_cutoff/constrained` **[미채점]** | 79 | 0.0% | ±0.0pp | ±0.0pp | ±0.0pp | ±0.0pp |
| `attack_technique/eval_pre_cutoff/free` **[미채점]** | 79 | 0.0% | ±0.0pp | ±0.0pp | ±0.0pp | ±0.0pp |
| `cve_to_cwe/eval_post_cutoff/constrained` | 3,867 | 39.0% | ±3.1pp | ±3.6pp | ±8.1pp | ±8.8pp |
| `cve_to_cwe/eval_post_cutoff/free` | 3,867 | 31.0% | ±2.9pp | ±3.4pp | ±7.8pp | ±8.7pp |
| `cve_to_cwe/eval_pre_cutoff/constrained` | 4,014 | 51.1% | ±3.1pp | ±4.4pp | ±6.3pp | ±6.3pp |
| `cve_to_cwe/eval_pre_cutoff/free` | 4,014 | 40.0% | ±3.1pp | ±4.3pp | ±6.2pp | ±6.2pp |
| `cvss_vector/eval_post_cutoff/constrained` | 4,549 | 18.0% | ±2.3pp | ±2.6pp | ±5.6pp | ±6.9pp |
| `cvss_vector/eval_post_cutoff/free` | 4,549 | 0.0% | ±0.1pp | ±0.1pp | ±0.0pp | ±0.6pp |
| `cvss_vector/eval_pre_cutoff/constrained` | 4,904 | 24.2% | ±2.4pp | ±3.3pp | ±5.0pp | ±5.0pp |
| `cvss_vector/eval_pre_cutoff/free` | 4,904 | 0.0% | ±0.0pp | ±0.0pp | ±0.0pp | ±0.0pp |
| `structured_extract/eval_post_cutoff/constrained` | 3,328 | 9.3% | ±2.0pp | ±1.8pp | ±6.4pp | ±6.4pp |
| `structured_extract/eval_post_cutoff/free` | 3,328 | 9.0% | ±2.0pp | ±1.8pp | ±6.4pp | ±6.2pp |
| `structured_extract/eval_pre_cutoff/constrained` | 2,307 | 8.5% | ±2.3pp | ±2.0pp | ±4.7pp | ±5.3pp |
| `structured_extract/eval_pre_cutoff/free` | 2,307 | 8.2% | ±2.3pp | ±2.2pp | ±4.7pp | ±5.0pp |

## 채점하지 않는 과제

- **`attack_technique`**: 738 training examples and 72 / 44 evaluation items; confidence intervals exceed +/-10 percentage points and the task is recall of ~800 fixed items. Kept in the datasets and manifest, reported descriptively by P4/P5, excluded from any comparison between conditions.

위 표에 숫자가 있어도 `scored: 아니오`로 표시된 행은 **조건 간 비교에 절대 쓰이지 않는다**. `python -m eval.stats --compare A B`가 그 행을 건너뛰고 건너뛴 사실을 기록한다.

## 이 결과로 할 수 없는 말

`reports/eval_harness.md`의 '이 하네스가 측정하지 못하는 것' 절을 읽지 않고 이 숫자를 인용하면 과대주장이 된다. 요약하면: 보안 역량을 재지 않고, 과제는 추론이 아니라 회수와 구조 추출이며, 평가 세트는 CNA 편향이 알려진 네 출처에서 나왔고, `attack_technique`는 너무 작다.

