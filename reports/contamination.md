# P3.1 오염 검사 보고서

> `manifests/datasets.manifest.json`의 **기록된 제거 사실**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 (`docs/engineering-rules.md` 규칙 1). `make datasets-docs` 또는 `python -m datasets.contamination --render`.

## 기준이 바뀐 이유

시간 분할이 이미 같은 CVE가 학습과 평가에 동시에 있을 수 없음을 보장한다. 그러므로 평가 설명문이 학습 설명문과 13토큰 연쇄 하나를 공유한다는 것은 **두 CNA가 같은 템플릿으로 썼다**는 뜻이지 문서가 샜다는 뜻이 아니다. P3의 단일 13-gram 무관용은 평가 세트의 28–61%를 제거했고, 살아남은 항목은 템플릿을 쓰지 않는 벤더 쪽으로 기울었으며, 공정 비교가 목적인 컷오프 이전 세트는 반토막이 났다.

실제로 남는 위험은 **다른 CVE ID를 단 학습 입력의 근사 복사본**이다. 벤더는 권고문 사이에서 설명을 복사한다. 그것은 근접 중복 입력이고, P2의 MinHash가 탐지하는 바로 그것이다.

## 적용된 기준

1. **근접 중복 입력** — Jaccard ≥ **0.75** (출처: P2 calibration (P2.1 not delivered)). P2의 `process/near.py`를 import (seed 1234, 순열 128, 5-gram 셰일, 밴드 16×8). 재구현하지 않았다.
2. **커버리지 비율** — 항목의 13-gram 중 학습 어딘가에 존재하는 비율 > **0.5**. 독립된 두 번째 기준.
3. *(진단만)* 단일 13-gram 일치 — 옛 기준. **보고하되 적용하지 않는다.**

학습 측 인덱스: 고유 13-gram 10,500,784, 8-gram 10,654,951, 근접 중복용 해시 텍스트 613,092 (학습 4과제 입력+정답, 리플레이 프롬프트+응답).

## 평가 세트별 실제 제거 (build.py가 수행하고 기록한 값)

| 평가 세트 | 검사 전 | 근접중복 | 커버리지 | 둘 다 | **제거 합계** | 제거율 | 검사 후 | *(진단)* 단일13-gram 옛 기준이면 |
|---|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 79 | 0 | 0 | 0 | **0** | 0.0% | 79 | 7 (8.9%) |
| `attack_technique/eval_pre_cutoff` | 79 | 0 | 12 | 0 | **12** | 15.2% | 67 | 35 (44.3%) |
| `cve_to_cwe/eval_post_cutoff` | 3,897 | 0 | 194 | 30 | **224** | 5.8% | 3,673 | 1,082 (27.8%) |
| `cve_to_cwe/eval_pre_cutoff` | 4,095 | 5 | 630 | 76 | **711** | 17.4% | 3,384 | 2,075 (50.7%) |
| `cvss_vector/eval_post_cutoff` | 4,578 | 0 | 216 | 29 | **245** | 5.3% | 4,333 | 1,462 (31.9%) |
| `cvss_vector/eval_pre_cutoff` | 4,993 | 5 | 744 | 84 | **833** | 16.7% | 4,160 | 2,495 (50.0%) |
| `structured_extract/eval_post_cutoff` | 3,355 | 0 | 211 | 27 | **238** | 7.1% | 3,117 | 1,178 (35.1%) |
| `structured_extract/eval_pre_cutoff` | 2,385 | 4 | 476 | 74 | **554** | 23.2% | 1,831 | 1,447 (60.7%) |

총 제거 **2,817건**. 옛 기준이었다면 **9,781건**.

## 분포

**커버리지 비율(13-gram) 분포** — 평가 항목 전체:

| 구간 | 항목 수 |
|---|---|
| `[0.0,0.1)` | 15,519 |
| `[0.1,0.2)` | 1,596 |
| `[0.2,0.3)` | 1,381 |
| `[0.3,0.4)` | 1,016 |
| `[0.4,0.5)` | 971 |
| `[0.5,0.6)` | 946 |
| `[0.6,0.7)` | 755 |
| `[0.7,0.8)` | 622 |
| `[0.8,0.9)` | 467 |
| `[0.9,1.0)` | 188 |

**최근접 학습 항목과의 Jaccard 분포**:

| 구간 | 항목 수 |
|---|---|
| `[0.0,0.1)` | 21,190 |
| `[0.2,0.3)` | 15 |
| `[0.3,0.4)` | 64 |
| `[0.4,0.5)` | 203 |
| `[0.5,0.6)` | 460 |
| `[0.6,0.7)` | 750 |
| `[0.7,0.8)` | 645 |
| `[0.8,0.9)` | 97 |
| `[0.9,1.0)` | 37 |

## CNA 분포 — 옛 기준 vs 새 기준 vs 학습 세트

TVD = 학습 세트 CNA 분포와의 총변동거리 (0 = 동일, 1 = 완전히 다름). 새 기준 아래 값이 옛 기준보다 학습에 가까우면 편향이 줄어든 것이다.

| 평가 세트 | 검사 전 TVD | 옛 기준 후 TVD | **새 기준 후 TVD** | 상위 CNA (새 기준 후) |
|---|---|---|---|---|
| `cve_to_cwe/eval_post_cutoff` | 0.5305 | 0.5755 | **0.5335** | Patchstack 500, GitHub_M 461, mitre 354, VulnCheck 345, Linux 222 |
| `cve_to_cwe/eval_pre_cutoff` | 0.2678 | 0.2852 | **0.2712** | mitre 1145, Patchstack 274, GitHub_M 248, VulDB 198, WPScan 120 |
| `cvss_vector/eval_post_cutoff` | 0.4454 | 0.4987 | **0.4485** | GitHub_M 538, Patchstack 500, Linux 435, VulDB 433, mitre 375 |
| `cvss_vector/eval_pre_cutoff` | 0.1438 | 0.3013 | **0.1737** | mitre 1279, GitHub_M 325, Patchstack 279, VulDB 242, WPScan 139 |
| `structured_extract/eval_post_cutoff` | 0.4506 | 0.581 | **0.4669** | GitHub_M 603, Patchstack 388, VulDB 361, VulnCheck 332, Wordfence 216 |
| `structured_extract/eval_pre_cutoff` | 0.2699 | 0.4498 | **0.3207** | GitHub_M 324, VulDB 141, WPScan 132, @huntrdev 92, icscert 61 |

**판정**: 6개 CVE 평가 세트 중 **6개**에서 새 기준 후 CNA 분포가 옛 기준 후보다 학습 분포에 더 가깝다; 검사 전보다 학습에서 눈에 띄게 멀어진 세트는 ['cvss_vector/eval_pre_cutoff', 'structured_extract/eval_pre_cutoff']이다 — 남은 편향은 여기다.

## 제거된 항목 — 전부 검사 가능

제거된 2,817건 각각의 ID·기준·최근접 학습 항목·커버리지가 매니페스트 `removal_record`에 있다. 처음 몇 건:

| 예제 | 기준 | 최근접 학습 항목 | Jaccard | 커버리지 | 일치 13-gram 예 |
|---|---|---|---|---|---|
| `attack_technique:T1406.002` | coverage | `None` | 0.0 | 0.5867 | `to conceal their code. Software packing is a method of compr` |
| `attack_technique:T1474.003` | coverage | `attack_technique:T1195.002:in` | 0.642 | 1.0 | `Adversaries may manipulate application software prior to rec` |
| `attack_technique:T1481.003` | coverage | `attack_technique:T1102.003:in` | 0.7005 | 0.8267 | `Adversaries may use an existing, legitimate external Web ser` |
| `attack_technique:T1521.001` | coverage | `None` | 0.0 | 0.7778 | `Adversaries may employ a known symmetric encryption algorith` |
| `attack_technique:T1623` | coverage | `None` | 0.0 | 0.6449 | `Adversaries may abuse command and script interpreters to exe` |
| `attack_technique:T1627` | coverage | `attack_technique:T1480:in` | 0.5042 | 0.7273 | `Adversaries may use execution guardrails to constrain execut` |
| `attack_technique:T1631.001` | coverage | `None` | 0.0 | 0.6281 | `Adversaries may inject malicious code into processes via ptr` |
| `attack_technique:T1631` | coverage | `None` | 0.0 | 0.5385 | `elevate privileges. Process injection is a method of executi` |
| `attack_technique:T1637` | coverage | `None` | 0.0 | 0.7358 | `Adversaries may dynamically establish connections to command` |
| `attack_technique:T1639.001` | coverage | `None` | 0.0 | 0.726 | `Adversaries may steal data by exfiltrating it over an un-enc` |
| `attack_technique:T1639` | coverage | `None` | 0.0 | 0.6806 | `Adversaries may steal data by exfiltrating it over a differe` |
| `attack_technique:T1640` | coverage | `None` | 0.0 | 0.6667 | `Adversaries may interrupt availability of system and network` |

## 교차 평가 검사

- `attack_technique`: 0 (0이어야 함)
- `cve_to_cwe`: 0 (0이어야 함)
- `cvss_vector`: 0 (0이어야 함)
- `structured_extract`: 0 (0이어야 함)

## RE-CHECK (별도 파일, 제거 기록이 아님)

`--assert-zero`가 최종 파일을 다시 검사한 결과: 기준 초과 항목 **0건** (통과). 이 숫자는 재검증이며 위의 제거 건수와 별개다.
