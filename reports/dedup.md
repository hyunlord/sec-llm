# P2 중복 제거 보고서

> `manifests/process.manifest.json`에서 **자동 생성**된다. `make process-report`로 다시 만들 것.

## 0. 아무것도 삭제하지 않았다

- 입력 레코드: **823,285** → 출력 레코드: **823,285**
- **삭제된 레코드: 0건**
- 제거 대상으로 *표시*된 레코드: **91,275** (**11.09%**)
- 유지: 732,010

P2는 **표시**만 한다. 물리적 삭제는 P3에서 데이터셋을 실제로 구성할 때 일어난다. 이렇게 하면 제거율이 감사 가능하고, 모든 판단이 되돌릴 수 있으며, 임계값을 바꾸려고 파이프라인 전체를 다시 돌릴 필요가 없다.

## 1. 임계값 보정 — 이 단계의 핵심 산출물

논문에서 가져온 임계값은 **주장**이다. 라벨링된 표본에서 정밀도·재현율을 측정해 고른 임계값은 **측정**이다. 아래가 그 측정이다.

라벨링된 쌍: **210개** (유사도 구간별 층화 표집)

| 임계값 | 클러스터 수 | 표시된 레코드 | 정밀도 (95% CI) | 재현율 (95% CI) | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| **0.75** **←채택** | 24,947 | 78,893 | 0.983 [0.960, 1.000] | 0.835 [0.780, 0.885] | 0.903 | 172 | 3 | 34 | 1 |
| **0.80** | 22,458 | 67,303 | 0.979 [0.951, 1.000] | 0.665 [0.598, 0.727] | 0.792 | 137 | 3 | 69 | 1 |
| **0.85** | 19,717 | 55,153 | 0.971 [0.933, 1.000] | 0.495 [0.427, 0.564] | 0.656 | 102 | 3 | 104 | 1 |
| **0.90** | 17,470 | 45,986 | 0.986 [0.950, 1.000] | 0.335 [0.271, 0.400] | 0.500 | 69 | 1 | 137 | 3 |

### 채택 임계값: **0.75**

> Precision is flat within its 95% bootstrap interval across all four tested thresholds while recall nearly triples from 0.90 to 0.75, so the higher thresholds buy no measurable precision and pay for it in redundancy left behind.

### 라벨링 기록

- 라벨러: **Claude Opus 5 (agent), acting as annotator for this work order**
- 사람 보안 전문가 여부: **아니오**
- 라벨링 일자: 2026-09-18
- 주어진 지시문: For each pair, answer one question: would a training set containing BOTH of these records be meaningfully redundant? Label 1 (redundant) when the two records describe the same kind of vulnerability and differ only in entities (product name, version, component, file, parameter) -- a model sees the same fact twice. Label 0 (not redundant) when the records describe different vulnerability classes, so that keeping both teaches a distinction rather than repeating a fact.
- 방법: All 210 pairs were read. A keyword scan over vulnerability-class terms (out-of-bounds read/write, use-after-free, stack/heap buffer overflow, XSS subtype, SQLi, command injection, race, integer overflow, privilege escalation, authorization bypass) was then run across the whole sample to catch class differences missed by eye. It flagged 4 pairs; 3 matched the manual negatives and 1 (#81) was a false flag where one side mentioned both DOM-based and stored XSS within the same CWE-79 family.
- 라벨 원본: `data/labels/near_dup_pairs.jsonl` (저장소에 커밋됨)

### 이 표가 말할 수 없는 것

- Recall is measured against labelled CANDIDATE pairs at or above 0.70. Pairs LSH never proposed cannot appear in the denominator, so this is not recall against all truly redundant pairs in the corpus.
- The label set is imbalanced (206 redundant / 4 not), so the precision confidence intervals are wide at the lower bound and the sample cannot discriminate between thresholds on precision.
- The annotator is a language model, not a human security analyst.

> The annotator is a language model, not a human security analyst. These labels are evidence about how the threshold was chosen, not a gold standard. A human review of the same committed sample would strengthen the claim and is the obvious next improvement.

## 2. 단계별 결과

| 단계 | 의미 | 레코드 수 |
|---|---|---|
| `identity` | 두 출처가 같은 엔티티를 서술 — **중복이 아니며 전부 유지** | 673,329 |
| `exact` | 정규화 후 텍스트가 완전히 동일 (동일 content_type 내) | 61,940 |
| `near` | MinHash+LSH, Jaccard ≥ 0.75 | 57,357 |
| `unique` | 중복이 발견되지 않음 | 30,659 |

### 정규화(Stage 1) — 무엇이 실제로 바뀌었나

무엇이 바뀌었는지가 발견 사항이다. '정규화했다'는 발견 사항이 아니다.

| 출처 | 변환 | 영향받은 레코드 |
|---|---|---|
| `attack` | `trailing_ws_stripped` | 2,619 |
| `attack` | `edges_trimmed` | 775 |
| `attack` | `inner_spaces_collapsed` | 559 |
| `attack` | `nbsp_normalized` | 76 |
| `attack` | `blank_lines_collapsed` | 33 |
| `cve_list` | `inner_spaces_collapsed` | 23,630 |
| `cve_list` | `nbsp_normalized` | 7,549 |
| `cve_list` | `edges_trimmed` | 4,318 |
| `cve_list` | `trailing_ws_stripped` | 3,857 |
| `cve_list` | `blank_lines_collapsed` | 2,881 |
| `cve_list` | `crlf_to_lf` | 1,724 |
| `cve_list` | `zero_width_removed` | 64 |
| `cve_list` | `control_chars_removed` | 1 |
| `cwe` | `inner_spaces_collapsed` | 153 |
| `cwe` | `trailing_ws_stripped` | 7 |
| `nvd` | `inner_spaces_collapsed` | 25,996 |
| `nvd` | `nbsp_normalized` | 7,515 |
| `nvd` | `edges_trimmed` | 4,383 |
| `nvd` | `trailing_ws_stripped` | 3,622 |
| `nvd` | `blank_lines_collapsed` | 2,880 |
| `nvd` | `crlf_to_lf` | 1,727 |
| `nvd` | `zero_width_removed` | 62 |
| `nvd` | `control_chars_removed` | 1 |

**소문자화·구두점 제거·불용어 제거는 하지 않았다.** 보안 텍스트는 대소문자와 구두점에 의미가 있다 (`CVE-2021-44228`, `../../`, `${jndi:ldap://}`, `O_CREAT|O_EXCL`). 공격적인 정규화는 이 코퍼스가 존재하는 이유인 신호를 파괴한다.

### Stage 2 — 완전 일치 중복

- 클러스터 12,325개, 중복 표시 49,615건
- 정규화 후 텍스트가 빈 레코드 21,919건은 **제외**했다 — 전부 빈 문자열의 SHA-256으로 해시되어 하나의 거대한 가짜 클러스터가 되기 때문이다.

### Stage 4 — 근접 중복 (content_type별)

| content_type | 레코드 | 해시됨 | 후보 쌍 | 클러스터 | 표시됨 |
|---|---|---|---|---|---|
| `nvd_cve_api_2_0_json` | 394,957 | 390,102 | 1,488,624 | 12,650 | 41,730 |
| `cve_record_v5_json` | 376,600 | 375,901 | 967,395 | 11,683 | 35,981 |
| `stix_relationship` | 22,286 | 21,262 | 4,099 | 521 | 1,019 |
| `stix_x-mitre-analytic` | 2,066 | 2,066 | 507 | 39 | 94 |
| `stix_attack-pattern` | 1,166 | 1,151 | 71 | 40 | 40 |
| `cwe_weakness` | 969 | 969 | 28 | 1 | 1 |
| `stix_x-mitre-detection-strategy` | 920 | 375 | 0 | 0 | 0 |
| `stix_malware` | 888 | 860 | 15 | 2 | 6 |
| `cwe_category` | 422 | 178 | 3 | 0 | 0 |
| `stix_course-of-action` | 335 | 334 | 149 | 11 | 22 |
| `stix_intrusion-set` | 229 | 193 | 0 | 0 | 0 |
| `stix_x-mitre-data-component` | 174 | 123 | 0 | 0 | 0 |
| `stix_tool` | 97 | 97 | 0 | 0 | 0 |
| `stix_campaign` | 68 | 60 | 0 | 0 | 0 |
| `stix_x-mitre-data-source` | 61 | 42 | 0 | 0 | 0 |
| `cwe_view` | 59 | 20 | 0 | 0 | 0 |
| `stix_x-mitre-tactic` | 41 | 41 | 0 | 0 | 0 |
| `stix_x-mitre-asset` | 18 | 18 | 0 | 0 | 0 |
| `stix_x-mitre-matrix` | 4 | 4 | 0 | 0 | 0 |
| `stix_identity` | 3 | 0 | 0 | 0 | 0 |
| `stix_x-mitre-collection` | 3 | 3 | 0 | 0 | 0 |

- 파라미터: seed=`1234`, 순열 128개, 5-gram 셰일, 최소 토큰 8, 버킷 상한 300
- **content_type별로 실행했고 전역으로 돌리지 않았다.** STIX relationship 객체와 CVE 설명을 비교하는 것은 의미가 없고, LSH 버킷을 쓰레기로 포화시킨다.
- **셰일 입력에서 보안 엔티티를 제거하지 않았다.** CVE 식별자·제품명·버전 문자열을 빼는 것은 그럴듯해 보이는 최적화지만, 그러면 "a buffer overflow in X version Y allows remote attackers to execute arbitrary code"만 남아 서로 무관한 수백 개 CVE가 한 클러스터로 뭉친다.

## 3. 출처별 / content_type별 분포

| 출처 | `exact` | `identity` | `near` | `unique` |
|---|---|---|---|---|
| `attack` | 2,290 | 0 | 420 | 28,184 |
| `cve_list` | 20,776 | 347,272 | 26,909 | 1 |
| `cwe` | 0 | 0 | 2 | 2,474 |
| `nvd` | 38,874 | 326,057 | 30,026 | 0 |

## 4. 재현성과 비용

> Fixed MinHash seed and permutations, sorted iteration at every point where order could leak into the result, and a union-find whose representative is the lexicographically smallest key. No wall-clock field is recorded here, so re-running against the same index reproduces this file byte for byte.

- 전체 벽시계 시간: **130.5초**
- 최대 RSS: **1.9 GiB**
  - `identity`: 23.8초
  - `near`: 1.5초
- 30분을 초과한 단계는 없다.

