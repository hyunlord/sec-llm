# P3.2 오염 검사 보고서

> `manifests/datasets.manifest.json`의 **기록된 제거 사실**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 (`docs/engineering-rules.md` 규칙 1). `make datasets-docs` 또는 `python -m datasets.contamination --render`.

## 적용되는 기준은 하나다: 근접 중복

**근접 중복 입력** — 학습 텍스트 중 어느 하나와 Jaccard ≥ **0.75** (출처: P2 calibration (P2.1 not delivered)). P2의 `process/near.py`를 import한다 (seed 1234, 순열 128, 5-gram 셰일, 밴드 16×8). 재구현하지 않았다.

시간 분할이 이미 같은 CVE가 학습과 평가에 동시에 있을 수 없음을 보장한다. 그러므로 남는 위험은 하나뿐이다 — **다른 CVE ID를 단 학습 입력의 근사 복사본**. 벤더는 권고문 사이에서 설명을 복사하고, 그 복사본은 시간 경계를 넘는다. 이것이 실제 누수이고 제거한다.

## P3.1 대비 무엇이 바뀌었나 — 복원 정산

| 항목 | 건수 |
|---|---|
| P3.1 기준(근접중복 ∪ 커버리지>0.5)이 제거했을 항목 | 2,817 |
| **P3.2가 실제로 제거한 항목 (근접 중복만)** | **334** |
| **복원된 항목 (커버리지만으로 제거됐던 것)** | **2,483** |

항등식 `p31_removed_total = p32_removed_total + restored_coverage_only (checked in build.py)`. P3.1 applied near-duplicate OR coverage>0.5 and removed the union. P3.2 applies near-duplicate alone; every item P3.1 removed on coverage alone is back in the set, carrying its coverage value as a field.

## 커버리지는 왜 더 이상 필터가 아닌가

커버리지 0.5는 **근거 없이 정해진 임계값**이었다 — 이 프로젝트가 P2의 빌려온 0.85를 비판한 바로 그 결함이다. 그것이 잘라낸 항목들의 커버리지는 p25 0.581 / 중앙값 0.667로 **조밀한 띠 한가운데**였고, 그 띠의 정체는 Linux 커널 CVE와 템플릿을 쓰는 벤더다. 기록된 CNA 분포가 대가를 보여줬다: 평가 세트 두 개가 **필터링 전보다도** 학습 분포에서 더 멀어졌다. 편향이 줄어든 게 아니라 다른 편향으로 바뀐 것이다.

그래서 커버리지는 이제 **측정값**이다. 모든 평가 항목이 `train_ngram_coverage` 필드로 자기 커버리지를 들고 다니고, 평가 세트마다 사분위 경계가 매니페스트에 기록된다. P4는 모든 점수를 **전체 및 커버리지 사분위별로** 보고한다. 커버리지가 올라갈수록 정확도가 오르면 그 격차가 암기의 측정값이다. 오르지 않으면 그것도 똑같이 결과다. **삭제된 항목은 아무것도 측정하지 못한다.**

학습 측 인덱스: 고유 13-gram 10,500,784, 8-gram 10,654,951, 근접 중복용 해시 텍스트 613,092 (학습 4과제 입력+정답, 리플레이 프롬프트+응답). 커버리지 적용 여부: **False**.

## 평가 세트별 제거와 복원 (build.py가 수행하고 기록한 값)

| 평가 세트 | 검사 전 | **제거(근접중복)** | 제거율 | **복원(커버리지 전용)** | 최종 | *(진단)* P3.1이면 | *(진단)* 단일13-gram이면 |
|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 79 | **0** | 0.0% | **+0** | 79 | 0 | 7 (8.9%) |
| `attack_technique/eval_pre_cutoff` | 79 | **0** | 0.0% | **+12** | 79 | 12 | 35 (44.3%) |
| `cve_to_cwe/eval_post_cutoff` | 3,897 | **30** | 0.8% | **+194** | 3,867 | 224 | 1,082 (27.8%) |
| `cve_to_cwe/eval_pre_cutoff` | 4,095 | **81** | 2.0% | **+630** | 4,014 | 711 | 2,075 (50.7%) |
| `cvss_vector/eval_post_cutoff` | 4,578 | **29** | 0.6% | **+216** | 4,549 | 245 | 1,462 (31.9%) |
| `cvss_vector/eval_pre_cutoff` | 4,993 | **89** | 1.8% | **+744** | 4,904 | 833 | 2,495 (50.0%) |
| `structured_extract/eval_post_cutoff` | 3,355 | **27** | 0.8% | **+211** | 3,328 | 238 | 1,178 (35.1%) |
| `structured_extract/eval_pre_cutoff` | 2,385 | **78** | 3.3% | **+476** | 2,307 | 554 | 1,447 (60.7%) |

총 제거 **334건**. 단일 13-gram 무관용(P3 원안)이었다면 **9,781건**이었다.

## 커버리지 분포 — 적용하지 않고 보고하는 값

평가 세트별 사분위 경계와 각 사분위에 속한 항목 수. 동일한 커버리지 값이 많으면 사분위가 고르게 나뉘지 않는다 — 그 사실을 숨기지 않고 건수를 그대로 싣는다. P4는 이 경계를 그대로 써서 층화한다.

| 평가 세트 | min | q25 | q50 | q75 | max | q1 | q2 | q3 | q4 | 커버리지 0 |
|---|---|---|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 0.0 | 0.0 | 0.0 | 0.0 | 0.1795 | 72 | 0 | 0 | 7 | 72 (91%) |
| `attack_technique/eval_pre_cutoff` | 0.0 | 0.0 | 0.0 | 0.2132 | 1.0 | 44 | 0 | 15 | 20 | 44 (56%) |
| `cve_to_cwe/eval_post_cutoff` | 0.0 | 0.0 | 0.0 | 0.0293 | 0.9794 | 2,815 | 0 | 86 | 966 | 2,815 (73%) |
| `cve_to_cwe/eval_pre_cutoff` | 0.0 | 0.0 | 0.0 | 0.35 | 1.0 | 2,018 | 0 | 997 | 999 | 2,018 (50%) |
| `cvss_vector/eval_post_cutoff` | 0.0 | 0.0 | 0.0 | 0.0667 | 0.9794 | 3,116 | 0 | 304 | 1,129 | 3,116 (68%) |
| `cvss_vector/eval_pre_cutoff` | 0.0 | 0.0 | 0.0 | 0.3333 | 1.0 | 2,496 | 0 | 1,196 | 1,212 | 2,496 (51%) |
| `structured_extract/eval_post_cutoff` | 0.0 | 0.0 | 0.0 | 0.1176 | 0.9138 | 2,177 | 0 | 325 | 826 | 2,177 (65%) |
| `structured_extract/eval_pre_cutoff` | 0.0 | 0.0 | 0.1 | 0.4468 | 1.0 | 936 | 219 | 576 | 576 | 936 (41%) |

사분위가 고르지 않은 이유는 기록에 그대로 있다: 각 세트의 상당 부분이 **커버리지 정확히 0** — 학습과 13-gram을 하나도 공유하지 않는다. 그래서 q25와 q50 경계가 같은 값으로 붕괴하고 7개 세트에서 q2 구간이 정의상 비어 있다. P4는 이 경계를 그대로 쓰되 **커버리지 0 그룹을 별도로** 보고해야 한다 — 그것이 실질적인 최저 구간이다.


**커버리지 비율(13-gram) 전체 분포** — 검사한 평가 항목 전부:

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

## CNA 분포 — 세 가지 버전 비교

TVD = 학습 세트 CNA 분포와의 총변동거리 (0 = 동일, 1 = 완전히 다름). 평가 세트가 학습 세트와 같은 CNA 구성을 가질수록 과제 난이도가 시간에 따라 달라지는 교란이 작다.

| 평가 세트 | 검사 전 | P3 단일13-gram 후 | P3.1 근접+커버리지 후 | **P3.2 근접만 후** | 상위 CNA (P3.2 후) |
|---|---|---|---|---|---|
| `cve_to_cwe/eval_post_cutoff` | 0.5305 | 0.5755 | 0.5335 | **0.5311** | Patchstack 500, GitHub_M 461, mitre 355, VulnCheck 345, Wordfence 303 |
| `cve_to_cwe/eval_pre_cutoff` | 0.2678 | 0.2852 | 0.2712 | **0.2691** | mitre 1227, Patchstack 280, GitHub_M 258, VulDB 246, WPScan 193 |
| `cvss_vector/eval_post_cutoff` | 0.4454 | 0.4987 | 0.4485 | **0.4462** | GitHub_M 538, Patchstack 500, VulDB 460, Linux 435, mitre 376 |
| `cvss_vector/eval_pre_cutoff` | 0.1438 | 0.3013 | 0.1737 | **0.1458** | mitre 1366, GitHub_M 338, VulDB 298, Patchstack 285, WPScan 214 |
| `structured_extract/eval_post_cutoff` | 0.4506 | 0.581 | 0.4669 | **0.4513** | GitHub_M 603, Patchstack 388, VulDB 385, VulnCheck 332, Wordfence 300 |
| `structured_extract/eval_pre_cutoff` | 0.2699 | 0.4498 | 0.3207 | **0.2815** | GitHub_M 337, WPScan 206, VulDB 182, @huntrdev 93, Wordfence 81 |

**판정**: 6개 CVE 평가 세트 중 **6개**에서 P3.2가 P3.1보다, **6개**에서 P3보다 학습 분포에 가깝다; **검사 전보다 학습 분포에서 눈에 띄게(TVD +0.02 초과) 멀어진 세트는 하나도 없다** — 커버리지 필터가 만들던 편향이 사라졌다.

## 제거된 항목 — 전부 검사 가능

제거된 334건 각각의 ID·최근접 학습 항목·Jaccard·커버리지가 매니페스트 `removal_record`에 있다. 처음 몇 건:

| 예제 | 기준 | 최근접 학습 항목 | Jaccard | 커버리지 | 일치 13-gram 예 |
|---|---|---|---|---|---|
| `cve_to_cwe:CVE-2018-25046` | near_duplicate | `cve_to_cwe:CVE-2020-36560:in` | 1.0 | 1.0 | `Due to improper path sanitization, archives containing relat` |
| `cve_to_cwe:CVE-2021-21088` | near_duplicate | `cve_to_cwe:CVE-2021-21021:in` | 1.0 | 1.0 | `Acrobat Reader DC versions versions 2020.013.20074 (and earl` |
| `cve_to_cwe:CVE-2021-25745` | near_duplicate | `cve_to_cwe:CVE-2021-25746:in` | 0.7544 | 0.6512 | `A security issue was discovered in ingress-nginx where a use` |
| `cve_to_cwe:CVE-2021-3862` | near_duplicate | `cve_to_cwe:CVE-2021-3646:in` | 0.8182 | 0.5 | `is vulnerable to Improper Neutralization of Input During Web` |
| `cve_to_cwe:CVE-2021-38927` | near_duplicate | `cve_to_cwe:CVE-2022-22402:in` | 0.7561 | 0.8214 | `is vulnerable to cross-site scripting. This vulnerability al` |
| `cve_to_cwe:CVE-2021-42265` | near_duplicate | `cve_to_cwe:CVE-2021-40791:in` | 1.0 | 1.0 | `Adobe Premiere Pro versions 22.0 (and earlier) and 15.4.2 (a` |
| `cve_to_cwe:CVE-2021-46817` | near_duplicate | `cve_to_cwe:CVE-2021-46816:in` | 0.8776 | 0.9211 | `version 15.4 (and earlier) are affected by a memory corrupti` |
| `cve_to_cwe:CVE-2022-20844` | near_duplicate | `cve_to_cwe:CVE-2022-20830:in` | 0.8043 | 0.7436 | `A vulnerability in authentication mechanism of Cisco Softwar` |
| `cve_to_cwe:CVE-2022-21277` | near_duplicate | `cve_to_cwe:CVE-2022-21360:in` | 0.9355 | 0.9178 | `Vulnerability in the Oracle Java SE, Oracle GraalVM Enterpri` |
| `cve_to_cwe:CVE-2022-22405` | near_duplicate | `cve_to_cwe:CVE-2016-9972:in` | 0.7609 | 0.8438 | `could allow a remote attacker to obtain sensitive informatio` |
| `cve_to_cwe:CVE-2022-22425` | near_duplicate | `cve_to_cwe:CVE-2023-22877:in` | 0.871 | 0.9048 | `InfoSphere Information Server 11.7 is potentially vulnerable` |
| `cve_to_cwe:CVE-2022-23053` | near_duplicate | `cve_to_cwe:CVE-2022-23054:in` | 0.7619 | 0.5517 | `Widget” element, that allows the injection of malicious Java` |

## 교차 평가 검사

- `attack_technique`: 0 (0이어야 함)
- `cve_to_cwe`: 0 (0이어야 함)
- `cvss_vector`: 0 (0이어야 함)
- `structured_extract`: 0 (0이어야 함)

## RE-CHECK (별도 파일, 제거 기록이 아님)

`--assert-zero`가 최종 파일을 다시 검사한 결과: 적용 기준(근접 중복) 초과 항목 **0건** (통과). 이 숫자는 재검증이며 위의 제거 건수와 별개다.
