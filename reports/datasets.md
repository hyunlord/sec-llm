# P3 데이터셋 구축 보고서

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

## 산출 파일

| 파일 | 예제 수 | SHA-256 |
|---|---|---|
| `attack_technique/eval_post_cutoff.jsonl` | 79 | `ab5e1e632d6a842d…` |
| `attack_technique/eval_pre_cutoff.jsonl` | 79 | `27aaa6817ad0b439…` |
| `attack_technique/train.jsonl` | 738 | `5a4f37c6b9b6a572…` |
| `cve_to_cwe/contested.jsonl` | 11,903 | `cdd553623b67e23b…` |
| `cve_to_cwe/eval_post_cutoff.jsonl` | 3,867 | `20c22e3a02489ce0…` |
| `cve_to_cwe/eval_pre_cutoff.jsonl` | 4,014 | `59b98bb44c9fe42a…` |
| `cve_to_cwe/train.jsonl` | 170,748 | `2d47329527439d29…` |
| `cve_to_cwe/train_subsample.jsonl` | 28,491 | `3285351ea811b759…` |
| `cvss_vector/eval_post_cutoff.jsonl` | 4,549 | `3473afda2ad9c50f…` |
| `cvss_vector/eval_pre_cutoff.jsonl` | 4,904 | `278ee3ea4dc6dcbd…` |
| `cvss_vector/train.jsonl` | 123,402 | `eb56f450594de6bd…` |
| `cvss_vector/train_subsample.jsonl` | 20,591 | `4010f3a7cdbc8f57…` |
| `replay/train.jsonl` | 37,100 | `003ac863ca82878e…` |
| `replay/train_subsample.jsonl` | 11,251 | `90657fb2afd26829…` |
| `structured_extract/eval_post_cutoff.jsonl` | 3,328 | `88ec0614ff5a32ce…` |
| `structured_extract/eval_pre_cutoff.jsonl` | 2,307 | `e10034a18ce04897…` |
| `structured_extract/train.jsonl` | 65,429 | `136457b00f88fb2d…` |
| `structured_extract/train_subsample.jsonl` | 10,918 | `5c28d6de1e15c888…` |

## 과제별 제외 사유

### `cve_to_cwe` — CVE→CWE 분류

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 3,867 |
| `eval_pre_cutoff` | 4,014 |
| `train` | 170,748 |

**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):

| dedup_stage | 제외 |
|---|---|
| `near` | 19,550 |
| `exact` | 15,347 |

**과제 필터·분할별 제외**:

| 사유 | 건수 |
|---|---|
| `post_cutoff_unused` | 79,151 |
| `bucket_placeholder` | 47,575 |
| `bucket_multi_cwe` | 20,250 |
| `bucket_none` | 5,349 |

템플릿 분포: T0=59,348, T1=59,675, T2=59,606

### `cvss_vector` — CVSS v3.1 벡터

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 4,549 |
| `eval_pre_cutoff` | 4,904 |
| `train` | 123,402 |

**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):

| dedup_stage | 제외 |
|---|---|
| `near` | 19,550 |
| `exact` | 15,347 |

**과제 필터·분할별 제외**:

| 사유 | 건수 |
|---|---|
| `no_v31_metric` | 115,157 |
| `post_cutoff_unused` | 93,573 |

v3.1이 없는 CVE에 어떤 CVSS 버전이 있었나 (대체하지 않고 제외):

| 존재하는 버전 | 건수 |
|---|---|
| `V2` | 68,931 |
| `V30+V2` | 35,865 |
| `V40` | 6,019 |
| `none` | 2,987 |
| `V30` | 1,083 |
| `V40+V30` | 272 |

템플릿 분포: T0=44,265, T1=44,352, T2=44,238

### `attack_technique` — ATT&CK 기법 식별

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 79 |
| `eval_pre_cutoff` | 79 |
| `train` | 738 |

**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):

| dedup_stage | 제외 |
|---|---|
| `near_or_exact` | 22 |

**과제 필터·분할별 제외**:

| 사유 | 건수 |
|---|---|

템플릿 분포: T0=293, T1=300, T2=303

### `structured_extract` — 구조화 추출

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 3,328 |
| `eval_pre_cutoff` | 2,307 |
| `train` | 65,429 |

**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):

| dedup_stage | 제외 |
|---|---|
| `near` | 19,550 |
| `exact` | 15,347 |

**과제 필터·분할별 제외**:

| 사유 | 건수 |
|---|---|
| `no_affected_product` | 135,958 |
| `post_cutoff_unused` | 69,514 |
| `multiple_affected_products` | 37,734 |
| `vendor_na` | 14,336 |
| `no_affected_versions` | 10,944 |
| `more_than_16_versions` | 2,048 |

템플릿 분포: T0=23,353, T1=23,904, T2=23,807

## 세 가지 결정

- Decision 1: `datasets/SPLIT.md`
- Decision 2: `datasets/CWE_POLICY.md`
- Decision 3: `datasets/CARD.md` 리플레이 절 및 `docs/data-sources.md`

## 재현성

> Splits by stable hash under a fixed seed; templates by stable hash; sorted iteration everywhere; no wall-clock field. Re-running against the same pins and P2 outputs reproduces this manifest byte for byte.

