# P3 데이터셋 구축 보고서

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

## 산출 파일

| 파일 | 예제 수 | SHA-256 |
|---|---|---|
| `attack_technique/eval_post_cutoff.jsonl` | 79 | `39fcd0f8a7978f4d…` |
| `attack_technique/eval_pre_cutoff.jsonl` | 67 | `07d0732860fa9caa…` |
| `attack_technique/train.jsonl` | 738 | `5a4f37c6b9b6a572…` |
| `cve_to_cwe/contested.jsonl` | 11,903 | `cdd553623b67e23b…` |
| `cve_to_cwe/eval_post_cutoff.jsonl` | 3,673 | `77890f20fa911e56…` |
| `cve_to_cwe/eval_pre_cutoff.jsonl` | 3,384 | `a6b371ed87d2f514…` |
| `cve_to_cwe/train.jsonl` | 170,748 | `2d47329527439d29…` |
| `cve_to_cwe/train_subsample.jsonl` | 28,491 | `3285351ea811b759…` |
| `cvss_vector/eval_post_cutoff.jsonl` | 4,333 | `5c579d65e5a25a6c…` |
| `cvss_vector/eval_pre_cutoff.jsonl` | 4,160 | `29783652edac5e6f…` |
| `cvss_vector/train.jsonl` | 123,402 | `eb56f450594de6bd…` |
| `cvss_vector/train_subsample.jsonl` | 20,591 | `4010f3a7cdbc8f57…` |
| `replay/train.jsonl` | 37,100 | `003ac863ca82878e…` |
| `replay/train_subsample.jsonl` | 11,251 | `90657fb2afd26829…` |
| `structured_extract/eval_post_cutoff.jsonl` | 3,117 | `d92954b13a01902f…` |
| `structured_extract/eval_pre_cutoff.jsonl` | 1,831 | `7826a8b77bbbb32f…` |
| `structured_extract/train.jsonl` | 65,429 | `136457b00f88fb2d…` |
| `structured_extract/train_subsample.jsonl` | 10,918 | `5c28d6de1e15c888…` |

## 과제별 제외 사유

### `cve_to_cwe` — CVE→CWE 분류

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 3,673 |
| `eval_pre_cutoff` | 3,384 |
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

템플릿 분포: T0=59,087, T1=59,401, T2=59,317

### `cvss_vector` — CVSS v3.1 벡터

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 4,333 |
| `eval_pre_cutoff` | 4,160 |
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

템플릿 분포: T0=43,961, T1=44,041, T2=43,893

### `attack_technique` — ATT&CK 기법 식별

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 79 |
| `eval_pre_cutoff` | 67 |
| `train` | 738 |

**dedup 단계별 제외** (P2 표시가 여기서 물질화됨):

| dedup_stage | 제외 |
|---|---|
| `near_or_exact` | 22 |

**과제 필터·분할별 제외**:

| 사유 | 건수 |
|---|---|

템플릿 분포: T0=289, T1=297, T2=298

### `structured_extract` — 구조화 추출

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 3,117 |
| `eval_pre_cutoff` | 1,831 |
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

템플릿 분포: T0=23,117, T1=23,684, T2=23,576

## 세 가지 결정

- Decision 1: `datasets/SPLIT.md`
- Decision 2: `datasets/CWE_POLICY.md`
- Decision 3: `datasets/CARD.md` 리플레이 절 및 `docs/data-sources.md`

## 재현성

> Splits by stable hash under a fixed seed; templates by stable hash; sorted iteration everywhere; no wall-clock field. Re-running against the same pins and P2 outputs reproduces this manifest byte for byte.

