# P3 데이터셋 구축 보고서

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

## 산출 파일

| 파일 | 예제 수 | SHA-256 |
|---|---|---|
| `attack_technique/eval_post_cutoff.jsonl` | 72 | `a2659fa6fa2a99ee…` |
| `attack_technique/eval_pre_cutoff.jsonl` | 44 | `82c8c036f3c8b0c3…` |
| `attack_technique/train.jsonl` | 738 | `5a4f37c6b9b6a572…` |
| `cve_to_cwe/contested.jsonl` | 11,903 | `cdd553623b67e23b…` |
| `cve_to_cwe/eval_post_cutoff.jsonl` | 2,815 | `80b716ef58cf0b9a…` |
| `cve_to_cwe/eval_pre_cutoff.jsonl` | 2,020 | `a08d8f90dacf7607…` |
| `cve_to_cwe/train.jsonl` | 170,748 | `2d47329527439d29…` |
| `cvss_vector/eval_post_cutoff.jsonl` | 3,116 | `e5b9aee9891c5a29…` |
| `cvss_vector/eval_pre_cutoff.jsonl` | 2,498 | `cec8d100389bcd20…` |
| `cvss_vector/train.jsonl` | 123,402 | `eb56f450594de6bd…` |
| `replay/train.jsonl` | 37,100 | `003ac863ca82878e…` |
| `structured_extract/eval_post_cutoff.jsonl` | 2,177 | `732e88cb9add8f3b…` |
| `structured_extract/eval_pre_cutoff.jsonl` | 938 | `d80a6b48f52c7814…` |
| `structured_extract/train.jsonl` | 65,429 | `136457b00f88fb2d…` |

## 과제별 제외 사유

### `cve_to_cwe` — CVE→CWE 분류

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 3,897 |
| `eval_pre_cutoff` | 4,095 |
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

템플릿 분포: T0=59,377, T1=59,711, T2=59,652

### `cvss_vector` — CVSS v3.1 벡터

| 분할 | 예제 |
|---|---|
| `eval_post_cutoff` | 4,578 |
| `eval_pre_cutoff` | 4,993 |
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

템플릿 분포: T0=44,302, T1=44,393, T2=44,278

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
| `eval_post_cutoff` | 3,355 |
| `eval_pre_cutoff` | 2,385 |
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

템플릿 분포: T0=23,387, T1=23,943, T2=23,839

## 세 가지 결정

- Decision 1: `datasets/SPLIT.md`
- Decision 2: `datasets/CWE_POLICY.md`
- Decision 3: `datasets/CARD.md` 리플레이 절 및 `docs/data-sources.md`

## 재현성

> Splits by stable hash under a fixed seed; templates by stable hash; sorted iteration everywhere; no wall-clock field. Re-running against the same pins and P2 outputs reproduces this manifest byte for byte.

