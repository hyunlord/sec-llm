# 데이터셋 명세

> 이 문서는 매니페스트와 실행 산출물에서 **자동 생성**된다. 손으로 고치지 말고 `make docs`로 다시 만들 것. 모든 수치의 출처는 `docs/trace.json`에 경로로 기록되어 있고 `python -m docs.trace_check --assert-all`이 이를 독립적으로 재확인한다.


이 문서는 무엇이 들어왔고, 무엇이 왜 빠졌고, 무엇이 평가 세트에 남았는지를 적는다. 원본 코퍼스는 재배포하지 않는다 — 핀과 해시와 매니페스트만 배포하고, 다운로더가 그것으로 다시 만든다(`docs/REPRODUCE.md`).

## 출처

네 개 출처, 정규화 이전 원시 레코드 **823,285건**. 모두 불변 참조로 고정되어 있고, 같은 핀에 대해 다시 수집하면 매니페스트가 바이트 단위로 재현된다(`make ingest-verify`, 네트워크를 막고도 `make ingest-offline`).

| 출처 | 핀 | 고정 시각 (UTC) | 레코드 | 엔티티 ID 커버리지 | 라이선스 |
|---|---|---|---|---|---|
| **CVE List V5 — CVE 레코드 원본**<br>`cve_list` | git 커밋 `9d4f632aa6e148754e1f27bdfb69f4635792f69a` (`CVEProject/cvelistV5`, `main`) | 2026-09-18T04:37:25Z | 394,958 | 100.0% | permitted_with_attribution |
| **NVD `CVE API 2.0` — NIST 분석(CVSS·CPE·CWE 매핑)**<br>`nvd` | api_snapshot | 2026-09-18T04:37:26Z | 394,957 | 100.0% | permitted_with_attribution |
| **CWE 카탈로그 — 약점 분류 체계**<br>`cwe` | 버전 고정 URL `https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip` (v4.20) | 2026-09-18T04:37:30Z | 2,476 | 100.0% | permitted_with_attribution |
| **MITRE ATT&CK STIX 번들 — 공격 기법**<br>`attack` | git 태그 `v19.2` → 커밋 `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4` (`mitre-attack/attack-stix-data`) | 2026-09-18T04:37:32Z | 30,894 | 19.6% | permitted_with_attribution |

엔티티 ID 커버리지가 출처마다 다른 것은 결함이 아니다. ATT&CK STIX 번들은 기법·소프트웨어·관계 객체를 한 파일에 담고 있고, 그중 CVE처럼 안정된 외부 식별자를 갖는 것은 일부다 — 식별 가능한 레코드만 놓고 보면 커버리지는 100.0%이다. 어떤 콘텐츠 타입이 식별자를 갖지 않는지는 매니페스트의 `content_types_without_entity_id`에 열거되어 있다.

### 계통(lineage) 필드

모든 레코드는 아래 필드를 달고 다닌다. 출처를 잃은 레코드는 없다.

`source_id` · `source_name` · `source_url` · `source_pin` · `retrieved_at` · `record_id` · `entity_id` · `content_type` · `source_license` · `upstream_license` · `redistribution_status` · `commercial_status` · `contains_third_party_content` · `pii_policy` · `model_publication_status` · `transform_history` · `content_sha256`

필드 수는 17개이며, 이 중 다섯 개(`source_license`, `upstream_license`, `redistribution_status`, `commercial_status`, `model_publication_status`)는 라이선스 판정을 레코드 단위로 끌고 가기 위한 것이다. 그 판정들이 어디서 왔는지는 `docs/LICENSES.md`에 있다.

## 정제와 중복 제거

P2는 **표시하고 지우지 않는다.** 입력 레코드는 전부 출력에 나타나며 결정이 달려 있을 뿐이다. 물리적으로 삭제된 레코드는 0건이다.

### 정규화

적용된 변환: `nfc`, `crlf_to_lf`, `control_chars_removed`, `zero_width_removed`, `nbsp_normalized`, `trailing_ws_stripped`, `blank_lines_collapsed`, `inner_spaces_collapsed`, `edges_trimmed`.

유니코드 NFC, CRLF→LF, 제어문자·제로폭 문자 제거, NBSP 정규화, 공백 정리. 정규화 후 본문이 비는 레코드는 출처별로 기록된다 — `cve_list` 18,358건은 거의 전부 REJECTED 상태의 CVE이고, 이들은 아래 결정 절에서 별도로 처리된다.

### 중복 제거

| 단계 | 방법 | 파라미터 | 결과 |
|---|---|---|---|
| 완전 일치 | 정규화 본문의 sha256 | — | 클러스터 12,325개, 중복 표시 49,615건 |
| 근사 중복 | MinHash + LSH, Jaccard | 순열 128 · shingle 5 · 밴드 16×8 · 임계값 0.75 | `cve_record_v5_json`만 해도 후보쌍 967,395개 → 클러스터 11,683개 |
| 동일 엔티티 묶기 | CVE ID | — | 엔티티 394,958개, 필드 충돌 201,104개 |

**동일 엔티티 묶기는 중복 제거가 아니다.** 두 출처가 같은 CVE를 서술하는 것은 중복이 아니라 비교 가능한 두 진술이며, 그 불일치야말로 이 단계가 존재하는 이유다. 묶인 레코드는 모두 `dedup_keep=true`를 유지한다.

전체 제거율은 **11.1%**(91,275 / 823,285)이다.

### 근사 중복 임계값 — 보정되지 않았다

임계값 **0.75**는 P2의 보정 실험에서 채택되었다. 그 실험의 **재현율(recall) 열은 나중에 표본 설계를 다시 진술한 것에 지나지 않는다는 사실이 밝혀졌다** — 재현율은 LSH가 이미 제안한 후보쌍에 대해서만 측정되므로, LSH가 제안한 적 없는 쌍은 분모에 들어올 수 없다. 임계값을 낮추면 후보가 늘고 재현율이 따라 오르는 것은 발견이 아니라 정의다. 재보정(P2.1)은 요청되었으나 **아직 수행되지 않았고, 임계값은 재보정되지 않은 채로 남아 있으며, 평가 세트는 그 위에 서 있다.** 이 문서는 그것을 기다리지 않고 그대로 적는다.

P2가 자기 한계를 매니페스트에 적어 두었고(`stages.calibration.limits`), 라벨은 210쌍이다. 그대로 옮긴다.

- Recall is measured against labelled CANDIDATE pairs at or above 0.70. Pairs LSH never proposed cannot appear in the denominator, so this is not recall against all truly redundant pairs in the corpus.
- The label set is imbalanced (206 redundant / 4 not), so the precision confidence intervals are wide at the lower bound and the sample cannot discriminate between thresholds on precision.
- The annotator is a language model, not a human security analyst.

| 임계값 | 정밀도 | 정밀도 신뢰구간(`ci95`) | 재현율(후보쌍 기준) | 근사 중복 표시 |
|---|---|---|---|---|
| 0.75 | 98.3% | [96.0, 100.0]% | 83.5% | 78,893 |
| 0.80 | 97.9% | [95.1, 100.0]% | 66.5% | 67,303 |
| 0.85 | 97.1% | [93.3, 100.0]% | 49.5% | 55,153 |
| 0.90 | 98.6% | [95.0, 100.0]% | 33.5% | 45,986 |

### 비밀과 PII

823,285건 전수 스캔, 발견 10,213건(비밀 22, PII 10,191).

- `pii`: replaced with a stable pseudonym so co-occurrence structure survives
- `public_iocs`: NOT masked -- routable IPs, C2 domains and file hashes are the IOC content of this corpus
- `secrets`: replaced with an unrecoverable marker
- `values_recorded`: never; counts and one-way digests only

**공개 침해지표는 마스킹하지 않는다.** 라우팅 가능한 IP, C2 도메인, 파일 해시는 이 코퍼스의 내용 그 자체다. 마스킹되는 것은 사설 IP·내부 호스트명·이메일·URL 내 자격증명이며, **탐지된 비밀 값은 저장소에 절대 기록되지 않는다** — 개수와 단방향 다이제스트만 남는다.

## 과제

| 과제 | 구성 규칙 | 정답 출처 | 학습 | 평가(컷오프 이후) | 평가(컷오프 이전) | 채점 |
|---|---|---|---|---|---|---|
| **CVE→CWE 분류**<br>`cve_to_cwe` | CVE 설명 → CWE ID 한 개 | CVE List와 NVD가 **합의한** CWE | 170,748 | 3,867 | 4,014 | 예 |
| **CVSS v3.1 벡터**<br>`cvss_vector` | CVE 설명 → `CVSS v3.1` 벡터 문자열 | NVD 기본 메트릭 벡터 | 123,402 | 4,549 | 4,904 | 예 |
| **구조화 추출**<br>`structured_extract` | CVE 설명 → 벤더·제품·버전 JSON | CVE 레코드의 `affected` 배열 | 65,429 | 3,328 | 2,307 | 예 |
| **ATT&CK 기법 식별**<br>`attack_technique` | 기법 설명 → ATT&CK 기법 ID | STIX `external_references` | 738 | 79 | 79 | **아니오** |

각 과제는 프롬프트 템플릿 세 개를 균등하게 돌려 쓴다 — 예를 들어 `cve_to_cwe`는 59,348 / 59,675 / 59,606건이다. 템플릿 하나에만 맞춰 과적합된 결과를 능력으로 읽지 않기 위한 것이다.

### `attack_technique`는 채점하지 않는다

> 738 training examples and 72 / 44 evaluation items; confidence intervals exceed +/-10 percentage points and the task is recall of ~800 fixed items. Kept in the datasets and manifest, reported descriptively by P4/P5, excluded from any comparison between conditions.

**이 문장 자체에 결함이 있다.** 인용문의 "72 / 44 evaluation items"는 평가 항목 수가 아니라 두 세트의 **커버리지 0 항목 수**(72 / 44)다. 실제 평가 항목은 각각 79건과 79건이다. 이 문장은 `datasets/build.py`에 **손으로 적힌 문자열 리터럴**이며 — 기록을 렌더링하지 않고 기록하려는 사실을 다시 적은 것, 즉 규칙 1이 막으려던 바로 그 형태다. P7은 `datasets/`를 수정하지 않는다(작업 범위 밖). 기록된 문장을 그대로 인용하고 옆에 실제 수치를 매니페스트에서 생성해 붙인다. 결론 자체는 바뀌지 않는다 — 평가 항목이 79건이어도 조건 간 비교를 지탱하기에는 여전히 너무 적다.

데이터셋과 매니페스트에는 남아 있고 서술적으로 보고되지만, **조건 간 비교에는 들어가지 않는다.** 신뢰구간이 신뢰구간이 매우 넓은 수치로 두 조건의 차이를 주장할 수 없기 때문이다. 지우지 않고 표시만 한다.

## 분할 정책

**컷오프: 2025-01-01.** 평가 세트는 이 날짜 이후에 공개된 CVE에서만 뽑는다.

이유는 하나다. CVE 텍스트는 웹 전역에 미러링되어 있어 무작위 분할로는 베이스 모델의 사전학습 오염을 막을 수 없다. 막을 수 있는 것은 **베이스 모델이 볼 수 없었던 날짜**뿐이다. 학습은 컷오프 이전 데이터만 쓴다(`training_uses_only_pre_cutoff`: True).

컷오프 이전 평가 세트도 같은 크기로 유지한다. 두 평가 세트의 차이는 **오염된 상태와 오염되지 않은 상태의 대조**이지, 난이도 비교가 아니다.

| 항목 | 값 |
|---|---|
| 기간별 평가 표본 | 5,000 |
| 학습(CVE) | 228,867 |
| 컷오프 이후 · 미사용 | 102,836 |
| 제외(CVE) | 53,255 |
| ATT&CK 학습 / 평가·이후 / 평가·이전 / 제외 | 738 / 79 / 79 / 22 |

컷오프 이후 CVE 중 102,836건은 평가 표본에 뽑히지 않고 **미사용으로 남겨 둔다.** 학습에 넣으면 컷오프의 의미가 사라지고, 평가에 다 넣으면 평가 비용이 감당되지 않는다. 지우지 않고 표시한다.

## 오염 처리

학습 텍스트 613,092건을 해싱해 평가 항목마다 최근접 이웃을 찾고, Jaccard가 0.75 이상이면 제거한다. **적용되는 기준은 이것 하나다.**

`13-gram` 커버리지는 **측정해서 붙이되 거르지 않는다.** 모든 평가 항목에 `train_ngram_coverage`가 달리고, 평가 세트마다 사분위 경계가 기록되며, P4는 전체 점수와 계층별 점수를 함께 보고한다. 커버리지가 높은 항목의 정확도가 높은 것은 오염일 수도, 그 항목이 쉬운 것일 수도 있다 — 거르면 그 구분이 영원히 불가능해진다.

| 평가 세트 | 제거 전 | 제거 후 | 제거 | 제거율 | 커버리지 0 | `P3.1`이라면 제거했을 수 |
|---|---|---|---|---|---|---|
| `cve_to_cwe` / 컷오프 이후 | 3,897 | 3,867 | 30 | 0.77% | 2,815 | 224 |
| `cve_to_cwe` / 컷오프 이전 | 4,095 | 4,014 | 81 | 1.98% | 2,018 | 711 |
| `cvss_vector` / 컷오프 이후 | 4,578 | 4,549 | 29 | 0.63% | 3,116 | 245 |
| `cvss_vector` / 컷오프 이전 | 4,993 | 4,904 | 89 | 1.78% | 2,496 | 833 |
| `structured_extract` / 컷오프 이후 | 3,355 | 3,328 | 27 | 0.80% | 2,177 | 238 |
| `structured_extract` / 컷오프 이전 | 2,385 | 2,307 | 78 | 3.27% | 936 | 554 |
| `attack_technique` / 컷오프 이후 | 79 | 79 | 0 | 0.00% | 72 | 0 |
| `attack_technique` / 컷오프 이전 | 79 | 79 | 0 | 0.00% | 44 | 12 |

`P3.1`은 근사 중복 **또는** 커버리지가 0.5을 넘는 것을 적용해 2,817건을 제거했다. `P3.2`는 근사 중복만 적용해 334건을 제거하고 2,483건을 되돌렸다. 두 수의 합은 정확히 첫 번째 수와 같으며, 그 항등식은 `datasets/build.py`의 단언으로 강제된다.

제거된 항목의 Jaccard 분포: 최소 0.75, `q25` 0.7692, 중앙값 0.7812, `q75` 0.82, 최대 1.0.

평가 세트끼리의 교차 오염은 네 과제 모두 0건이다.

## 결정과 그 개수

각 결정은 얼마나 많은 레코드를 움직였는지와 함께 적는다. 개수 없는 정책은 검증할 수 없다.

### CWE 정답 정책

> agree->label; one side->label with source; disagree->contested, excluded, reported; placeholders absent; REJECTED excluded everywhere; multi-CWE excluded from the single-label task

| 버킷 | 건수 | 처리 |
|---|---|---|
| 두 출처가 합의 (`agreed`) | 127,332 | 정답으로 사용 |
| NVD만 라벨 (`nvd`) | 154,289 | 출처를 기록하고 사용 |
| CNA만 라벨 (`cna`) | 1,740 | 출처를 기록하고 사용 |
| 두 출처가 **불일치** (`contested`) | 13,562 | **제외하고 보고** |
| NVD-CWE-noinfo 등 플레이스홀더 (`placeholder`) | 53,149 | **라벨 없음으로 취급** |
| CWE 여러 개 (`multi_cwe`) | 21,076 | 단일 라벨 과제에서 제외 |
| 라벨 없음 (`none`) | 5,452 | 제외 |
| REJECTED 상태 CVE (`rejected`) | 18,358 | **제외** |

**불일치 13,562건을 제외한 것**은 이 명세에서 가장 큰 임의적 결정이다. 두 권위 있는 출처가 같은 CVE에 다른 CWE를 붙였을 때 어느 쪽을 정답으로 삼을 근거가 없다. 정답 없는 항목으로 모델을 채점하면 채점하는 것은 모델이 아니라 출처 선택이다. 제외하되 **보고한다** — 상위 CNA와 상위 충돌 쌍은 매니페스트의 `contested_structure`에 있다.

플레이스홀더 53,149건은 "분류 정보 없음"을 뜻하는 표식이지 CWE가 아니다. 라벨로 취급하면 모델은 "모름"을 예측하도록 학습된다. 라벨 없음으로 취급한다.

REJECTED CVE 18,358건은 철회된 식별자다. 본문이 비어 있거나 철회 사유만 남아 있다. 제외한다.

**누출 가드**: 근사 중복 클러스터의 대표 하나만 남기면, 남은 대표가 평가 세트에 있을 때 동일 내용의 학습 항목이 조용히 사라진다. 이를 막기 위해 1,265건을 학습으로 되돌리고, 대표가 평가에 있어 되돌리지 않은 29건은 그 사실과 함께 기록했다. 이 가드의 출처 표기는 `interim guard in datasets/build.py; P2.1 not delivered, reconciliation deferred`로 매니페스트에 남아 있다.

### 학습 조건

> equal total token budget T. Cond-1: T domain. Cond-2: (1-f)T domain drawn from Cond-1 by the same seed and order, plus fT replay. Both run the same number of optimizer steps (see lengths.equal_budget_schedule).

| | Cond-1 | Cond-2 |
|---|---|---|
| 도메인 토큰 | 9,960,190 | 7,967,976 |
| 리플레이 토큰 | 0 | 1,992,009 |
| 합계 | 9,960,190 | 9,959,985 |
| 예제 | 60,000 | 47,913 + 9,043 리플레이 |
| 옵티마이저 스텝 | 157 | 157 |

두 조건의 예산 차이는 205토큰, 즉 0.0021%다. **Cond-2의 도메인 집합은 Cond-1의 진부분집합**이며, 정렬된 `example_id`의 sha256이 교집합의 sha256과 같다는 것으로 증명된다(`python -m datasets.build --verify-subset`).

이 설계의 대가는 분명하다: 동일 토큰 예산을 유지했으므로 Cond-2는 도메인 데이터를 Cond-1보다 적게 본다. 도메인 정확도에서 Cond-1이 앞서는 것은 발견이 아니라 설계의 귀결이다.

### 리플레이 세트

출처는 `replay_oasst2`. 원본에서 쌍 37,100개를 뽑았고 이 중 9,043개가 동일 예산 조건에 들어갔다.

제외 사유별 개수: 언어 42,570, 삭제됨 3,197, 검수 탈락 1,770, 너무 짧음 681. 선택된 쌍의 언어 분포는 영어 37,091 / 한국어 9이다.

리플레이에도 P2와 **동일한** 비밀·PII 스캔을 적용했다 — 37,100쌍 중 110쌍에서 발견. 정책은 P2와 같다.

모델이 생성한 메시지(`synthetic: true`)는 **제외**한다. 사람이 쓴 턴만 쓴다는 제약이며, 그것이 HelpSteer2를 쓰지 않은 이유이기도 하다 — 라이선스가 아니라 출처 때문이다(`docs/LICENSES.md`).

## 이 명세가 수정한 것들

아래 네 건은 모두 **출판된 뒤에 발견된 결함**이다. 각각이 `docs/engineering-rules.md`의 규칙 하나를 낳았고, 그 규칙은 지금도 강제된다. 수정 이력을 적지 않은 명세보다 적은 명세가 더 믿을 만하다.

| 단계 | 결함 | 독자가 내렸을 결론 | 실제 | 낳은 규칙 |
|---|---|---|---|---|
| `P1.1` | `cwe` 매니페스트의 다이제스트가 Gate 1 테스트의 유도된 실패로 오염 | `cwe` 수집 실패 | 완전한 `v4.20` 매니페스트로 성공 | 규칙 {F.plain('refs', 'engineering_rules', 'report_renders_the_record')} |
| P3 | `--assert-zero` 재검증이 제거 기록과 **같은 파일**을 `removed: 0`으로 덮어씀 | 오염 없음 | 평가 세트의 상당 부분이 제거됨 | 규칙 {F.plain('refs', 'engineering_rules', 'report_renders_the_record')} |
| `P3.1` | 커버리지 초과를 **근거 없이** 제거 기준으로 사용 | 오염 제거 | 커버리지가 높다는 것과 오염되었다는 것은 다른 진술 · 2,483건 복원 | 규칙 5 |
| P5 | 짝지은 비교를 주변 신뢰구간 겹침으로 판정 | 차이 없음 | McNemar p=0.00019인 비교가 "차이 검출되지 않음"으로 출판됨 | 규칙 {F.plain('refs', 'engineering_rules', 'the_test_must_match_the_design')} |

네 번째 결함의 판정 규칙은 **P4 작업지시서가 명시한 것**이고 구현은 그대로 따랐다. 그 규칙은 출처까지 기록한다 — 지시서에서 온 결함도 결함이며, 지시서를 따랐다는 것은 잘못된 숫자를 출판한 변명이 되지 않는다.

보정 전 수치는 지우지 않았다. `runs/compare_p5_uncorrected.json`에 그대로 있다.

전체 규칙과 각 규칙이 나온 사건은 `docs/engineering-rules.md`에 있다.

## 무결성

데이터셋 매니페스트 해시 `61c060f77d28f95482abc816664f1970c9ae5b30a18e51adca45c34cf25ff149`는 세 실행 모두에서 같다. 평가 하니스는 모델을 적재하기 **전에** 이 해시와 개별 평가 파일의 sha256을 검증하고, 하나라도 어긋나면 중단한다.

| 평가 파일 | 건수 | sha256 |
|---|---|---|
| `attack_technique/eval_post_cutoff.jsonl` | 79 | `ab5e1e632d6a842d…` |
| `attack_technique/eval_pre_cutoff.jsonl` | 79 | `27aaa6817ad0b439…` |
| `cve_to_cwe/eval_post_cutoff.jsonl` | 3,867 | `20c22e3a02489ce0…` |
| `cve_to_cwe/eval_pre_cutoff.jsonl` | 4,014 | `59b98bb44c9fe42a…` |
| `cvss_vector/eval_post_cutoff.jsonl` | 4,549 | `3473afda2ad9c50f…` |
| `cvss_vector/eval_pre_cutoff.jsonl` | 4,904 | `278ee3ea4dc6dcbd…` |
| `structured_extract/eval_post_cutoff.jsonl` | 3,328 | `88ec0614ff5a32ce…` |
| `structured_extract/eval_pre_cutoff.jsonl` | 2,307 | `e10034a18ce04897…` |

결정론: This manifest contains no wall-clock field. All timestamps derive from the committed pin, so re-running the ingester against the same pin reproduces this file byte for byte. Run time is recorded in reports/ingest.md.

