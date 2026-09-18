# 데이터 출처와 라이선스 매트릭스

> 이 문서는 `ingest/sources.py`로부터 **자동 생성**된다. 손으로 고치지 말고 `make sources-doc`으로 다시 만들 것. 표의 값은 모든 레코드의 lineage에 들어가는 값과 동일한 출처에서 나온다.

모든 라이선스 값은 **각 출처의 공식 문서를 직접 읽고** 기록했다. 유사 프로젝트에서 추정하지 않았고, 읽지 않은 라이선스를 적지 않았다. 출처 문서가 답하지 않는 항목은 **확인 불가**로 적고 무엇을 확인했는지 함께 남긴다.

## 매트릭스

| 출처 | 원본 재배포 가능 여부 | 이 데이터로 학습한 가중치 공개 가능 여부 | 상업적 이용 가능 여부 | 제3자 콘텐츠 포함 | 출처 URL | 라이선스 문서 | 확인 일자 |
|---|---|---|---|---|---|---|---|
| **CVE List V5 (CVEProject/cvelistV5)** | 가능 (출처 표기 조건) | 확인 불가 | 가능 (출처 표기 조건) | 예 | [https://github.com/CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | [CVE Program Terms of Use (The MITRE Corporation)](https://www.cve.org/Legal/TermsOfUse) | 2026-09-18 |
| **NVD CVE API 2.0 (NIST National Vulnerability Database)** | 가능 (출처 표기 조건) | 확인 불가 | 가능 (출처 표기 조건) | 예 | [https://services.nvd.nist.gov/rest/json/cves/2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) | [US Government work, public domain under 17 U.S.C. (NIST publication); NVD requests a source-attribution notice](https://nvd.nist.gov/developers/start-here) | 2026-09-18 |
| **CWE (Common Weakness Enumeration) versioned XML catalog** | 가능 (출처 표기 조건) | 확인 불가 | 가능 (출처 표기 조건) | 예 | [https://cwe.mitre.org/data/downloads.html](https://cwe.mitre.org/data/downloads.html) | [CWE Terms of Use (The MITRE Corporation)](https://cwe.mitre.org/about/termsofuse.html) | 2026-09-18 |
| **MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data)** | 가능 (출처 표기 조건) | 확인 불가 | 가능 (출처 표기 조건) | 예 | [https://github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | [MITRE ATT&CK License (LICENSE.txt in attack-stix-data)](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt) | 2026-09-18 |

> 빈 칸은 없다. **확인 불가**는 유효한 값이고 공란은 아니다.

## 컨테이너 라이선스와 콘텐츠 라이선스는 다르다

이 프로젝트가 `source_license`(컨테이너)와 `upstream_license`(내용물)를 **별도 필드로** 유지하는 이유다. 하나의 `license` 칼럼으로 합치면 아래 구분이 사라진다.

| 출처 | 컨테이너 라이선스 (`source_license`) | 내용물 라이선스 (`upstream_license`) |
|---|---|---|
| `cve_list` | CVE Program Terms of Use (The MITRE Corporation) | CNA submissions under the CVE Program Terms of Use submitter grant (submitters grant MITRE and all CNAs a perpetual, royalty-free, irrevocable copyright license) |
| `nvd` | US Government work, public domain under 17 U.S.C. (NIST publication); NVD requests a source-attribution notice | CVE Program Terms of Use (The MITRE Corporation) -- the CVE records embedded in every NVD response originate from the CVE Program and are NOT a US Government work; only NVD's own analysis (CVSS scoring, CPE applicability, CWE mapping) is public domain |
| `cwe` | CWE Terms of Use (The MITRE Corporation) | Community contributions under the CWE Terms of Use contributor grant (contributors grant all users a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license) |
| `attack` | MITRE ATT&CK License (LICENSE.txt in attack-stix-data) | Same MITRE ATT&CK License; individual STIX objects carry external_references to third-party vendor threat reports, which are cited but not redistributed |

가장 분명한 사례가 **NVD**다. NVD 자체 분석(CVSS 점수, CPE 적용범위, CWE 매핑)은 미국 정부 저작물로 퍼블릭 도메인이지만, **같은 JSON 객체 안에 들어 있는 CVE 설명은** CVE 프로그램에서 온 것이고 MITRE의 이용 약관을 따른다. 두 개를 하나로 합쳐 적으면 이 차이가 지워진다.

## 근거 (출처 문서 원문 인용)

### CVE List V5 (CVEProject/cvelistV5)

- 라이선스 문서: <https://www.cve.org/Legal/TermsOfUse> (확인 일자 2026-09-18)
- 재배포: **가능 (출처 표기 조건)** / 상업적 이용: **가능 (출처 표기 조건)**
- 근거 인용:
  > CVE Usage: "MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." The grant carries no field-of-use restriction, but note that -- unlike CWE and ATT&CK -- the word "commercial" does not appear in the CVE Terms of Use.

- **학습 가중치 공개: 확인 불가**
  - 확인한 내용: The Terms of Use grant the right to prepare derivative works and to distribute them, and impose an attribution condition. They do not mention machine learning, training, or model weights in any form. Whether a trained weight is a derivative work of the training corpus is not settled by this document. Legal review required.
- PII 정책: no_intentional_pii; free-text description/credit/reference fields may carry researcher or reporter names -- P2 secret/PII scanning is required
- 현재 핀: `git_commit` → `9d4f632aa6e148754e1f27bdfb69f4635792f69a`

### NVD CVE API 2.0 (NIST National Vulnerability Database)

- 라이선스 문서: <https://nvd.nist.gov/developers/start-here> (확인 일자 2026-09-18)
- 재배포: **가능 (출처 표기 조건)** / 상업적 이용: **가능 (출처 표기 조건)**
- 근거 인용:
  > "All NIST publications are available in the public domain according to Title 17 of the United States Code, however services which utilize or access the NVD are asked to display the following notice prominently within the application: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.' You may use the NVD name to identify the source of the data. You may not use the NVD name, to imply endorsement of any product, service, or entity, not-for-profit, commercial or otherwise." Commercial use is therefore contemplated; only use of the NVD *name* to imply endorsement is restricted.

- **학습 가중치 공개: 확인 불가**
  - 확인한 내용: NVD's own analysis being public domain places no restriction on weight release. The embedded CVE content is a different matter and inherits the CVE Terms of Use, which do not address model weights. This is precisely why source_license and upstream_license are separate fields.
- **필수 표기 문구**: `This product uses data from the NVD API but is not endorsed or certified by the NVD.`
- PII 정책: no_intentional_pii; free-text description/credit/reference fields may carry researcher or reporter names -- P2 secret/PII scanning is required
- 현재 핀: `api_snapshot` → `2026-09-18T04:37:25Z`

### CWE (Common Weakness Enumeration) versioned XML catalog

- 라이선스 문서: <https://cwe.mitre.org/about/termsofuse.html> (확인 일자 2026-09-18)
- 재배포: **가능 (출처 표기 조건)** / 상업적 이용: **가능 (출처 표기 조건)**
- 근거 인용:
  > "CWE is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy."

- **학습 가중치 공개: 확인 불가**
  - 확인한 내용: Commercial use is granted explicitly, but the Terms of Use do not mention training or model weights. The contributor grant does include the right to "prepare derivative works". Legal review required.
- PII 정책: no_intentional_pii; free-text description/credit/reference fields may carry researcher or reporter names -- P2 secret/PII scanning is required
- 현재 핀: `versioned_release` → `4.20`

### MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data)

- 라이선스 문서: <https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt> (확인 일자 2026-09-18)
- 재배포: **가능 (출처 표기 조건)** / 상업적 이용: **가능 (출처 표기 조건)**
- 근거 인용:
  > "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." Required designation: "(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

- **학습 가중치 공개: 확인 불가**
  - 확인한 내용: Commercial use is granted explicitly. The license is silent on machine learning, training corpora, and model weights. Legal review required.
- PII 정책: no_intentional_pii; free-text description/credit/reference fields may carry researcher or reporter names -- P2 secret/PII scanning is required
- 현재 핀: `git_tag_release` → `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`

## 네 출처 모두 답하지 않는 질문 — 학습 가중치

**네 출처 중 어느 것도 머신러닝 학습이나 모델 가중치를 언급하지 않는다.** 따라서 표의 해당 칸은 전부 **확인 불가**다.

확인한 내용은 다음과 같다:

- CWE와 ATT&CK는 "research, development, and commercial purposes"를 **명시적으로** 허용한다.
- CVE 이용 약관은 사용 목적 제한 없는 저작권 라이선스를 부여하지만 "commercial"이라는 단어 자체는 등장하지 않는다.
- 네 출처 모두 "prepare derivative works"(파생물 작성) 권리를 부여한다.
- 그러나 **학습된 가중치가 학습 코퍼스의 파생물에 해당하는지**는 이 문서들이 답하지 않는다. 이것은 라이선스 해석이 아니라 법률 판단의 영역이다.

> **법무 검토가 필요하다.** 이 표의 '확인 불가'를 '가능'으로 바꾸려면 근거가 될 문서나 법률 자문이 있어야 하며, 유사 프로젝트가 그렇게 하고 있다는 사실은 근거가 아니다.

## 배포 시 지켜야 할 표기 의무

재배포와 상업적 이용이 모두 **출처 표기 조건부**이므로, 산출물을 공개할 때 아래를 포함해야 한다.

- **NVD**: `This product uses data from the NVD API but is not endorsed or certified by the NVD.`
- **ATT&CK**: `© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.`
- **CWE / CVE**: MITRE의 저작권 표시와 해당 이용 약관 전문을 사본에 함께 포함.

