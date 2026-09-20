# 라이선스 정합성

> 이 문서는 매니페스트와 실행 산출물에서 **자동 생성**된다. 손으로 고치지 말고 `make docs`로 다시 만들 것. 모든 수치의 출처는 `docs/trace.json`에 경로로 기록되어 있고 `python -m docs.trace_check --assert-all`이 이를 독립적으로 재확인한다.


## 결론부터

**네 개 보안 출처와 리플레이 출처 모두 모델 가중치에 대해 아무 말도 하지 않는다.** 금지한 것이 아니라 언급하지 않는다. 가중치 공개는 허가가 아니라 그 침묵 위에 서 있고, 이 차이는 문서상 구분되어야 한다. 이 표에서 **문서에 언급 없음**은 "해당 문서를 읽었고 그 항목이 없었다"는 *확인된 사실*이며, **확인 불가**는 "아무도 확인하지 않았다"는 *확인의 부재*다. 둘은 서로 다른 칸으로 렌더링되고, 어느 출처도 후자에 해당하지 않는다.

재배포는 다르다. 다섯 출처 모두 출처 표기를 조건으로 재배포를 명시적으로 허용한다. 다만 이 저장소는 원본 코퍼스를 재배포하지 않는다 — 매니페스트와 핀과 해시만 배포하고 내려받기는 그것으로 재구성한다(`docs/REPRODUCE.md`).

상업적 이용은 출처마다 갈린다. CVE List와 oasst2의 라이선스 본문에는 "commercial"이라는 단어가 등장하지 않으므로 **허용**이 아니라 **문서에 언급 없음**으로 적는다. 이 구분은 사람이 읽는 산문에만 있었고 기계가 읽는 필드에는 없었던 적이 있으며, 그것이 `ingest/audit_licenses.py`가 존재하는 이유다.

## 권한 매트릭스

| 출처 | 라이선스 | 재배포 | 가중치 공개 | 상업적 이용 | 확인일 |
|---|---|---|---|---|---|
| `cve_list`<br>CVE List V5 (CVEProject/cvelistV5) | CVE Program Terms of Use (The MITRE Corporation) | 허용 (출처 표기 조건) | 문서에 언급 없음 | 문서에 언급 없음 | 2026-09-18 |
| `nvd`<br>NVD CVE API 2.0 (NIST National Vulnerability Database) | US Government work, public domain under 17 U.S.C. (NIST publication); NVD requests a source-attribution notice | 허용 (출처 표기 조건) | 문서에 언급 없음 | 허용 (출처 표기 조건) | 2026-09-18 |
| `cwe`<br>CWE (Common Weakness Enumeration) versioned XML catalog | CWE Terms of Use (The MITRE Corporation) | 허용 (출처 표기 조건) | 문서에 언급 없음 | 허용 (출처 표기 조건) | 2026-09-18 |
| `attack`<br>MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data) | MITRE ATT&CK License (LICENSE.txt in attack-stix-data) | 허용 (출처 표기 조건) | 문서에 언급 없음 | 허용 (출처 표기 조건) | 2026-09-18 |
| `replay_oasst2`<br>OpenAssistant/oasst2 (general-instruction replay set) | Apache License 2.0 (declared in the dataset card: `license: apache-2.0`) | 허용 (출처 표기 조건) | 문서에 언급 없음 | 문서에 언급 없음 | 2026-09-19 |
| `replay_helpsteer2_not_used` *(미사용)*<br>nvidia/HelpSteer2 (evaluated as replay top-up -- NOT USED) | Creative Commons Attribution 4.0 (declared in the dataset card: `license: cc-by-4.0`) | 허용 (출처 표기 조건) | 문서에 언급 없음 | 허용 | 2026-09-19 |

빈 칸은 없다. 확인되지 않은 항목이 있었다면 **확인 불가**로 적히고 그 자체가 결함으로 보고된다.

## 근거 문장

각 판정은 그 출처의 문서에서 직접 읽은 문장에 근거한다. `ingest/audit_licenses.py`는 권한을 주장하는 필드가 자기 근거에 없는 내용을 주장하면 비정상 종료 코드를 반환한다 — 재배포·상업적 이용은 `license_evidence`가, 가중치 공개는 `weights_release_evidence`가 각각 뒷받침한다.

### `cve_list` — CVE List V5 (CVEProject/cvelistV5)

라이선스 원문: <https://www.cve.org/Legal/TermsOfUse>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> CVE Usage: "MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." The grant carries no field-of-use restriction, but note that -- unlike CWE and ATT&CK -- the word "commercial" does not appear in the CVE Terms of Use.

**가중치 공개의 근거** (가중치 공개)

> The Terms of Use grant the right to prepare derivative works and to distribute them, and impose an attribution condition. They do not mention machine learning, training, or model weights in any form. Whether a trained weight is a derivative work of the training corpus is not settled by this document. Legal review required.

**상위 출처의 권리 관계**: CNA submissions under the CVE Program Terms of Use submitter grant (submitters grant MITRE and all CNAs a perpetual, royalty-free, irrevocable copyright license)

### `nvd` — NVD CVE API 2.0 (NIST National Vulnerability Database)

라이선스 원문: <https://nvd.nist.gov/developers/start-here>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> "All NIST publications are available in the public domain according to Title 17 of the United States Code, however services which utilize or access the NVD are asked to display the following notice prominently within the application: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.' You may use the NVD name to identify the source of the data. You may not use the NVD name, to imply endorsement of any product, service, or entity, not-for-profit, commercial or otherwise." Commercial use is therefore contemplated; only use of the NVD *name* to imply endorsement is restricted.

**가중치 공개의 근거** (가중치 공개)

> NVD's own analysis being public domain places no restriction on weight release. The embedded CVE content is a different matter and inherits the CVE Terms of Use, which do not address model weights. This is precisely why source_license and upstream_license are separate fields.

**상위 출처의 권리 관계**: CVE Program Terms of Use (The MITRE Corporation) -- the CVE records embedded in every NVD response originate from the CVE Program and are NOT a US Government work; only NVD's own analysis (CVSS scoring, CPE applicability, CWE mapping) is public domain

### `cwe` — CWE (Common Weakness Enumeration) versioned XML catalog

라이선스 원문: <https://cwe.mitre.org/about/termsofuse.html>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> "CWE is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy."

**가중치 공개의 근거** (가중치 공개)

> Commercial use is granted explicitly, but the Terms of Use do not mention training or model weights. The contributor grant does include the right to "prepare derivative works". Legal review required.

**상위 출처의 권리 관계**: Community contributions under the CWE Terms of Use contributor grant (contributors grant all users a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license)

### `attack` — MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data)

라이선스 원문: <https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." Required designation: "(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

**가중치 공개의 근거** (가중치 공개)

> Commercial use is granted explicitly. The license is silent on machine learning, training corpora, and model weights. Legal review required.

**상위 출처의 권리 관계**: Same MITRE ATT&CK License; individual STIX objects carry external_references to third-party vendor threat reports, which are cited but not redistributed

### `replay_oasst2` — OpenAssistant/oasst2 (general-instruction replay set)

라이선스 원문: <https://huggingface.co/datasets/OpenAssistant/oasst2/blob/main/README.md>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> Dataset card frontmatter, read 2026-09-19 at commit 179dd21f: `license: apache-2.0`. The repository ships NO separate LICENSE file; the declaration is the card's SPDX field. Apache License 2.0 section 2 grants "a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form"; section 4 conditions redistribution on retaining attribution and NOTICE. The word "commercial" does not appear in the Apache License 2.0 text; the grant carries no field-of-use restriction. Held to the same standard as cve_list, that is not_addressed rather than permitted.

**가중치 공개의 근거** (가중치 공개)

> Apache-2.0 grants the right to prepare and distribute Derivative Works broadly, but does not mention machine learning, training, or model weights. Whether a trained weight is a Derivative Work of the training corpus is not settled by the license text. Same open question as the four security sources; legal review required.

**상위 출처의 권리 관계**: Human volunteer contributions to the Open Assistant project, released by the project under the same Apache-2.0 declaration; model-generated messages (`synthetic: true`, with the generating model named) exist in the raw data and are EXCLUDED from the replay set so no third model's terms apply

### `replay_helpsteer2_not_used` — nvidia/HelpSteer2 (evaluated as replay top-up -- NOT USED)

라이선스 원문: <https://huggingface.co/datasets/nvidia/HelpSteer2/blob/main/README.md>

**재배포 · 상업적 이용의 근거** (재배포 / 상업적 이용)

> Dataset card, read 2026-09-19 at commit 990b2711: `license: cc-by-4.0`. CC BY 4.0 section 2(a)(1) grants a licence to "reproduce and Share the Licensed Material, in whole or in part; and produce, reproduce, and Share Adapted Material", and the CC BY 4.0 legal code contains no NonCommercial restriction (unlike CC BY-NC); section 3(a) conditions Sharing on attribution. Commercial use is therefore permitted -- the legal code's own FAQ and the absence of the NC element establish it, and the word "commercial" appears in the licence text in the definition of NonCommercial, which this licence deliberately omits.

**가중치 공개의 근거** (가중치 공개)

> CC BY 4.0 does not mention machine learning, training, or model weights.

**상위 출처의 권리 관계**: Prompts: mostly user-contributed ShareGPT plus ~5% written by Scale AI. Responses: generated by in-house NVIDIA LLMs. The response turns are therefore model-generated, not human-written.

**사용하지 않은 이유**: The dataset card states under Source: "Responses are generated by early versions of a mix of 10 different inhouse LLMs (note: none from properitary LLM providers such as OpenAI)." Every response turn is model-generated. The replay constraint is English human-written turns only; using HelpSteer2 would leave prompts with no human-written response to pair them with. Rejected on provenance, not on licence.

## 리플레이 후보 중 기각된 것들

리플레이 세트는 **사람이 쓴 영어 응답**만 쓴다는 제약 아래 고른다. 라이선스로 기각된 것과 출처(provenance)로 기각된 것을 섞지 않는다.

| 후보 | 기각 사유 |
|---|---|
| `GAIR/lima` | license 'other' (CC-BY-NC-SA on inspection); NonCommercial + ShareAlike |
| `HuggingFaceH4/no_robots` | cc-by-nc-4.0 -- NonCommercial |
| `allenai/tulu-3-sft-mixture` | odc-by, but a MIXTURE of sources with differing underlying licenses; unclear/mixed |
| `databricks/databricks-dolly-15k` | cc-by-sa-3.0 -- ShareAlike imposes a copyleft condition on derivatives; mixed obligations |
| `nvidia/HelpSteer2` | cc-by-4.0 -- acceptable license, NOT rejected on license; not chosen because responses are model-generated, which brings a generating model's terms into scope. Recorded as the fallback. |

**HelpSteer2는 라이선스로 기각된 것이 아니다.** `CC BY 4.0`은 이 파이프라인이 요구하는 모든 권한을 부여하며, 위 매트릭스에서 상업적 이용이 **허용**으로 적힌 유일한 출처다. 기각 사유는 응답 턴이 전부 모델 생성물이라는 점 — 사람이 쓴 턴만 쓴다는 제약과 충돌한다. 라이선스가 아니라 출처가 이유였다는 사실 자체가 기록될 가치가 있다.

## 남아 있는 법적 미결 사항

학습된 가중치가 학습 코퍼스의 이차적 저작물인가 — 이 질문은 다섯 출처 중 어느 문서도 답하지 않는다. 이 저장소는 답을 추정하지 않고, 추정한 것처럼 보이지도 않게 한다. 가중치를 공개하려면 법률 검토가 선행되어야 하며, 그 검토의 출발점은 위 **가중치 공개의 근거** 절이다.

`contains_third_party_content`는 다섯 출처 모두에서 참이다. CVE 레코드의 CNA 제출물, ATT&CK STIX 객체가 인용하는 벤더 위협 보고서, oasst2의 자원봉사자 기여 — 상위 권리자가 존재하고, 그들의 권리는 위 **상위 출처의 권리 관계** 항목에 기록되어 있다.

