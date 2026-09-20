# SBOM

> 이 문서는 매니페스트와 실행 산출물에서 **자동 생성**된다. 손으로 고치지 말고 `make docs`로 다시 만들 것. 모든 수치의 출처는 `docs/trace.json`에 경로로 기록되어 있고 `python -m docs.trace_check --assert-all`이 이를 독립적으로 재확인한다.


`sbom.spdx.json`은 `SPDX-2.3` 형식이며 `env/versions.lock` — 게이트가 실제로 통과한 환경의 동결본 — 에서 생성된다. 파이썬 패키지 207개와 고정된 데이터 출처 네 개를 담는다.

데이터 출처를 SBOM에 넣는 이유는 단순하다. 이 프로젝트의 산출물에 법적 의무를 부과할 수 있는 것은 파이썬 패키지가 아니라 **데이터**다.

## 두 가지 설계 결정

**생성 시각은 시계가 아니라 핀에서 가져온다.** `creationInfo.created`는 `2026-09-18T04:37:32Z`이며, 이는 `ingest/sources.lock.json`에 기록된 가장 최근 핀 시각이다. 빌드 시각을 찍으면 문서가 바이트 단위로 재현되지 않고, 재현되지 않는 SBOM은 이 저장소의 나머지 주장과 어긋난다.

**파이썬 패키지의 라이선스는 `NOASSERTION`이다.** 고정된 환경은 학습 호스트에 있고 이 문서는 로컬에서 만들어진다. 로컬에 우연히 설치된 **다른 버전**의 패키지에서 라이선스를 읽어 고정된 버전에 붙이면 그것은 확인이 아니라 **날조된 귀속**이다. 비어 있는 편이 낫다. 실제 확인이 필요해지면 학습 호스트에서 설치된 배포판 메타데이터로 다시 생성해야 하며, 그때 이 칸이 채워진다.

## 데이터 라이선스와 의존성 라이선스의 교차 확인

확인한 질문은 이것이다 — **어느 한쪽의 의무가 다른 쪽으로 전파되어 산출물을 구속하는가?**

| 방향 | 확인한 것 | 결과 |
|---|---|---|
| 데이터 → 산출물 | 카피레프트(ShareAlike/GPL 계열) 조항을 가진 데이터 출처가 있는가 | **없음.** 채택된 다섯 출처는 모두 귀속 조건부 허용이다 |
| 데이터 → 가중치 | 가중치 공개를 허용하거나 금지하는 조항이 있는가 | **어느 출처도 언급하지 않는다.** 침묵이지 허가가 아니다 |
| 의존성 → 산출물 | 파이썬 패키지의 라이선스가 산출물(매니페스트·보고서·가중치)에 의무를 부과하는가 | **확인하지 못했다** — 위 `NOASSERTION` 사유 |

첫 번째 줄이 중요한 이유는 기각된 후보들에서 드러난다. 리플레이 후보 중 카피레프트 조항을 가진 것들(`databricks/databricks-dolly-15k`의 ShareAlike, `GAIR/lima`의 NC+SA)은 **바로 그 이유로 기각되었다.** 채택된 `oasst2`는 Apache-2.0이며 ShareAlike가 없다. 따라서 어떤 카피레프트 의무도 산출물에 도달하지 않는다. 기각 사유 전체는 `docs/LICENSES.md`에 있다.

세 번째 줄은 미결이며 그렇게 표시된다. 이 프로젝트가 배포하는 것은 코드·매니페스트·보고서이고 파이썬 패키지를 재배포하지 않으므로 실무적 위험은 낮지만, **낮다는 것과 확인했다는 것은 다른 진술이다.**

## 데이터 출처 항목

| 출처 | 버전/커밋 | 선언된 라이선스 | SPDX `licenseConcluded` |
|---|---|---|---|
| `cve_list` | `9d4f632aa6e148754e1f27bdfb69f4635792f69a` | CVE Program Terms of Use (The MITRE Corporation) | `NOASSERTION` |
| `nvd` | `` | US Government work, public domain under 17 U.S.C. (NIST publication); NVD requests a source-attribution notice | `NOASSERTION` |
| `cwe` | `4.20` | CWE Terms of Use (The MITRE Corporation) | `NOASSERTION` |
| `attack` | `19.2` | MITRE ATT&CK License (LICENSE.txt in attack-stix-data) | `NOASSERTION` |

`licenseConcluded`가 `NOASSERTION`인 것은 확인하지 않았기 때문이 아니다. 이 문서들은 SPDX 목록에 있는 라이선스가 아니라 각 기관의 이용약관이며, SPDX 식별자로 축약하면 원문이 실제로 무엇을 허용하는지가 사라진다. `licenseDeclared`에 원문 이름을 적고, 근거 문장은 `docs/LICENSES.md`에 둔다.

## 검증

```bash
make docs
python -c "import json; d=json.load(open('sbom.spdx.json')); print(d['spdxVersion'], len(d['packages']), 'packages')"
```

`make docs`를 두 번 실행하면 `sbom.spdx.json`은 바이트 단위로 같다.

