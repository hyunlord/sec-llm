# -*- coding: utf-8 -*-
"""sbom.spdx.json and docs/SBOM.md.

The SPDX document is generated from `env/versions.lock` -- the freeze of the
environment the gates actually ran in -- plus the four pinned data sources,
which belong in a bill of materials as much as the Python packages do.

Two deliberate choices, both recorded in the markdown note:

* `created` is taken from the newest source pin, not from the clock. A document
  that stamps the build time is not byte-reproducible, and this one has to be.
* Every Python package carries `NOASSERTION` for its license. The pinned
  environment lives on the training host; this build runs on a laptop where a
  different set of packages at different versions happens to be importable.
  Reading a license off *those* and attributing it to the pinned version would
  be a fabricated attribution, which is worse than an honest absence.
"""

from __future__ import annotations

import hashlib
import json
import re

from docs.common import Fmt, gen_note

SOURCES4 = ("cve_list", "nvd", "cwe", "attack")
SPDX_NAME = "sec-llm"


def _spdxid(prefix: str, name: str) -> str:
    return f"SPDXRef-{prefix}-" + re.sub(r"[^A-Za-z0-9.\-]", "-", name)


def _created(F: Fmt) -> str:
    """Newest source pin, not the clock. Deterministic by construction."""
    stamps = [F.get("lock", "sources", sid, "pinned_at_utc") for sid in SOURCES4]
    return max(stamps)


def _download_location(F: Fmt, sid: str) -> str:
    pin = F.get("lock", "sources", sid)
    if "clone_url" in pin:
        return f"git+{pin['clone_url']}@{pin['commit_sha']}"
    if "url" in pin:
        return pin["url"]
    if "repo" in pin:
        return f"git+https://github.com/{pin['repo']}.git@{pin['commit_sha']}"
    return "NOASSERTION"


def spdx_json(F: Fmt) -> str:
    versions = F.get("versions")
    created = _created(F)
    digest = hashlib.sha256(
        json.dumps(versions, sort_keys=True).encode() + created.encode()).hexdigest()

    packages = [{
        "SPDXID": _spdxid("Package", SPDX_NAME),
        "name": SPDX_NAME,
        "versionInfo": "P7",
        "downloadLocation": F.get("refs", "repo_url"),
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
        "comment": ("the pipeline itself; its published artifacts are manifests, pins and "
                    "reports, and it does not redistribute the raw corpora"),
    }]

    for name in sorted(versions):
        packages.append({
            "SPDXID": _spdxid("Pypi", name),
            "name": name,
            "versionInfo": versions[name],
            "downloadLocation": f"https://pypi.org/project/{name}/{versions[name]}/",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:pypi/{name}@{versions[name]}",
            }],
            "comment": ("license not asserted: the pinned environment lives on the training "
                        "host and was not available to this build; see docs/SBOM.md"),
        })

    for sid in SOURCES4:
        lic = F.get(sid, "license")
        packages.append({
            "SPDXID": _spdxid("Data", sid),
            "name": sid,
            "versionInfo": str(F.get("lock", "sources", sid).get(
                "version", F.get("lock", "sources", sid).get("commit_sha", "NOASSERTION"))),
            "downloadLocation": _download_location(F, sid),
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": lic["source_license"],
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "SOURCE",
            "comment": (f"data source. redistribution={lic['redistribution_status']}; "
                        f"commercial={lic['commercial_status']}; "
                        f"model_publication={lic['model_publication_status']}. "
                        f"Evidence and verification date in docs/LICENSES.md. "
                        f"licenseConcluded is NOASSERTION because these are terms-of-use "
                        f"documents, not SPDX-listed licenses."),
        })

    doc = {
        "spdxVersion": F.get("refs", "spdx", "spec_version"),
        "dataLicense": F.get("refs", "spdx", "data_license"),
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{SPDX_NAME}-sbom",
        "documentNamespace": f"{F.get('refs', 'repo_url')}/spdx/{digest[:32]}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: sec-llm-docs-build"],
            "comment": ("created is the newest source pin recorded in ingest/sources.lock.json, "
                        "not the build clock: this document must reproduce byte for byte."),
        },
        "packages": packages,
        "relationships": (
            [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
              "relatedSpdxElement": _spdxid("Package", SPDX_NAME)}]
            + [{"spdxElementId": _spdxid("Package", SPDX_NAME),
                "relationshipType": "DEPENDS_ON", "relatedSpdxElement": p["SPDXID"]}
               for p in packages[1:]]
        ),
    }
    return json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def render(F: Fmt) -> str:
    L = ["# SBOM", "", gen_note(), ""]

    L.append(f"`sbom.spdx.json`은 `{F.get('refs', 'spdx', 'spec_version')}` 형식이며 "
             f"`env/versions.lock` — 게이트가 실제로 통과한 환경의 동결본 — 에서 생성된다. "
             f"파이썬 패키지 {F.count('versions')}개와 고정된 데이터 출처 네 개를 담는다.")
    L.append("")
    L.append("데이터 출처를 SBOM에 넣는 이유는 단순하다. 이 프로젝트의 산출물에 법적 의무를 "
             "부과할 수 있는 것은 파이썬 패키지가 아니라 **데이터**다.")
    L.append("")

    L.append("## 두 가지 설계 결정")
    L.append("")
    L.append(f"**생성 시각은 시계가 아니라 핀에서 가져온다.** `creationInfo.created`는 "
             f"`{_created(F)}`이며, 이는 `ingest/sources.lock.json`에 기록된 가장 최근 핀 시각이다. "
             "빌드 시각을 찍으면 문서가 바이트 단위로 재현되지 않고, 재현되지 않는 SBOM은 "
             "이 저장소의 나머지 주장과 어긋난다.")
    L.append("")
    L.append("**파이썬 패키지의 라이선스는 `NOASSERTION`이다.** 고정된 환경은 학습 호스트에 있고 "
             "이 문서는 로컬에서 만들어진다. 로컬에 우연히 설치된 **다른 버전**의 패키지에서 "
             "라이선스를 읽어 고정된 버전에 붙이면 그것은 확인이 아니라 **날조된 귀속**이다. "
             "비어 있는 편이 낫다. 실제 확인이 필요해지면 학습 호스트에서 "
             "설치된 배포판 메타데이터로 다시 생성해야 하며, 그때 이 칸이 채워진다.")
    L.append("")

    L.append("## 데이터 라이선스와 의존성 라이선스의 교차 확인")
    L.append("")
    L.append("확인한 질문은 이것이다 — **어느 한쪽의 의무가 다른 쪽으로 전파되어 산출물을 "
             "구속하는가?**")
    L.append("")
    L.append("| 방향 | 확인한 것 | 결과 |")
    L.append("|---|---|---|")
    L.append("| 데이터 → 산출물 | 카피레프트(ShareAlike/GPL 계열) 조항을 가진 데이터 출처가 있는가 "
             "| **없음.** 채택된 다섯 출처는 모두 귀속 조건부 허용이다 |")
    L.append("| 데이터 → 가중치 | 가중치 공개를 허용하거나 금지하는 조항이 있는가 "
             "| **어느 출처도 언급하지 않는다.** 침묵이지 허가가 아니다 |")
    L.append("| 의존성 → 산출물 | 파이썬 패키지의 라이선스가 산출물(매니페스트·보고서·가중치)에 "
             "의무를 부과하는가 | **확인하지 못했다** — 위 `NOASSERTION` 사유 |")
    L.append("")
    L.append("첫 번째 줄이 중요한 이유는 기각된 후보들에서 드러난다. "
             "리플레이 후보 중 카피레프트 조항을 가진 것들"
             "(`databricks/databricks-dolly-15k`의 ShareAlike, `GAIR/lima`의 NC+SA)은 "
             "**바로 그 이유로 기각되었다.** 채택된 `oasst2`는 Apache-2.0이며 ShareAlike가 없다. "
             "따라서 어떤 카피레프트 의무도 산출물에 도달하지 않는다. "
             "기각 사유 전체는 `docs/LICENSES.md`에 있다.")
    L.append("")
    L.append("세 번째 줄은 미결이며 그렇게 표시된다. 이 프로젝트가 배포하는 것은 코드·매니페스트·"
             "보고서이고 파이썬 패키지를 재배포하지 않으므로 실무적 위험은 낮지만, "
             "**낮다는 것과 확인했다는 것은 다른 진술이다.**")
    L.append("")

    L.append("## 데이터 출처 항목")
    L.append("")
    L.append("| 출처 | 버전/커밋 | 선언된 라이선스 | SPDX `licenseConcluded` |")
    L.append("|---|---|---|---|")
    for sid in SOURCES4:
        pin = F.get("lock", "sources", sid)
        ver = pin.get("version") or pin.get("commit_sha", "")
        L.append(f"| `{sid}` | `{ver}` | {F.s(sid, 'license', 'source_license')} | `NOASSERTION` |")
    L.append("")
    L.append("`licenseConcluded`가 `NOASSERTION`인 것은 확인하지 않았기 때문이 아니다. "
             "이 문서들은 SPDX 목록에 있는 라이선스가 아니라 각 기관의 이용약관이며, "
             "SPDX 식별자로 축약하면 원문이 실제로 무엇을 허용하는지가 사라진다. "
             "`licenseDeclared`에 원문 이름을 적고, 근거 문장은 `docs/LICENSES.md`에 둔다.")
    L.append("")

    L.append("## 검증")
    L.append("")
    L.append("```bash")
    L.append("make docs")
    L.append("python -c \"import json; d=json.load(open('sbom.spdx.json')); "
             "print(d['spdxVersion'], len(d['packages']), 'packages')\"")
    L.append("```")
    L.append("")
    L.append("`make docs`를 두 번 실행하면 `sbom.spdx.json`은 바이트 단위로 같다.")
    L.append("")
    return "\n".join(L) + "\n"
