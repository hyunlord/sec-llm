# -*- coding: utf-8 -*-
"""sbom.spdx.json and docs/SBOM.md.

The SPDX document is generated from `env/versions.lock` -- the freeze of the
environment the gates actually ran in -- plus the four pinned data sources,
which belong in a bill of materials as much as the Python packages do.

Two deliberate choices, both recorded in the markdown note:

* `created` is taken from the newest source pin, not from the clock. A document
  that stamps the build time is not byte-reproducible, and this one has to be.
* Package licenses are read from the pinned interpreter on the training host
  (`tools/extract_licenses.py` -> `env/package_licenses.json`), never from
  whatever happens to be importable where this builds. P7 left them all at
  NOASSERTION for exactly that reason; P6 reads the right machine instead of
  guessing better. A package that declares nothing still reads NOASSERTION,
  and those are counted rather than quietly filled in.
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

    pkg_lic = F.get("pkglic", "packages")
    # The extractor runs on the training host, where the checkout predates the
    # docs package, so it carries its own copy of the lock parser. If the two
    # ever drift, the package sets differ and the build stops here rather than
    # publishing an SBOM keyed to a different lock than the one it names.
    if set(pkg_lic) != set(versions):
        raise SystemExit(
            "env/package_licenses.json does not cover env/versions.lock: "
            f"{len(set(versions) - set(pkg_lic))} locked packages missing, "
            f"{len(set(pkg_lic) - set(versions))} extra. Re-run tools/extract_licenses.py "
            "on the pinned interpreter.")

    for name in sorted(versions):
        rec = pkg_lic[name]
        concluded = rec["spdx"] or "NOASSERTION"
        packages.append({
            "SPDXID": _spdxid("Pypi", name),
            "name": name,
            "versionInfo": versions[name],
            "downloadLocation": f"https://pypi.org/project/{name}/{versions[name]}/",
            "filesAnalyzed": False,
            "licenseConcluded": concluded,
            "licenseDeclared": rec["declared"] or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:pypi/{name}@{versions[name]}",
            }],
            "comment": (f"licence read from the pinned interpreter on "
                        f"{F.get('pkglic', 'read_from', 'host')} "
                        f"({F.get('pkglic', 'read_from', 'interpreter')}) on "
                        f"{F.get('pkglic', 'read_on')}, field "
                        f"{rec.get('source_field') or 'none'}"
                        + (f"; {rec['note']}" if rec.get("note") else "")),
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
    L.append("**패키지 라이선스는 고정된 인터프리터에서 읽는다.** 이 문서를 만드는 기계가 아니라 "
             f"`env/versions.lock`을 만든 기계에서 읽는다 — 호스트 `{F.s('pkglic', 'read_from', 'host')}`"
             f"(`{F.s('pkglic', 'read_from', 'machine')}`), 인터프리터 "
             f"`{F.s('pkglic', 'read_from', 'interpreter')}` (Python "
             f"{F.s('pkglic', 'read_from', 'python_version')}), 읽은 날짜 "
             f"{F.s('pkglic', 'read_on')}. 로컬에 우연히 설치된 **다른 버전**에서 라이선스를 읽어 "
             "고정된 버전에 붙이는 것은 확인이 아니라 날조된 귀속이므로, 그 방법은 쓰지 않는다.")
    L.append("")
    L.append(f"읽는 대상은 배포판이 **스스로 선언한 것**뿐이다 — "
             f"{', '.join(chr(96) + x + chr(96) for x in F.get('pkglic', 'method', 'fields_consulted'))} 필드. 패키지 이름이나 이웃 패키지에서 추정하지 않는다. "
             "설치된 버전이 고정 버전과 다르면 귀속하지 않고 그 사실을 기록한다.")
    L.append("")

    L.append("### 읽은 결과")
    L.append("")
    L.append(f"고정 패키지 {F.n('pkglic', 'counts', 'locked')}개 중 "
             f"**{F.n('pkglic', 'counts', 'resolved')}개**에서 SPDX 식별자를 확정했고, "
             f"**{F.n('pkglic', 'counts', 'unresolved')}개**는 `NOASSERTION`으로 남았다. "
             "남은 것들은 채우지 못한 것이지 빠뜨린 것이 아니며, 사유별로 아래에 적는다.")
    L.append("")
    L.append("| `NOASSERTION`으로 남은 사유 | 개수 |")
    L.append("|---|---|")
    reasons = {}
    for n, rec in F.get("pkglic", "packages").items():
        if not rec["spdx"]:
            reasons.setdefault(rec.get("note", "unknown"), []).append(n)
    for r in sorted(reasons):
        names = ", ".join(f"`{x}`" for x in sorted(reasons[r])[:4])
        more = f" 외 {len(reasons[r]) - 4}개" if len(reasons[r]) > 4 else ""
        L.append(f"| {r}<br>{names}{more} | {len(reasons[r])} |")
    L.append("")
    L.append("가장 큰 덩어리는 NVIDIA CUDA 배포판들로, 분류자가 "
             "`License :: Other/Proprietary License`라서 **SPDX 식별자로 번역할 대상이 없다.** "
             "독점 라이선스라는 사실 자체는 선언되어 있고 그대로 `licenseDeclared`에 들어간다. "
             "번역표에 없는 분류자를 임의로 식별자에 밀어 넣지 않는 것이 이 표가 비어 있는 이유다.")
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
    L.append(f"| 의존성 → 산출물 | 파이썬 패키지 중 상호주의(copyleft) 조항을 가진 것이 있고, "
             f"그것이 어댑터 가중치 배포에 의무를 부과하는가 "
             f"| **{F.n('pkglic', 'counts', 'copyleft')}개 발견, 가중치 배포에는 영향 없음** — 아래 |")
    L.append("")
    L.append("첫 번째 줄이 중요한 이유는 기각된 후보들에서 드러난다. "
             "리플레이 후보 중 카피레프트 조항을 가진 것들"
             "(`databricks/databricks-dolly-15k`의 ShareAlike, `GAIR/lima`의 NC+SA)은 "
             "**바로 그 이유로 기각되었다.** 채택된 `oasst2`는 Apache-2.0이며 ShareAlike가 없다. "
             "따라서 어떤 카피레프트 의무도 산출물에 도달하지 않는다. "
             "기각 사유 전체는 `docs/LICENSES.md`에 있다.")
    L.append("")
    L.append("### 상호주의 의존성 검사")
    L.append("")
    L.append(f"확정된 식별자에 `{'`, `'.join(F.get('pkglic', 'method', 'copyleft_markers')[:6])}` 등이 "
             f"포함된 패키지를 찾았다. 이름이 아니라 **확정된 식별자**를 기준으로 매칭한다.")
    L.append("")
    L.append("| 패키지 | 라이선스 | 읽은 필드 |")
    L.append("|---|---|---|")
    for n in F.get("pkglic", "copyleft_packages"):
        L.append(f"| `{n}` | {F.s('pkglic', 'packages', n, 'spdx')} "
                 f"| `{F.s('pkglic', 'packages', n, 'source_field')}` |")
    L.append("")
    L.append("**어댑터 가중치 배포에는 의무가 도달하지 않는다.** 근거는 두 가지이고, 둘 다 "
             "법률 자문이 아니라 이 저장소가 무엇을 하고 무엇을 하지 않는지에 대한 진술이다.")
    L.append("")
    L.append("- **이 패키지들을 재배포하지 않는다.** MPL-2.0의 의무는 해당 라이선스가 붙은 "
             "**파일을 수정해 배포할 때** 발생하는 파일 단위 상호주의이고, LGPL의 의무는 "
             "**라이브러리나 그 파생물을 배포할 때** 발생한다. 이 저장소가 배포하는 것은 코드·"
             "매니페스트·보고서이며 의존성 자체는 배포하지 않는다.")
    L.append("- **가중치는 이 패키지들의 코드에서 파생되지 않는다.** 어댑터 가중치는 학습 "
             "데이터에서 파생되며, 이 패키지들은 그 과정을 실행한 도구다. 컴파일러의 "
             "라이선스가 컴파일 결과물을 구속하지 않는 것과 같은 구분이다.")
    L.append("")
    L.append("**미결로 남는 것은 따로 있다.** 학습된 가중치가 **학습 데이터**의 이차적 저작물인가 — "
             "이것은 의존성이 아니라 데이터 쪽 질문이고, 다섯 데이터 출처 중 어느 문서도 답하지 "
             "않는다(`docs/LICENSES.md`). 의존성 방향이 정리되었다고 해서 그 질문이 닫히지 않는다.")
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
