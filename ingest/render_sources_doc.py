# -*- coding: utf-8 -*-
"""Render docs/data-sources.md (Korean) from ingest/sources.py.

Generated rather than hand-written for the same reason docs/determinism.md is:
the values in this table are the same values that go into every record's
lineage, and a hand-maintained copy diverges from them the first time either
changes. If the table and the data disagree, the table is the one people read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.sources import SOURCE_ORDER, SOURCES  # noqa: E402

LOCK = REPO / "ingest" / "sources.lock.json"
OUT = REPO / "docs" / "data-sources.md"

STATUS_KO = {
    "permitted": "가능",
    "permitted_with_attribution": "가능 (출처 표기 조건)",
    "prohibited": "불가",
    "unknown": "확인 불가",
}


def _ko(status: str) -> str:
    return STATUS_KO.get(status, status)


def render() -> Path:
    pins = {}
    if LOCK.exists():
        pins = json.loads(LOCK.read_text()).get("sources", {})

    L = []
    L.append("# 데이터 출처와 라이선스 매트릭스\n")
    L.append("> 이 문서는 `ingest/sources.py`로부터 **자동 생성**된다. 손으로 고치지 말고 "
             "`make sources-doc`으로 다시 만들 것. 표의 값은 모든 레코드의 lineage에 들어가는 "
             "값과 동일한 출처에서 나온다.\n")
    L.append("모든 라이선스 값은 **각 출처의 공식 문서를 직접 읽고** 기록했다. 유사 프로젝트에서 "
             "추정하지 않았고, 읽지 않은 라이선스를 적지 않았다. 출처 문서가 답하지 않는 항목은 "
             "**확인 불가**로 적고 무엇을 확인했는지 함께 남긴다.\n")

    # --- main matrix ------------------------------------------------------
    L.append("## 매트릭스\n")
    L.append("| 출처 | 원본 재배포 가능 여부 | 이 데이터로 학습한 가중치 공개 가능 여부 | 상업적 이용 가능 여부 | 제3자 콘텐츠 포함 | 출처 URL | 라이선스 문서 | 확인 일자 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for sid in SOURCE_ORDER:
        s = SOURCES[sid]
        lic = s["license"]
        L.append(
            f"| **{s['source_name']}** "
            f"| {_ko(lic['redistribution_status'])} "
            f"| {_ko(lic['weights_release'])} "
            f"| {_ko(lic['commercial_status'])} "
            f"| {'예' if lic['contains_third_party_content'] else '아니오'} "
            f"| [{s['source_url']}]({s['source_url']}) "
            f"| [{lic['source_license']}]({lic['source_license_url']}) "
            f"| {lic['checked_on']} |"
        )
    L.append("")
    L.append("> 빈 칸은 없다. **확인 불가**는 유효한 값이고 공란은 아니다.\n")

    # --- container vs content --------------------------------------------
    L.append("## 컨테이너 라이선스와 콘텐츠 라이선스는 다르다\n")
    L.append("이 프로젝트가 `source_license`(컨테이너)와 `upstream_license`(내용물)를 "
             "**별도 필드로** 유지하는 이유다. 하나의 `license` 칼럼으로 합치면 아래 구분이 사라진다.\n")
    L.append("| 출처 | 컨테이너 라이선스 (`source_license`) | 내용물 라이선스 (`upstream_license`) |")
    L.append("|---|---|---|")
    for sid in SOURCE_ORDER:
        lic = SOURCES[sid]["license"]
        L.append(f"| `{sid}` | {lic['source_license']} | {lic['upstream_license']} |")
    L.append("")
    L.append("가장 분명한 사례가 **NVD**다. NVD 자체 분석(CVSS 점수, CPE 적용범위, CWE 매핑)은 "
             "미국 정부 저작물로 퍼블릭 도메인이지만, **같은 JSON 객체 안에 들어 있는 CVE 설명은** "
             "CVE 프로그램에서 온 것이고 MITRE의 이용 약관을 따른다. 두 개를 하나로 합쳐 적으면 "
             "이 차이가 지워진다.\n")

    # --- evidence ---------------------------------------------------------
    L.append("## 근거 (출처 문서 원문 인용)\n")
    for sid in SOURCE_ORDER:
        s = SOURCES[sid]
        lic = s["license"]
        L.append(f"### {s['source_name']}\n")
        L.append(f"- 라이선스 문서: <{lic['source_license_url']}> (확인 일자 {lic['checked_on']})")
        L.append(f"- 재배포: **{_ko(lic['redistribution_status'])}** / 상업적 이용: **{_ko(lic['commercial_status'])}**")
        L.append("- 근거 인용:")
        L.append(f"  > {lic['license_evidence']}")
        L.append("")
        L.append(f"- **학습 가중치 공개: {_ko(lic['weights_release'])}**")
        L.append(f"  - 확인한 내용: {lic['weights_release_evidence']}")
        if lic.get("attribution_notice_required"):
            L.append(f"- **필수 표기 문구**: `{lic['attribution_notice_required']}`")
        L.append(f"- PII 정책: {lic['pii_policy']}")
        pin = pins.get(sid)
        if pin:
            head = pin.get("commit_sha") or pin.get("version") or pin.get("tag") or pin.get("snapshot_instant_utc")
            L.append(f"- 현재 핀: `{pin.get('pin_type')}` → `{head}`")
        L.append("")

    # --- the weights question --------------------------------------------
    L.append("## 네 출처 모두 답하지 않는 질문 — 학습 가중치\n")
    L.append("**네 출처 중 어느 것도 머신러닝 학습이나 모델 가중치를 언급하지 않는다.** "
             "따라서 표의 해당 칸은 전부 **확인 불가**다.\n")
    L.append("확인한 내용은 다음과 같다:\n")
    L.append("- CWE와 ATT&CK는 \"research, development, and commercial purposes\"를 **명시적으로** 허용한다.")
    L.append("- CVE 이용 약관은 사용 목적 제한 없는 저작권 라이선스를 부여하지만 \"commercial\"이라는 "
             "단어 자체는 등장하지 않는다.")
    L.append("- 네 출처 모두 \"prepare derivative works\"(파생물 작성) 권리를 부여한다.")
    L.append("- 그러나 **학습된 가중치가 학습 코퍼스의 파생물에 해당하는지**는 이 문서들이 답하지 않는다. "
             "이것은 라이선스 해석이 아니라 법률 판단의 영역이다.\n")
    L.append("> **법무 검토가 필요하다.** 이 표의 '확인 불가'를 '가능'으로 바꾸려면 근거가 될 문서나 "
             "법률 자문이 있어야 하며, 유사 프로젝트가 그렇게 하고 있다는 사실은 근거가 아니다.\n")

    # --- attribution obligations -----------------------------------------
    L.append("## 배포 시 지켜야 할 표기 의무\n")
    L.append("재배포와 상업적 이용이 모두 **출처 표기 조건부**이므로, 산출물을 공개할 때 아래를 포함해야 한다.\n")
    L.append("- **NVD**: `This product uses data from the NVD API but is not endorsed or certified by the NVD.`")
    L.append("- **ATT&CK**: `© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.`")
    L.append("- **CWE / CVE**: MITRE의 저작권 표시와 해당 이용 약관 전문을 사본에 함께 포함.\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")
    return OUT


if __name__ == "__main__":
    print(render())
