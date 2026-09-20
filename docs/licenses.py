# -*- coding: utf-8 -*-
"""docs/LICENSES.md -- the license matrix, generated from the audited record.

The verdicts come from `ingest/sources.py` (imported, never retyped) and the
pins they apply to come from `ingest/sources.lock.json`. `ingest/audit_licenses.py`
already refuses any verdict that its own quoted evidence does not support; this
file publishes what survived that audit.
"""

from __future__ import annotations

from docs.common import Fmt, gen_note

# The two that must never collapse into each other. `not_addressed` is a
# finding: the document was read and says nothing. `unknown` is the absence of
# a finding: nobody established what the document says.
STATUS_KO = {
    "permitted": "허용",
    "permitted_with_attribution": "허용 (출처 표기 조건)",
    "not_addressed": "문서에 언급 없음",
    "unknown": "확인 불가",
    "prohibited": "금지",
}
FIELD_KO = {
    "redistribution_status": "재배포",
    "model_publication_status": "가중치 공개",
    "commercial_status": "상업적 이용",
}


def _status(v: str) -> str:
    if v not in STATUS_KO:
        raise KeyError(f"unmapped license status {v!r} -- add it rather than guessing")
    return STATUS_KO[v]


def _flat(s: str) -> str:
    return " ".join(str(s).split()).replace("|", "\\|")


def render(F: Fmt) -> str:
    order = F.get("license_meta", "order")
    L = ["# 라이선스 정합성", "", gen_note(), ""]

    L.append("## 결론부터")
    L.append("")
    L.append("**네 개 보안 출처와 리플레이 출처 모두 모델 가중치에 대해 아무 말도 하지 않는다.** "
             "금지한 것이 아니라 언급하지 않는다. 가중치 공개는 허가가 아니라 그 침묵 위에 서 있고, "
             "이 차이는 문서상 구분되어야 한다. 이 표에서 **문서에 언급 없음**은 "
             "\"해당 문서를 읽었고 그 항목이 없었다\"는 *확인된 사실*이며, **확인 불가**는 "
             "\"아무도 확인하지 않았다\"는 *확인의 부재*다. 둘은 서로 다른 칸으로 렌더링되고, "
             "어느 출처도 후자에 해당하지 않는다.")
    L.append("")
    L.append("재배포는 다르다. 다섯 출처 모두 출처 표기를 조건으로 재배포를 명시적으로 허용한다. "
             "다만 이 저장소는 원본 코퍼스를 재배포하지 않는다 — 매니페스트와 핀과 해시만 배포하고 "
             "내려받기는 그것으로 재구성한다(`docs/REPRODUCE.md`).")
    L.append("")
    L.append("상업적 이용은 출처마다 갈린다. CVE List와 oasst2의 라이선스 본문에는 "
             "\"commercial\"이라는 단어가 등장하지 않으므로 **허용**이 아니라 **문서에 언급 없음**으로 적는다. "
             "이 구분은 사람이 읽는 산문에만 있었고 기계가 읽는 필드에는 없었던 적이 있으며, "
             "그것이 `ingest/audit_licenses.py`가 존재하는 이유다.")
    L.append("")

    # ---------------------------------------------------------- the matrix
    L.append("## 권한 매트릭스")
    L.append("")
    L.append("| 출처 | 라이선스 | 재배포 | 가중치 공개 | 상업적 이용 | 확인일 |")
    L.append("|---|---|---|---|---|---|")
    for sid in order:
        lic = F.get("licenses", sid, "license")
        name = F.s("licenses", sid, "source_name")
        used = F.get("licenses", sid).get("used", True)
        mark = "" if used else " *(미사용)*"
        L.append(
            f"| `{sid}`{mark}<br>{name} | {_flat(F.s('licenses', sid, 'license', 'source_license'))} "
            f"| {_status(lic['redistribution_status'])} "
            f"| {_status(lic['model_publication_status'])} "
            f"| {_status(lic['commercial_status'])} "
            f"| {F.s('licenses', sid, 'license', 'checked_on')} |")
    L.append("")
    L.append("빈 칸은 없다. 확인되지 않은 항목이 있었다면 **확인 불가**로 적히고 그 자체가 결함으로 보고된다.")
    L.append("")

    # ---------------------------------------------------------- evidence
    L.append("## 근거 문장")
    L.append("")
    L.append("각 판정은 그 출처의 문서에서 직접 읽은 문장에 근거한다. "
             "`ingest/audit_licenses.py`는 권한을 주장하는 필드가 자기 근거에 없는 내용을 주장하면 "
             "비정상 종료 코드를 반환한다 — 재배포·상업적 이용은 `license_evidence`가, "
             "가중치 공개는 `weights_release_evidence`가 각각 뒷받침한다.")
    L.append("")
    for sid in order:
        name = F.s("licenses", sid, "source_name")
        url = F.get("licenses", sid, "license", "source_license_url")
        L.append(f"### `{sid}` — {name}")
        L.append("")
        L.append(f"라이선스 원문: <{url}>")
        L.append("")
        L.append(f"**재배포 · 상업적 이용의 근거** ({FIELD_KO['redistribution_status']} / "
                 f"{FIELD_KO['commercial_status']})")
        L.append("")
        L.append("> " + _flat(F.s("licenses", sid, "license", "license_evidence")))
        L.append("")
        L.append(f"**가중치 공개의 근거** ({FIELD_KO['model_publication_status']})")
        L.append("")
        L.append("> " + _flat(F.s("licenses", sid, "license", "weights_release_evidence")))
        L.append("")
        upstream = F.get("licenses", sid, "license").get("upstream_license")
        if upstream:
            L.append(f"**상위 출처의 권리 관계**: {_flat(F.s('licenses', sid, 'license', 'upstream_license'))}")
            L.append("")
        why = F.get("licenses", sid, "license").get("why_not_used")
        if why:
            L.append(f"**사용하지 않은 이유**: {_flat(F.s('licenses', sid, 'license', 'why_not_used'))}")
            L.append("")

    # ---------------------------------------------------- rejected candidates
    L.append("## 리플레이 후보 중 기각된 것들")
    L.append("")
    L.append("리플레이 세트는 **사람이 쓴 영어 응답**만 쓴다는 제약 아래 고른다. "
             "라이선스로 기각된 것과 출처(provenance)로 기각된 것을 섞지 않는다.")
    L.append("")
    L.append("| 후보 | 기각 사유 |")
    L.append("|---|---|")
    rejected = F.get("licenses", "replay_oasst2", "license", "candidates_rejected")
    for cand in sorted(rejected):
        L.append(f"| `{cand}` | {_flat(F.s('licenses', 'replay_oasst2', 'license', 'candidates_rejected', cand))} |")
    L.append("")
    L.append("**HelpSteer2는 라이선스로 기각된 것이 아니다.** `CC BY 4.0`은 이 파이프라인이 요구하는 모든 권한을 "
             "부여하며, 위 매트릭스에서 상업적 이용이 **허용**으로 적힌 유일한 출처다. 기각 사유는 응답 턴이 "
             "전부 모델 생성물이라는 점 — 사람이 쓴 턴만 쓴다는 제약과 충돌한다. "
             "라이선스가 아니라 출처가 이유였다는 사실 자체가 기록될 가치가 있다.")
    L.append("")

    # ---------------------------------------------------------- open question
    L.append("## 남아 있는 법적 미결 사항")
    L.append("")
    L.append("학습된 가중치가 학습 코퍼스의 이차적 저작물인가 — 이 질문은 다섯 출처 중 어느 문서도 답하지 않는다. "
             "이 저장소는 답을 추정하지 않고, 추정한 것처럼 보이지도 않게 한다. "
             "가중치를 공개하려면 법률 검토가 선행되어야 하며, 그 검토의 출발점은 위 **가중치 공개의 근거** 절이다.")
    L.append("")
    L.append("`contains_third_party_content`는 다섯 출처 모두에서 참이다. "
             "CVE 레코드의 CNA 제출물, ATT&CK STIX 객체가 인용하는 벤더 위협 보고서, "
             "oasst2의 자원봉사자 기여 — 상위 권리자가 존재하고, 그들의 권리는 위 "
             "**상위 출처의 권리 관계** 항목에 기록되어 있다.")
    L.append("")
    return "\n".join(L) + "\n"
