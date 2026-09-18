# P1 수집 보고서 — 출처 수집과 계보(lineage)

> 이 문서는 `manifests/*.json`과 실행 기록으로부터 **자동 생성**된다. `make ingest-report`로 다시 만들 것.

실행 호스트: 로컬 Mac Studio M3 Ultra (DGX 아님). 이 작업지시서에는 CUDA·GPU·학습 프레임워크·모델 로드가 없다 — HTTP, git, JSON 파싱, 파일 해싱뿐이다.

## 출처별 요약

| 출처 | 핀 | 레코드 수 | 디스크 사용량 | 소요 시간 | 요청 수 | entity_id 커버리지 | 상태 |
|---|---|---|---|---|---|---|---|
| `cve_list` | `git_commit` → `9d4f632aa6e148754e1f27bdfb69f4635792f69a` (2026-09-18T04:34:36Z) | 394,958 | 3.8 GiB | 94.7 초 | — | 1.0000 | ✅ 성공 |
| `nvd` | `api_snapshot` → 스냅숏 기준시각 `2026-09-18T04:37:25Z` | 394,957 | 1.8 GiB | 49.4 초 | 198 페이지 | 1.0000 | ✅ 성공 |
| `cwe` | `versioned_release` → v4.20 (2026-04-30) | 2,476 | 1.9 MiB | 9.9 초 | — | 1.0000 | ✅ 성공 |
| `attack` | `git_tag_release` → `v19.2` @ `6cda5ad8462c` (2026-08-05T22:58:54Z) | 30,894 | 60.7 MiB | 11.0 초 | — | 0.1964 (식별가능 타입 1.0000) | ✅ 성공 |

실패한 출처는 없다.

## 출처별 상세

### `cve_list` — CVE List V5 (CVEProject/cvelistV5)

- 사용한 핀: `git_commit` → `9d4f632aa6e148754e1f27bdfb69f4635792f69a` (2026-09-18T04:34:36Z)
- 불변성: 커밋/태그/버전 주소 지정으로 불변
- 레코드 수: **394,958**
- 디스크 사용량: **3.8 GiB** (디렉터리 1개(체크아웃 전체))
- 소요 시간: **94.7 초**
- entity_id 커버리지: **1.0000**
- 레코드 다이제스트: `29ac54daf15be05a7c104faca2f4c116...`
- 컨테이너 라이선스: CVE Program Terms of Use (The MITRE Corporation)
- 내용물 라이선스: CNA submissions under the CVE Program Terms of Use submitter grant (submitters grant MITRE and all CNAs a perpetual, royalty-free, irrevocable copyright license)
- 기록 사항:
  - INTEGRITY: this source carries no per-file sha256 -- ~300k files would bloat the manifest past usefulness. Content integrity is anchored to two real digests instead: the git commit SHA (a Merkle root over the entire tree) and records_digest (SHA-256 over every record's content hash). Neither is synthesised.
  - clone strategy: partial_clone_blob_none then checkout of the pinned commit; history depth 77380 commits, so the pin is verifiable by ancestry and not only by object hash.
  - Attribution required by the CVE Program Terms of Use: reproduce MITRE's copyright designation and the license in any copy.
  - records=394958, malformed JSON skipped=0, records with no cveMetadata.cveId=0
  - cveMetadata.state counts: PUBLISHED=376600, REJECTED=18358
  - on-disk checkout size: 3.8 GiB

### `nvd` — NVD CVE API 2.0 (NIST National Vulnerability Database)

- 사용한 핀: `api_snapshot` → 스냅숏 기준시각 `2026-09-18T04:37:25Z`
- 불변성: NOT immutable upstream. NVD serves current data and retired its dated JSON feeds; reproducibility is anchored to the locally retained snapshot whose file digests are recorded in manifests/nvd.manifest.json.
- 레코드 수: **394,957**
- 디스크 사용량: **1.8 GiB** (파일 198개)
- 소요 시간: **49.4 초**
- entity_id 커버리지: **1.0000**
- 레코드 다이제스트: `5bedcab2d520c5079339a2372a91e5d3...`
- 컨테이너 라이선스: US Government work, public domain under 17 U.S.C. (NIST publication); NVD requests a source-attribution notice
- 내용물 라이선스: CVE Program Terms of Use (The MITRE Corporation) -- the CVE records embedded in every NVD response originate from the CVE Program and are NOT a US Government work; only NVD's own analysis (CVSS scoring, CPE applicability, CWE mapping) is public domain
- 기록 사항:
  - NVD has no immutable upstream snapshot: the dated JSON feeds are retired and the API serves current data. The record SET is made deterministic by a client-side cutoff on lastModified <= snapshot_instant_utc; the record CONTENT cannot be, because upstream may edit a record after the snapshot.
  - Reproducibility is therefore anchored to the retained local snapshot, whose per-page digests are listed in this manifest. A re-run from scratch on a later date will legitimately differ, and these digests make that visible rather than silent.
  - Attribution required by NVD: This product uses data from the NVD API but is not endorsed or certified by the NVD.
  - pages=198, records kept=394957, excluded by the lastModified cutoff=1, records with no cve.id=0

### `cwe` — CWE (Common Weakness Enumeration) versioned XML catalog

- 사용한 핀: `versioned_release` → v4.20 (2026-04-30)
- 불변성: Versioned URL; MITRE does not republish a released version in place.
- 레코드 수: **2,476**
- 디스크 사용량: **1.9 MiB** (파일 1개)
- 소요 시간: **9.9 초**
- entity_id 커버리지: **1.0000**
- 레코드 다이제스트: `76e4bb9a78dde5a3fbb4833522631367...`
- 컨테이너 라이선스: CWE Terms of Use (The MITRE Corporation)
- 내용물 라이선스: Community contributions under the CWE Terms of Use contributor grant (contributors grant all users a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license)
- 기록 사항:
  - Weakness hierarchy preserved: Related_Weaknesses edges, Category members, and View members are carried through structurally rather than flattened.
  - catalog declares Version=4.20 Date=2026-04-30
  - record counts by type: cwe_category=422, cwe_external_reference=1026, cwe_view=59, cwe_weakness=969

### `attack` — MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data)

- 사용한 핀: `git_tag_release` → `v19.2` @ `6cda5ad8462c` (2026-08-05T22:58:54Z)
- 불변성: Release tag pinned to a commit SHA; raw URLs are commit-addressed.
- 레코드 수: **30,894**
- 디스크 사용량: **60.7 MiB** (파일 3개)
- 소요 시간: **11.0 초**
- entity_id 커버리지: **0.1964** (식별 가능한 타입만 기준 **1.0000**)
  - 출처가 식별자를 주지 않는 타입(분모에서 제외): `stix_identity, stix_marking-definition, stix_relationship, stix_x-mitre-collection`
- 레코드 다이제스트: `317b7f7e0ae3b6ed708bd7dc8e7a181d...`
- 컨테이너 라이선스: MITRE ATT&CK License (LICENSE.txt in attack-stix-data)
- 내용물 라이선스: Same MITRE ATT&CK License; individual STIX objects carry external_references to third-party vendor threat reports, which are cited but not redistributed
- 기록 사항:
  - STIX object structure preserved; not flattened to a technique list. Relationship, mitigation, group, software, campaign and data-component objects are all retained.
  - Attribution required by the ATT&CK license: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
  - STIX object counts: relationship=24818, x-mitre-analytic=2066, attack-pattern=1166, x-mitre-detection-strategy=920, malware=888, course-of-action=335, intrusion-set=229, x-mitre-data-component=174, tool=97, campaign=68, x-mitre-data-source=61, x-mitre-tactic=41, x-mitre-asset=18, x-mitre-matrix=4, x-mitre-collection=3, identity=3, marking-definition=3
  - objects by domain: enterprise-attack=26086, ics-attack=2173, mobile-attack=2635
  - entity_id absent for 24827 of 30894 objects. STIX relationship, marking-definition, identity and collection objects carry no ATT&CK external_id by design and are excluded from the identifiable denominator; among object types that should have one, coverage is 1.0000. Missing ids are counted, never synthesised.

## 재현성

매니페스트에는 **실행 시각(wall-clock) 필드가 없다.** 모든 시각 값은 커밋된 핀에서 나오며, 레코드 해시는 lineage 봉투가 아니라 **출처 콘텐츠만** 대상으로 계산한다 (`retrieved_at`은 매 실행마다 달라지는 값이므로 봉투를 해싱하면 재현성이 깨진다).

```bash
make ingest
shasum -a 256 manifests/*.json > /tmp/m1.txt
make ingest
shasum -a 256 manifests/*.json > /tmp/m2.txt
diff /tmp/m1.txt /tmp/m2.txt
```

`make ingest-verify`가 위 과정을 수행하고 차이가 있으면 실패한다.

### NVD의 예외 — 정직하게 적는다

NVD는 이 작업지시서의 네 출처 중 **유일하게 상류에 불변 참조가 없다.** 날짜별 JSON 피드는 폐지되었고 API는 항상 현재 데이터를 제공한다. 그래서:

- **레코드 집합**은 `lastModified <= 스냅숏 기준시각` 클라이언트 측 컷오프로 결정적이게 만들 수 있다.
- **레코드 내용**은 그럴 수 없다. 상류가 스냅숏 이후에 레코드를 수정하면 내용이 달라진다.
- 따라서 재현성의 기준점은 **로컬에 보존된 스냅숏**이며, 그 페이지별 다이제스트가 `manifests/nvd.manifest.json`에 들어 있다. 나중에 처음부터 다시 받으면 내용이 달라질 수 있고, 이 다이제스트가 그것을 **침묵이 아니라 탐지 가능한 차이**로 만든다.

## 원시 코퍼스는 git에 들어가지 않는다

- git이 추적하는 파일: **44개, 합계 337.5 KiB**
- 원시 데이터(`data/`)는 `.gitignore`로 제외된다. 커밋되는 것은 매니페스트, 핀, 보고서뿐이다.

```bash
git ls-files | xargs du -ch 2>/dev/null | tail -1
```

## 이 작업지시서가 하지 않은 것

- 중복 제거, 정규화, 시크릿 스캐닝을 하지 않았다. 다음 작업지시서(P2)의 몫이다.
- `transform_history`는 모든 레코드에서 **빈 리스트**다. 이후 처리 단계가 여기에 append한다.
- `scripts/env_check/`를 건드리지 않았다. P0.1 재실행은 DGX 복구 후 그대로 이어진다.

