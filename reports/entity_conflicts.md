# P2 교차 출처 엔티티 충돌 보고서

> `manifests/process.manifest.json`에서 **자동 생성**된다.

## 같은 CVE가 두 출처에 있는 것은 중복이 아니다

`cve_list`와 `nvd`에 같은 CVE가 나타난다. **이것은 중복이 아니다.** 하나의 엔티티를 서술하는 두 출처이고, **둘 사이의 차이가 곧 정보다.** 합쳐버리면 이 코퍼스를 만들 이유가 사라진다.

- 전체 엔티티: **394,958**
- 2개 이상 출처에 존재: **394,957**
- 단일 출처에만 존재: **1**
- **필드 충돌이 있는 엔티티: 201,104**

## 필드별 충돌

| 충돌 종류 | 엔티티 수 | 의미 |
|---|---|---|
| `cvss_base_score_one_sided` | 209,315 | 한쪽에만 점수가 있다 |
| `cwe_ids_one_sided` | 160,826 | 한쪽 출처에만 CWE가 있다 |
| `cvss_base_score` | 30,003 | 양쪽 모두 점수가 있으나 0.05 초과로 다르다 |
| `cwe_ids` | 13,562 | 양쪽 출처가 모두 CWE를 부여했으나 **서로 다르다** |

## CVE→CWE 과제 설계에 주는 함의

- **13,562개 CVE에서 CNA가 부여한 CWE와 NVD 분석가가 부여한 CWE가 다르다.** 어느 쪽을 정답으로 삼을지는 **P3가 결정한다.** P2는 그 선택지가 존재한다는 사실을 드러낼 뿐이며, 여기서 해소하지 않는다.
- 160,826개 CVE는 한쪽 출처에만 CWE가 있다. 정답 출처를 한쪽으로 고정하면 이만큼의 학습 데이터가 사라진다.
- 이 숫자들이 과제 설계를 좌우한다: 정답 출처 선택, 다중 정답 허용 여부, 충돌 사례를 평가에서 제외할지 여부.

> Identity grouping is NOT deduplication. Records grouped here keep dedup_stage='identity' and dedup_keep=true on every member: two sources describing one entity are not redundant, and the disagreement between them is the information this stage exists to surface.

