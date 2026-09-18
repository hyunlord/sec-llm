# P2 시크릿·PII 스캔 보고서

> **이 문서에는 탐지된 값이 하나도 들어 있지 않다.** 유형·필드·출처별 개수만 적는다. 자기가 찾은 시크릿을 커밋하는 시크릿 스캐너는 '보고서가 딸린 보안 사고'다.

- 스캔한 레코드: **823,285**
- 탐지 건수: **10,213**
- 분류별: {'pii': 10191, 'secret': 22}

## 유형별

| 유형 | 탐지 건수 | 고유 값 개수 | 처리 |
|---|---|---|---|
| `credentials_in_url` | 22 | 7 | 복구 불가 마커로 치환 |
| `email` | 974 | 395 | 안정적 가명 (`USER_xxxx`) |
| `internal_hostname` | 197 | 52 | 안정적 가명 (`HOST_xxxx`) |
| `private_ip` | 9,020 | 910 | 안정적 가명 (`IP_xxxx`) |

## 출처별

| 출처 | 탐지 건수 | 탐지된 레코드 수 |
|---|---|---|
| `cve_list` | 5,146 | 3,323 |
| `nvd` | 5,026 | 3,319 |
| `attack` | 37 | 29 |
| `cwe` | 4 | 3 |

### 출처 × 유형

| 출처 | 유형 | 건수 |
|---|---|---|
| `attack` | `private_ip` | 20 |
| `attack` | `internal_hostname` | 16 |
| `attack` | `email` | 1 |
| `cve_list` | `private_ip` | 4,558 |
| `cve_list` | `email` | 486 |
| `cve_list` | `internal_hostname` | 91 |
| `cve_list` | `credentials_in_url` | 11 |
| `cwe` | `private_ip` | 4 |
| `nvd` | `private_ip` | 4,438 |
| `nvd` | `email` | 487 |
| `nvd` | `internal_hostname` | 90 |
| `nvd` | `credentials_in_url` | 11 |

## 정책 — 공개 악성 지표(IOC)는 마스킹하지 않는다

- **pii**: replaced with a stable pseudonym so co-occurrence structure survives
- **public_iocs**: NOT masked -- routable IPs, C2 domains and file hashes are the IOC content of this corpus
- **secrets**: replaced with an unrecoverable marker
- **values_recorded**: never; counts and one-way digests only

이 구분이 핵심이다. **URL에 유출된 자격증명**과 **그 레코드의 존재 이유인 IOC**는 다르다. 멀웨어 C2 도메인, 공격자 IP, 파일 해시는 ATT&CK과 CVE 참조의 본문 내용이다. 이것들을 가리면 코퍼스의 가치가 사라진다. 그래서 라우팅 가능한 공인 IP는 탐지 대상이 아니고, 사설·루프백 대역만 가명 처리한다.

가명은 코퍼스 전체에서 **안정적**이다. 같은 값은 항상 같은 가명이 되므로 동시출현 구조가 살아남는다. 반면 실제 시크릿은 가명이 아니라 복구 불가 마커로 바뀐다 — 가명은 '되돌릴 수 있다'는 잘못된 약속이기 때문이다.

