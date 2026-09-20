# 재현

> 이 문서는 매니페스트와 실행 산출물에서 **자동 생성**된다. 손으로 고치지 말고 `make docs`로 다시 만들 것. 모든 수치의 출처는 `docs/trace.json`에 경로로 기록되어 있고 `python -m docs.trace_check --assert-all`이 이를 독립적으로 재확인한다.


**원본 코퍼스는 재배포하지 않는다.** 이 저장소가 배포하는 것은 핀과 해시와 매니페스트이고, 다운로더가 그것으로 원본을 다시 만든다. 다시 만든 결과가 같은지는 매니페스트의 다이제스트가 판정한다 — 같은 핀에 대해 매니페스트는 바이트 단위로 재현되며(`make ingest-verify`), 네트워크를 차단한 상태에서도 재현된다(`make ingest-offline`).

## 받아오는 것

| 출처 | 고정 방식 | 전송량 | 최초 취득 실측 | 요청 수 |
|---|---|---|---|---|
| **CVE List V5** `cve_list` | `git_commit` | git clone, 4.06 GiB on disk after checkout | 12.3분 | 1 |
| **NVD `CVE API 2.0`** `nvd` | `api_snapshot` | 1.81 GiB across 198 page files | 60.0분 | 198 |
| **CWE 카탈로그** `cwe` | `versioned_release` | 1.9 MiB | 0.1분 | 1 |
| **MITRE ATT&CK STIX** `attack` | `git_tag_release` | 60.7 MiB | 0.2분 | 3 |

합계 **1.2시간**(2026-09-18 실측). 이 시간의 대부분은 198 paged API requests under the public rate limit (5 req / rolling 30s, 6s sleep), across resumable foreground runs — 즉 NVD의 공개 속도 제한이며, 코드를 고쳐서 줄일 수 있는 것이 아니다.

디스크는 `data/raw/cve_list/cvelistV5` 체크아웃만으로 3.8 GiB를 쓴다. 여유 공간을 미리 확인하는 편이 낫다.

이미 받아 둔 로컬 사본이 있으면 재수집은 네트워크를 쓰지 않는다. `SEC_LLM_OFFLINE=1`을 주면 네트워크 호출 자체가 예외를 던지므로, "재현되었다"와 "네트워크를 건드리지 않고 재현되었다"를 구분해서 증명할 수 있다.

## 파생되는 것 (GPU 불필요)

```bash
make pin           # 모든 출처를 불변 참조로 해석 -> ingest/sources.lock.json
make ingest        # 수집 -> manifests/<source>.manifest.json
make process       # 정규화 · 완전일치/근사 중복 · 동일 엔티티 · 비밀·PII 스캔
make datasets      # 과제 · 시간 분할 · 리플레이 · 오염 · 길이 · 매니페스트 · 문서
make docs          # 여섯 개 문서와 SPDX SBOM
```

| 단계 | 입력 | 출력 | 증거 |
|---|---|---|---|
| `pin` | 출처 목록 | `ingest/sources.lock.json` | 커밋 SHA · 버전 URL · blob SHA |
| `ingest` | 핀 | 출처별 매니페스트 | `records_digest`, 파일별 sha256, 레코드 823,285건 |
| `process` | 매니페스트 | `process.manifest.json` | 제거율 11.1%, 삭제 0건 |
| `datasets` | 위 전체 | 과제 JSONL · `datasets.manifest.json` | 평가 파일 8개의 sha256 |
| `docs` | 매니페스트 전체 | 여섯 문서 · SBOM | `docs/trace.json` |

이 구간은 노트북에서 돈다. 결정론은 코드 안에서 보장된다 — 고정된 MinHash 시드, 고정된 순열 수, 순서가 결과에 새어 들어갈 수 있는 모든 지점에서의 정렬된 순회.

## GPU가 필요한 것

학습과 평가는 `NVIDIA GB10`에서 돌았다(`aarch64`, 드라이버 `580.126.09`). **이 구간은 노트북에서 재현되지 않는다.**

| 단계 | 명령 | 실측 시간 |
|---|---|---|
| Gate 4 — 평가 결정론 | `make eval-gate4` | 전체 평가를 두 번 완주 |
| 베이스 평가 | `make eval-run RUN_ID=baseline` | 2.7시간 |
| Cond-1 학습 | `make train COND=cond1` | 5.7시간 |
| Cond-2 학습 | `make train COND=cond2` | 5.7시간 |
| Cond-1 평가 | `make eval-run RUN_ID=cond1 ARGS='--model checkpoints/cond1/merged'` | 1.9시간 |
| Cond-2 평가 | `make eval-run RUN_ID=cond2 ARGS='--model checkpoints/cond2/merged'` | 1.8시간 |
| 채점 · 비교 | `make eval-score` · `make eval-report` | 분 단위 |

한 번의 완주는 GPU 시간 약 17.7시간이다(Gate 4의 반복 완주는 제외).

**필수 설정은 셸에 맡기지 않는다.** `VLLM_BATCH_INVARIANT=1`, `VLLM_USE_FLASHINFER_SAMPLER=0`, `PIP_ONLY_BINARY=:all:`은 Makefile이 걸고, `eval/common.py`는 실행 매니페스트에 이 값들이 없으면 **채점을 거부한다.** `make docs`도 같은 검사를 통과하지 못한 실행에서는 문서를 만들지 않는다.

**모든 하위 프로세스는 측정된 메모리 상한 아래에서 돈다** — `systemd-run --user --scope`, `MemoryMax=80G`, `MemorySwapMax=0`. 통합 메모리에서 이 상한은 호스트 RAM만 묶는다. CUDA 쪽은 `gpu_memory_utilization=0.45`이 따로 묶으며, 둘 다 기록된다.

## 재현되지 않는 것

- **비트 단위 재학습.** 시드, 데이터 순서 해시, 패킹 시드는 모두 기록되어 있지만 재학습을 실제로 다시 돌려 비교하지는 않았다. 기록된 그대로 옮기면 — `seed, data order hash and packing seed are recorded; bit-identical re-training was NOT re-run and is therefore untested`
- **다른 기계에서의 결정론.** Gate 0와 Gate 4는 `NVIDIA GB10` 한 대에 대한 측정이다. 다른 GPU, 다른 vLLM 버전, 다른 커널에서 같은 보장이 성립한다는 주장은 하지 않는다.
- **원본 코퍼스의 바이트 동일성.** CVE List는 계속 갱신되는 저장소다. 핀된 커밋을 체크아웃하면 같은 트리가 나오지만, 그 커밋이 언젠가 사라지면 매니페스트의 다이제스트만 남는다. 다이제스트는 재현을 검증하지, 재현을 대신하지 않는다.

## 검증 명령

```bash
make ingest-verify              # 매니페스트가 같은 핀에 대해 바이트 동일한가
make ingest-offline             # 네트워크를 막고도 재현되는가
python -m ingest.audit_licenses # 모든 권한 주장이 자기 근거를 갖는가
python -m ingest.verify_digests # 로컬 파일이 매니페스트의 해시와 맞는가
python -m train.verify_subset   # Cond-2 도메인이 Cond-1의 부분집합인가
make docs && python -m docs.trace_check --assert-all
```

마지막 줄이 이 문서 묶음의 자기 검사다. 생성된 문서에서 숫자 리터럴을 다시 뽑아, 각각이 매니페스트의 어느 경로에서 왔는지 재확인한다. 출처를 찾을 수 없는 숫자가 하나라도 있으면 빌드가 실패한다.

