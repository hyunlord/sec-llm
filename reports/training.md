# P5 학습 보고서 — 두 조건, 같은 토큰, 같은 스텝

> `runs/<cond>/train_manifest.json`과 `steps.jsonl`의 기록을 렌더링한다. 재생성: `python -m eval.stats --render-training`.

## 설정 (두 조건 동일, 데이터 구성만 다름)

- LoRA r=64, alpha=128, dropout 0.0, 대상 `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj`
- lr 0.0001 (선형 워밍업 8스텝 후 코사인 → 0), AdamW, 클리핑 1.0, bf16 베이스 + fp32 LoRA, bf16 autocast
- seq 4096 패킹(블록 대각 마스크 + 예제별 position id), 배치 4 × GA 4 = 스텝당 16 시퀀스, **157스텝**, gradient checkpointing, sdpa, seed 1234
- 메모리 상한: `systemd-run --user --scope -p MemoryMax=80G -p MemorySwapMax=0` (호스트 RSS만 덮음, A2 측정)

## 결과

| 조건 | 상태 | 예제 | 패킹 시퀀스 | 사용 / 잔여 | 본 예제 비율 | 토큰(사용) | 지도 토큰 | 스텝 | 평균 s/step | 벽시계 | 첫 loss → 끝 loss |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `cond1` | completed | 60,000 | 2,996 | 2,512 / 484 | **84.0%** | 9,911,278 | 2,605,996 | 157 | 129.01 | **5.68 h** | 0.85704 → 0.112 |
| `cond2` | completed | 56,956 | 2,977 | 2,512 / 465 | **84.9%** | 9,904,255 | 3,572,661 | 157 | 129.52 | **5.71 h** | 1.36084 → 0.46353 |

### 워밍업 검사 — Gate 0의 129.5 s/step 예측 대비

| 조건 | 측정 스텝 | 평균 s/step | 예측 | 비율 | 예상 총 시간 |
|---|---|---|---|---|---|
| `cond1` | 19 | 129.05 | 129.5 | **×0.997** | 5.63 h |
| `cond2` | 19 | 129.49 | 129.5 | **×1.0** | 5.65 h |

Gate 0의 수치는 합성 4096토큰 시퀀스에서 나왔고 패킹된 실제 데이터는 모양이 다르다 — 그런데도 예측이 맞았다. 중단 기준(2배 초과)에 근접하지도 않았다.

### 일정이 놓친 것 — 에폭이 아니다

P3.2 counted prompt+target tokens only (9,960,190 for Cond-1). The chat template adds a system prompt and role markers per example, so the same examples pack into more 4096-token sequences than the schedule assumed. Steps stay at 157 as specified; both conditions therefore see the same token budget and the same fraction of their data, and neither sees a full epoch. epoch_fraction is the measured value.

| 조건 | 과제별 본 예제 | 전체 |
|---|---|---|
| `cond1` | {'cve_to_cwe': 23988, 'cvss_vector': 17240, 'structured_extract': 9150} | 50,378 / 60,000 |
| `cond2` | {'cve_to_cwe': 19417, 'cvss_vector': 13896, 'replay': 7696, 'structured_extract': 7343} | 48,352 / 56,956 |

두 조건 모두 같은 토큰 예산(157 × 16 × 4096 슬롯)을 썼고 같은 비율의 데이터를 봤다. 비교는 성립한다. '1 에폭'이라는 표현은 성립하지 않으므로 쓰지 않는다.

### 패킹 격리 검사 (실행 시작 시 이 장비에서 재측정)

| 조건 | 마스크 적용 vs 단독 (max |Δlogit|) | 순진 패킹 vs 단독 | argmax 일치 |
|---|---|---|---|
| `cond1` | 1.8125 | 15.5469 | 1.0 |
| `cond2` | 1.8125 | 15.5469 | 1.0 |

### 재현성 — 기록한 것과 주장하지 않는 것

| 조건 | seed | 데이터 순서 해시 | 어댑터 sha256 | 병합 체크포인트 sha256 | 부분집합 검사 |
|---|---|---|---|---|---|
| `cond1` | 1234 | `90785b13193c8b36…` | `af03311f76dd8c5a…` | `a717d8d179d074d2…` | 파일에서 재계산, 통과 |
| `cond2` | 1234 | `ab59bed62d9631f8…` | `6d257cc9f72ded43…` | `fdc162c71839efb9…` | 파일에서 재계산, 통과 |

seed, data order hash and packing seed are recorded; bit-identical re-training was NOT re-run and is therefore untested. 두 조건의 seed는 같고 데이터 순서 해시는 다르다 — 데이터가 다르기 때문이고, 그것이 유일한 차이다.

### 손실 곡선 (기록된 스텝에서 발췌)

| 스텝 | `cond1` loss | `cond2` loss |
|---|---|---|
| 1 | 0.85704 | 1.36084 |
| 5 | 0.24105 | 0.82017 |
| 10 | 0.16955 | 0.69043 |
| 20 | 0.10644 | 0.67529 |
| 40 | 0.11968 | 0.5267 |
| 60 | 0.0866 | 0.6431 |
| 80 | 0.08456 | 0.78487 |
| 100 | 0.08619 | 0.46941 |
| 120 | 0.08391 | 0.68734 |
| 140 | 0.0587 | 0.61475 |
| 157 | 0.112 | 0.46353 |
