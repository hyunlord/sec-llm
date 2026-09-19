# P3 토큰 길이 분포와 패킹 수율

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

토크나이저: Qwen2.5-7B-Instruct, 커밋 `a09a35458c70` (DGX 게이트와 동일). 시퀀스 길이 4096.

## 과제·분할별 분포 (토큰)

| 과제/분할 | 예제 | 입력 p50/p90/p99/max | 정답 p50/p90/p99/max | >512 | >1024 | >2048 | >4096 |
|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 79 | 206/383/499/585 | 16/16/16/16 | 1.27% | 0.00% | 0.00% | 0.00% |
| `attack_technique/eval_pre_cutoff` | 67 | 227/360/481/672 | 16/16/16/16 | 1.49% | 0.00% | 0.00% | 0.00% |
| `attack_technique/train` | 738 | 216/382/628/952 | 16/16/16/16 | 2.98% | 0.00% | 0.00% | 0.00% |
| `cve_to_cwe/eval_post_cutoff` | 3,673 | 94/197/613/2437 | 13/13/14/14 | 1.63% | 0.49% | 0.11% | 0.00% |
| `cve_to_cwe/eval_pre_cutoff` | 3,384 | 77/147/309/1974 | 13/13/14/14 | 0.24% | 0.06% | 0.00% | 0.00% |
| `cve_to_cwe/train` | 170,748 | 84/145/421/2771 | 13/13/13/14 | 0.77% | 0.36% | 0.08% | 0.00% |
| `cve_to_cwe/train_subsample` | 28,491 | 84/146/443/2771 | 13/13/13/14 | 0.83% | 0.42% | 0.08% | 0.00% |
| `cvss_vector/eval_post_cutoff` | 4,333 | 118/229/929/2449 | 102/103/106/107 | 3.28% | 1.01% | 0.25% | 0.00% |
| `cvss_vector/eval_pre_cutoff` | 4,160 | 95/166/338/2002 | 102/103/106/107 | 0.58% | 0.12% | 0.02% | 0.00% |
| `cvss_vector/train` | 123,402 | 103/182/662/2890 | 102/103/106/107 | 1.89% | 0.70% | 0.19% | 0.00% |
| `cvss_vector/train_subsample` | 20,591 | 103/185/677/2872 | 102/103/106/107 | 2.02% | 0.72% | 0.18% | 0.00% |
| `replay/train` | 37,100 | 17/54/208/2213 | 137/415/776/11625 | 7.00% | 0.59% | 0.05% | 0.01% |
| `replay/train_subsample` | 11,251 | 17/54/216/2213 | 140/417/821/4704 | 7.42% | 0.60% | 0.07% | 0.01% |
| `structured_extract/eval_post_cutoff` | 3,117 | 107/193/323/770 | 34/53/106/603 | 0.26% | 0.00% | 0.00% | 0.00% |
| `structured_extract/eval_pre_cutoff` | 1,831 | 94/178/347/951 | 35/68/295/823 | 0.87% | 0.06% | 0.00% | 0.00% |
| `structured_extract/train` | 65,429 | 100/185/367/2495 | 35/70/323/1219 | 1.56% | 0.09% | 0.03% | 0.00% |
| `structured_extract/train_subsample` | 10,918 | 100/184/355/1040 | 35/69/298/905 | 1.43% | 0.04% | 0.00% | 0.00% |

## 패킹 수율 @ 4096 (순차 greedy)

| 과제/분할 | 4096 시퀀스 수 | 시퀀스당 예제 | 패딩 비율 | 4096 초과(절단) |
|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 5 | **15.8** | 5.5% | 0 |
| `attack_technique/eval_pre_cutoff` | 5 | **13.4** | 18.2% | 0 |
| `attack_technique/train` | 48 | **15.375** | 4.9% | 0 |
| `cve_to_cwe/eval_post_cutoff` | 130 | **28.254** | 3.8% | 0 |
| `cve_to_cwe/eval_pre_cutoff` | 90 | **37.6** | 2.6% | 0 |
| `cve_to_cwe/train` | 5,005 | **34.115** | 3.0% | 0 |
| `cve_to_cwe/train_subsample` | 841 | **33.878** | 3.1% | 0 |
| `cvss_vector/eval_post_cutoff` | 287 | **15.098** | 4.5% | 0 |
| `cvss_vector/eval_pre_cutoff` | 224 | **18.571** | 3.3% | 0 |
| `cvss_vector/train` | 7,348 | **16.794** | 4.3% | 0 |
| `cvss_vector/train_subsample` | 1,230 | **16.741** | 4.2% | 0 |
| `replay/train` | 2,077 | **17.862** | 4.7% | 3 |
| `replay/train_subsample` | 641 | **17.552** | 5.2% | 1 |
| `structured_extract/eval_post_cutoff` | 127 | **24.543** | 2.8% | 0 |
| `structured_extract/eval_pre_cutoff` | 73 | **25.082** | 3.2% | 0 |
| `structured_extract/train` | 2,743 | **23.853** | 3.0% | 0 |
| `structured_extract/train_subsample` | 451 | **24.208** | 2.9% | 0 |

## 사전 등록된 P5 절제 실험 — 60k 서브샘플 일정

- 표집: 60,000개 도메인 예제, 채점 과제 3개에 비례 층화 (`{'cve_to_cwe': 28491, 'cvss_vector': 20591, 'structured_extract': 10918}`), 시드 `sec-llm-p5-subsample-v1`, 파일 해시는 매니페스트에.
- Cond-1과 Cond-2는 **정확히 이 서브샘플**로 학습한다. Cond-2는 여기에 리플레이를 더한다.

| 조건 | 예제 | 토큰 | 4096 시퀀스 | 시퀀스당 예제 | 패딩 | 에폭당 스텝 | **에폭당 시간** |
|---|---|---|---|---|---|---|---|
| Cond-1: 60k domain subsample | 60,000 | 9,960,190 | 2,521 | 23.8 | 3.5% | 157.6 | **5.67 h** |
| Cond-2: 60k domain subsample + replay (20% of tokens) | 71,251 | 12,450,033 | 3,162 | 22.534 | 3.9% | 197.6 | **7.11 h** |

- Cond-2에서 리플레이가 차지하는 토큰 비율: **20.0%**
- 두 조건 합계(1 에폭씩): **12.8 h** — 전체 세트 두 조건 77.4 h 대비.

## 전체 세트 일정 (절제 실험 후 선택적 실행)

- P0 체크 07: **129.5145초/옵티마이저 스텝**, 스텝당 65,536 토큰 (16 × 4096, 합성 전장 시퀀스).
- 실제 학습 토큰(4과제 + 리플레이): **67,893,482**
- 패킹 후 4096 시퀀스: **17,221** → 스텝당 16 시퀀스 → **에폭당 1076.3 스텝**
- **에폭당 예상 벽시계: 38.72 시간** (P0 스텝 비용 기준, 패딩 포함)

> Derived from the P0 measurement (129.5 s per 65,536-token step) and the packing yield above. Padding fraction is already inside the sequence count, so this is wall time for the real corpus, not for 4096-token synthetic rows.

작업지시서 P0의 외삽(10k/30k/60k 예제 → 22.5/67.5/134.9시간)은 예제 = 4096 토큰을 가정했다. 위 표의 시퀀스당 예제 수가 그 가정과 실제의 비율이다.

