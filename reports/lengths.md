# P3 토큰 길이 분포와 패킹 수율

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

토크나이저: Qwen2.5-7B-Instruct, 커밋 `a09a35458c70` (DGX 게이트와 동일). 시퀀스 길이 4096.

## 과제·분할별 분포 (토큰)

| 과제/분할 | 예제 | 입력 p50/p90/p99/max | 정답 p50/p90/p99/max | >512 | >1024 | >2048 | >4096 |
|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 72 | 211/383/457/585 | 16/16/16/16 | 1.39% | 0.00% | 0.00% | 0.00% |
| `attack_technique/eval_pre_cutoff` | 44 | 245/367/459/459 | 16/16/16/16 | 0.00% | 0.00% | 0.00% | 0.00% |
| `attack_technique/train` | 738 | 216/382/628/952 | 16/16/16/16 | 2.98% | 0.00% | 0.00% | 0.00% |
| `cve_to_cwe/eval_post_cutoff` | 2,815 | 90/192/534/2371 | 13/13/14/14 | 1.31% | 0.28% | 0.04% | 0.00% |
| `cve_to_cwe/eval_pre_cutoff` | 2,020 | 68/120/256/634 | 13/13/14/14 | 0.05% | 0.00% | 0.00% | 0.00% |
| `cve_to_cwe/train` | 170,748 | 84/145/421/2771 | 13/13/13/14 | 0.77% | 0.36% | 0.08% | 0.00% |
| `cvss_vector/eval_post_cutoff` | 3,116 | 112/236/676/2390 | 102/103/106/107 | 3.15% | 0.67% | 0.16% | 0.00% |
| `cvss_vector/eval_pre_cutoff` | 2,498 | 86/142/274/975 | 102/103/106/107 | 0.28% | 0.04% | 0.00% | 0.00% |
| `cvss_vector/train` | 123,402 | 103/182/662/2890 | 102/103/106/107 | 1.89% | 0.70% | 0.19% | 0.00% |
| `replay/train` | 37,100 | 17/54/208/2213 | 137/415/776/11625 | 7.00% | 0.59% | 0.05% | 0.01% |
| `structured_extract/eval_post_cutoff` | 2,177 | 103/195/335/770 | 34/54/104/398 | 0.32% | 0.00% | 0.00% | 0.00% |
| `structured_extract/eval_pre_cutoff` | 938 | 81/165/332/951 | 34/57/212/576 | 0.43% | 0.11% | 0.00% | 0.00% |
| `structured_extract/train` | 65,429 | 100/185/367/2495 | 35/70/323/1219 | 1.56% | 0.09% | 0.03% | 0.00% |

## 패킹 수율 @ 4096 (순차 greedy)

| 과제/분할 | 4096 시퀀스 수 | 시퀀스당 예제 | 패딩 비율 | 4096 초과(절단) |
|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 5 | **14.4** | 14.0% | 0 |
| `attack_technique/eval_pre_cutoff` | 3 | **14.667** | 6.7% | 0 |
| `attack_technique/train` | 48 | **15.375** | 4.9% | 0 |
| `cve_to_cwe/eval_post_cutoff` | 93 | **30.269** | 2.9% | 0 |
| `cve_to_cwe/eval_pre_cutoff` | 47 | **42.979** | 2.3% | 0 |
| `cve_to_cwe/train` | 5,005 | **34.115** | 3.0% | 0 |
| `cvss_vector/eval_post_cutoff` | 200 | **15.58** | 4.3% | 0 |
| `cvss_vector/eval_pre_cutoff` | 126 | **19.825** | 3.1% | 0 |
| `cvss_vector/train` | 7,348 | **16.794** | 4.3% | 0 |
| `replay/train` | 2,077 | **17.862** | 4.7% | 3 |
| `structured_extract/eval_post_cutoff` | 88 | **24.739** | 2.9% | 0 |
| `structured_extract/eval_pre_cutoff` | 34 | **27.588** | 4.9% | 0 |
| `structured_extract/train` | 2,743 | **23.853** | 3.0% | 0 |

## P0 측정치를 P5 일정으로 — 이 보고서의 존재 이유

- P0 체크 07: **129.5145초/옵티마이저 스텝**, 스텝당 65,536 토큰 (16 × 4096, 합성 전장 시퀀스).
- 실제 학습 토큰(4과제 + 리플레이): **67,893,482**
- 패킹 후 4096 시퀀스: **17,221** → 스텝당 16 시퀀스 → **에폭당 1076.3 스텝**
- **에폭당 예상 벽시계: 38.72 시간** (P0 스텝 비용 기준, 패딩 포함)

> Derived from the P0 measurement (129.5 s per 65,536-token step) and the packing yield above. Padding fraction is already inside the sequence count, so this is wall time for the real corpus, not for 4096-token synthetic rows.

작업지시서 P0의 외삽(10k/30k/60k 예제 → 22.5/67.5/134.9시간)은 예제 = 4096 토큰을 가정했다. 위 표의 시퀀스당 예제 수가 그 가정과 실제의 비율이다.

