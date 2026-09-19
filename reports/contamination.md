# P3 오염 검사 보고서

> `manifests/datasets.manifest.json`에서 **자동 생성**된다. 손으로 고치지 말고 `make datasets-docs`로 다시 만들 것.

정책: **13-gram, 무관용.** 학습 세트(도메인 4과제 + 리플레이)의 어떤 항목과도 13-gram을 공유하는 평가 항목은 제거한다. **8-gram**은 같은 세트에 진단용으로 돌려 함께 보고한다.

n-gram은 `input`과 `target_json`(내용)에서만 계산한다. 지시 템플릿은 설계상 공유되므로 포함하면 모든 항목이 걸린다.

학습 세트 고유 n-gram: 13-gram **10,500,784**, 8-gram **10,654,951**

## 평가 세트별 결과

| 평가 세트 | 검사 전 | 13-gram 제거 | 제거율 | 검사 후 | 8-gram이면 제거될 수 | 8-gram 추가분 | 8-gram 제거율 |
|---|---|---|---|---|---|---|---|
| `attack_technique/eval_post_cutoff` | 72 | **0** | 0.0% | 72 | 7 | +7 | 9.7% |
| `attack_technique/eval_pre_cutoff` | 44 | **0** | 0.0% | 44 | 10 | +10 | 22.7% |
| `cve_to_cwe/eval_post_cutoff` | 2,815 | **0** | 0.0% | 2,815 | 1,166 | +1,166 | 41.4% |
| `cve_to_cwe/eval_pre_cutoff` | 2,020 | **0** | 0.0% | 2,020 | 1,089 | +1,089 | 53.9% |
| `cvss_vector/eval_post_cutoff` | 3,116 | **0** | 0.0% | 3,116 | 1,433 | +1,433 | 46.0% |
| `cvss_vector/eval_pre_cutoff` | 2,498 | **0** | 0.0% | 2,498 | 1,309 | +1,309 | 52.4% |
| `structured_extract/eval_post_cutoff` | 2,177 | **0** | 0.0% | 2,177 | 866 | +866 | 39.8% |
| `structured_extract/eval_pre_cutoff` | 938 | **0** | 0.0% | 938 | 502 | +502 | 53.5% |

총 13-gram 제거: **0건**. 제거 후 재검사 결과 13-gram 겹침 **0** (`--assert-zero` 통과).

## 8-gram이 추가로 잡는 것 — 이 코퍼스가 얼마나 정형화되어 있는가

8-gram에서 가장 자주 걸린 구절(공개 취약점 설명의 상투구이며 비밀이 아니다):

**`attack_technique/eval_post_cutoff`**
- (2) `to establish an interactive command and control channel`
- (1) `extensions to establish persistent access to victim systems.`
- (1) `establish an interactive command and control channel to`
- (1) `an interactive command and control channel to target`
- (1) `to hide their malicious data in order to`

**`attack_technique/eval_pre_cutoff`**
- (1) `In some cases, adversaries may be able to`
- (1) `Adversaries may establish persistence and elevate privileges by`
- (1) `enable follow-on behaviors such as Network Sniffing or`
- (1) `follow-on behaviors such as Network Sniffing or Transmitted`
- (1) `behaviors such as Network Sniffing or Transmitted Data`

**`cve_to_cwe/eval_post_cutoff`**
- (170) `In the Linux kernel, the following vulnerability has`
- (170) `the Linux kernel, the following vulnerability has been`
- (170) `Linux kernel, the following vulnerability has been resolved:`
- (129) `Improper Neutralization of Input During Web Page Generation`
- (127) `Neutralization of Input During Web Page Generation ('Cross-site`

**`cve_to_cwe/eval_pre_cutoff`**
- (36) `Auth. (admin+) Stored Cross-Site Scripting (XSS) vulnerability in`
- (16) `Improper Neutralization of Input During Web Page Generation`
- (16) `Neutralization of Input During Web Page Generation ('Cross-site`
- (16) `of Input During Web Page Generation ('Cross-site Scripting')`
- (15) `was discovered to contain a SQL injection vulnerability`

**`cvss_vector/eval_post_cutoff`**
- (354) `In the Linux kernel, the following vulnerability has`
- (354) `the Linux kernel, the following vulnerability has been`
- (354) `Linux kernel, the following vulnerability has been resolved:`
- (129) `Improper Neutralization of Input During Web Page Generation`
- (127) `Neutralization of Input During Web Page Generation ('Cross-site`

**`cvss_vector/eval_pre_cutoff`**
- (36) `Auth. (admin+) Stored Cross-Site Scripting (XSS) vulnerability in`
- (16) `Improper Neutralization of Input During Web Page Generation`
- (16) `Neutralization of Input During Web Page Generation ('Cross-site`
- (16) `of Input During Web Page Generation ('Cross-site Scripting')`
- (15) `was discovered to contain a SQL injection vulnerability`

**`structured_extract/eval_post_cutoff`**
- (124) `Improper Neutralization of Input During Web Page Generation`
- (122) `Neutralization of Input During Web Page Generation ('Cross-site`
- (122) `of Input During Web Page Generation ('Cross-site Scripting')`
- (61) `allows Exploiting Incorrectly Configured Access Control Security Levels.This`
- (60) `Exploiting Incorrectly Configured Access Control Security Levels.This issue`

**`structured_extract/eval_pre_cutoff`**
- (8) `Cross-site Scripting (XSS) - Stored in GitHub repository`
- (5) `Improper Neutralization of Input During Web Page Generation`
- (5) `Neutralization of Input During Web Page Generation ('Cross-site`
- (5) `of Input During Web Page Generation ('Cross-site Scripting')`
- (4) `Unrestricted Upload of File with Dangerous Type in`

13-gram 제거율이 높은 것 자체가 발견 사항이다: Oracle·Adobe·Android 같은 벤더의 CVE 설명은 제품명과 버전만 다른 고정 문장이라 13단어 연쇄가 그대로 학습 세트에 존재한다. 무관용 정책은 이런 항목을 평가에서 걷어내므로 **평가 세트는 정형화가 덜한 벤더 쪽으로 기운다.** P4는 이 편향을 알고 해석해야 한다.

## 교차 평가 검사

- `attack_technique`: 0 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)
- `cve_tasks_post_vs_pre_shared`: 0 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)
- `cve_to_cwe`: 0 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)
- `cvss_vector`: 0 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)
- `structured_extract`: 0 개 엔티티가 두 시간 세트에 동시 존재 (0이어야 함)
