"""Axis 4 -- the sandbox axis: score by execution, not by string comparison.

One executable task, kept deliberately small. Its purpose is to prove the harness
can score by running code with a deterministic ground truth. It contains no
attack code and needs none: the model produces a CVSS v3.1 vector string, and a
container runs the official CVSS v3.1 base-score formula on that vector and
compares the result with the base score NVD recorded for the same CVE.

Container flags are Gate 0 check 08's, which that check confirmed work here:

    --network=none --memory=512m --pids-limit=128 --read-only
    --tmpfs /tmp --security-opt no-new-privileges:true

with a 30 s timeout and --rm so nothing survives the run.

Batching: one container per (split, decoding) group rather than per item. 4,500
container starts would cost more than the evaluation itself, and the formula for a
whole set runs in milliseconds, so the 30 s timeout stays meaningful. The number
of containers, their arguments and any timeout are recorded.

Self-test, and it is not optional. The same container also computes the score from
NVD's OWN vector for every item and compares it with NVD's recorded score. If the
formula implementation were wrong, the model's score-match rate would be wrong in
the same direction and would look like a model result. The self-test is reported
next to every model number.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

IMAGE_PIN = Path(__file__).resolve().parent / "sandbox_image.json"
IMAGE = json.loads(IMAGE_PIN.read_text())["reference"]   # pinned by digest, not by tag
TIMEOUT_SEC = 30
DOCKER_FLAGS = ["--rm", "-i", "--network=none", "--memory=512m", "--pids-limit=128",
                "--read-only", "--tmpfs", "/tmp", "--security-opt", "no-new-privileges:true"]

# The official CVSS v3.1 specification, section 7.1 (base score) and the Roundup
# function from Appendix A. Written out rather than imported so the container has
# no dependencies and nothing to install.
FORMULA = r'''
import json, sys, math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

def roundup(x):
    # CVSS v3.1 Appendix A: smallest one-decimal number >= x, computed on integers.
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0

def parse(vec):
    if not isinstance(vec, str):
        raise ValueError("not a string")
    parts = vec.strip().upper().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("prefix is not CVSS:3.1")
    m = {}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        if not k or not v:
            raise ValueError("malformed component " + p)
        m[k] = v
    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if k not in m:
            raise ValueError("missing " + k)
    return m

def base_score(vec):
    m = parse(vec)
    changed = m["S"] == "C"
    pr = (PR_C if changed else PR_U)[m["PR"]]
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else (6.42 * iss)
    expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1.0) * (impact + expl), 10.0))

items = json.loads(INPUT)
out = []
for it in items:
    row = {"id": it["id"]}
    for which in ("model", "nvd"):
        vec = it.get(which + "_vector")
        if vec is None:
            row[which] = {"ok": False, "error": "absent"}
            continue
        try:
            row[which] = {"ok": True, "score": base_score(vec)}
        except Exception as e:
            row[which] = {"ok": False, "error": type(e).__name__ + ": " + str(e)[:80]}
    out.append(row)
print(json.dumps({"results": out}, sort_keys=True))
'''


def script_for(items) -> str:
    return "INPUT = " + json.dumps(json.dumps(items, sort_keys=True)) + "\n" + FORMULA


def image_id() -> str:
    try:
        r = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}} {{.Architecture}}", IMAGE],
                           capture_output=True, text=True, timeout=60)
        return r.stdout.strip()
    except Exception:
        return ""


def run_batch(items) -> dict:
    """items: [{'id':..., 'model_vector': str|None, 'nvd_vector': str}]. One container."""
    script = script_for(items)
    cmd = ["docker", "run", *DOCKER_FLAGS, IMAGE, "python", "-"]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        return {"ok": False, "timeout": True, "seconds": round(time.time() - t0, 2),
                "n_items": len(items), "results": []}
    el = round(time.time() - t0, 2)
    if r.returncode != 0:
        return {"ok": False, "timeout": False, "seconds": el, "n_items": len(items),
                "exit_code": r.returncode, "stderr": r.stderr[-400:], "results": []}
    try:
        payload = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as e:
        return {"ok": False, "timeout": False, "seconds": el, "n_items": len(items),
                "error": f"unparseable container output: {type(e).__name__}", "results": []}
    return {"ok": True, "timeout": False, "seconds": el, "n_items": len(items),
            "results": payload["results"]}


def summarize(batches, targets) -> dict:
    """targets: {id: nvd_base_score}. Reports execution and match rates, plus the
    formula self-test against NVD's own vectors."""
    n_items = sum(b["n_items"] for b in batches)
    timeouts = [b for b in batches if b.get("timeout")]
    failed = [b for b in batches if not b["ok"]]
    exec_ok = match = absent = 0
    self_ok = self_match = 0
    per_item = {}
    for b in batches:
        for row in b["results"]:
            want = targets.get(row["id"])
            m = row.get("model", {})
            if m.get("ok"):
                exec_ok += 1
                hit = (want is not None and round(float(m["score"]), 1) == round(float(want), 1))
                match += int(hit)
                per_item[row["id"]] = {"computed": m["score"], "nvd": want, "match": hit}
            else:
                if m.get("error") == "absent":
                    absent += 1
                per_item[row["id"]] = {"computed": None, "nvd": want, "match": False,
                                       "error": m.get("error")}
            s = row.get("nvd", {})
            if s.get("ok"):
                self_ok += 1
                self_match += int(want is not None and round(float(s["score"]), 1) == round(float(want), 1))
    return {
        "containers": len(batches), "container_failures": len(failed), "timeouts": len(timeouts),
        "image": IMAGE, "image_id": image_id(), "timeout_sec": TIMEOUT_SEC,
        "docker_flags": DOCKER_FLAGS, "script_sha256": None,
        "items": n_items,
        "execution": {"n": n_items, "succeeded": exec_ok, "no_vector_produced": absent,
                      "rate": (exec_ok / n_items if n_items else 0.0)},
        "score_match": {"n": exec_ok, "k": match, "rate": (match / exec_ok if exec_ok else 0.0),
                        "denominator": "items whose vector executed"},
        "formula_self_test": {"n": self_ok, "k": self_match,
                              "rate": (self_match / self_ok if self_ok else 0.0),
                              "means": "score computed from NVD's own vector vs NVD's recorded score; "
                                       "must be 1.0 or the formula implementation is wrong"},
        "seconds": round(sum(b["seconds"] for b in batches), 2),
        "per_item": per_item,
    }
