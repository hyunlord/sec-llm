"""Shared helpers for the P0 environment verification checks.

Every check script exposes CHECK_ID, CHECK_NAME and run() -> dict, then calls
main(). The result is written to env/checks/<id>_<slug>.json so that
run_all.py can merge them into env/gate0.json without re-executing anything.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENV_DIR = REPO / "env"
CHECK_DIR = ENV_DIR / "checks"
LOG_DIR = REPO / "logs"

# Model under test for the whole gate. Pinned deliberately: every check that
# touches a model must touch the same one so results are comparable.
MODEL_ID = os.environ.get("GATE0_MODEL", "Qwen/Qwen2.5-7B-Instruct")

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"


def sh(cmd, timeout=120, check=False):
    """Run a shell command, returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and p.returncode != 0:
            raise RuntimeError(f"{cmd} -> rc={p.returncode}\n{p.stderr}")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def gpu_mem_gb():
    """Free / total GPU-visible memory in GiB, or None if torch is unusable."""
    try:
        import torch

        if not torch.cuda.is_available():
            return None
        free, total = torch.cuda.mem_get_info()
        return {"free_gib": round(free / 2**30, 2), "total_gib": round(total / 2**30, 2)}
    except Exception:
        return None


def host_meminfo_gb():
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            if k in ("MemTotal", "MemAvailable", "MemFree"):
                info[k] = round(int(v.split()[0]) / 1024 / 1024, 2)
    except Exception:
        pass
    return info


def disk_free_gb(path):
    try:
        u = shutil.disk_usage(path)
        return {
            "path": str(path),
            "total_gib": round(u.total / 2**30, 2),
            "used_gib": round(u.used / 2**30, 2),
            "free_gib": round(u.free / 2**30, 2),
        }
    except Exception as exc:
        return {"path": str(path), "error": str(exc)}


def corruption_metrics(text: str):
    """Two cheap heuristics for detecting garbled decoder output.

    ratio_bad   -- share of U+FFFD replacement chars and C0/C1 control chars
    max_repeat  -- longest immediately-repeated n-gram run (word level), i.e.
                   the length of the longest block that repeats back to back.
    """
    if not text:
        return {"length": 0, "ratio_bad": 1.0, "max_repeat_ngram": 0, "repeat_unit": ""}

    bad = 0
    for ch in text:
        if ch == "�":
            bad += 1
        elif ord(ch) < 32 and ch not in "\n\r\t":
            bad += 1
        elif 0x7F <= ord(ch) <= 0x9F:
            bad += 1
    ratio_bad = bad / len(text)

    words = text.split()
    best_n, best_unit = 0, ""
    # An immediately-repeated n-gram: words[i:i+n] == words[i+n:i+2n]
    for n in range(1, min(40, len(words) // 2) + 1):
        for i in range(0, len(words) - 2 * n + 1):
            if words[i : i + n] == words[i + n : i + 2 * n]:
                reps = 2
                j = i + 2 * n
                while words[j : j + n] == words[i : i + n] and words[j : j + n]:
                    reps += 1
                    j += n
                score = n * reps
                if score > best_n:
                    best_n, best_unit = score, " ".join(words[i : i + n])
    return {
        "length": len(text),
        "ratio_bad": round(ratio_bad, 5),
        "max_repeat_ngram": best_n,
        "repeat_unit": best_unit[:120],
    }


def looks_corrupted(text: str, metrics=None):
    m = metrics or corruption_metrics(text)
    words = len(text.split())
    if m["ratio_bad"] > 0.02:
        return True, "replacement/control character ratio above 2%"
    # A repeated block covering more than half the output is degenerate.
    if words >= 20 and m["max_repeat_ngram"] > max(8, words * 0.5):
        return True, "degenerate repetition covers more than half the output"
    if m["length"] < 5:
        return True, "output effectively empty"
    return False, ""


def write_result(check_id, name, status, data, notes=None, started=None):
    CHECK_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "check_id": check_id,
        "name": name,
        "status": status,
        "started_at": started,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "duration_sec": round(time.time() - _T0, 2),
        "notes": notes or [],
        "data": data,
    }
    out = CHECK_DIR / f"{check_id}_{name}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"\n[{check_id}] status={status} -> {out.relative_to(REPO)}")
    return payload


_T0 = time.time()


def main(module):
    global _T0
    _T0 = time.time()
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    cid, name = module.CHECK_ID, module.CHECK_NAME
    print(f"=== CHECK {cid} :: {name} ===")
    print(f"host={platform.node()} python={platform.python_version()} started={started}")
    try:
        result = module.run()
        status = result.get("status", STATUS_PASS)
        data = result.get("data", {})
        notes = result.get("notes", [])
    except Exception:
        tb = traceback.format_exc()
        print(tb, file=sys.stderr)
        status, data, notes = STATUS_FAIL, {"traceback": tb}, ["check raised an unhandled exception"]
    write_result(cid, name, status, data, notes, started)
    # A failed check is recorded, not fatal: run_all decides the gate verdict.
    return 0
