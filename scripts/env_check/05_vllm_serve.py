"""Check 05 -- can vLLM serve this model on aarch64 + CUDA 13?

Two attempts: default settings (which try CUDA graph capture) and
--enforce-eager (which does not). For each we record whether /health ever
returned 200, the startup log tail on failure, and the latency of one
128-token completion. Whichever works becomes the project default and is
written into the result so check 06 can read it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import _vllm  # noqa: E402

CHECK_ID = "05"
CHECK_NAME = "vllm_serve"

PROMPT = "Summarize what a buffer overflow is, in three sentences."
CONFIGS = [
    {"name": "default", "args": [], "port": 8131, "note": "CUDA graph capture enabled (vLLM default)"},
    {"name": "enforce_eager", "args": ["--enforce-eager"], "port": 8132, "note": "CUDA graph capture disabled"},
]


def run():
    notes = []
    data = {
        "model": C.MODEL_ID,
        "base_args": _vllm.BASE_ARGS,
        "attempts": [],
    }

    for cfg in CONFIGS:
        print(f"\n=== vLLM attempt: {cfg['name']} ({cfg['note']}) ===")
        entry = {"name": cfg["name"], "extra_args": cfg["args"], "note": cfg["note"]}
        srv = _vllm.VLLMServer(C.MODEL_ID, cfg["port"], cfg["args"], tag=cfg["name"])
        entry["command"] = " ".join(srv.cmd)
        entry["dropped_unsupported_flags"] = list(srv.dropped_args)
        try:
            ready, secs, why = srv.start()
            entry["env_applied"] = dict(srv.env_applied)
            entry["ready"] = ready
            entry["startup_seconds"] = secs
            entry["startup_result"] = why
            print(f"ready={ready} after {secs}s ({why})")
            if ready:
                text, latency = srv.complete(PROMPT, max_tokens=128)
                entry["completion_latency_sec"] = latency
                entry["completion_text"] = text
                m = C.corruption_metrics(text)
                entry["metrics"] = m
                corrupted, _ = C.looks_corrupted(text, m)
                entry["corrupted"] = corrupted
                print(f"128-token completion in {latency}s, corrupted={corrupted}")
                print("OUTPUT >>>")
                print(text)
                print("<<< END OUTPUT")
            else:
                entry["log_tail"] = srv.log_tail(80)
                print("--- startup log tail ---")
                print(entry["log_tail"])
        except Exception as exc:
            entry["ready"] = False
            entry["error"] = repr(exc)
            entry["log_tail"] = srv.log_tail(80)
            print(f"ERROR: {exc!r}")
            print(entry["log_tail"])
        finally:
            srv.stop()
        data["attempts"].append(entry)

    usable = [a for a in data["attempts"] if a.get("ready") and not a.get("corrupted")]
    if usable:
        # Prefer the default (graph capture) config if it works -- it is faster.
        chosen = usable[0]
        data["usable_configs"] = [a["name"] for a in usable]
        data["project_default"] = {
            "name": chosen["name"],
            "extra_args": chosen["extra_args"],
            "port": next(c["port"] for c in CONFIGS if c["name"] == chosen["name"]),
        }
        notes.append(
            f"vLLM project default: {chosen['name']} "
            f"(extra args: {chosen['extra_args'] or 'none'}), "
            f"startup {chosen['startup_seconds']}s, "
            f"128-token completion {chosen.get('completion_latency_sec')}s"
        )
        failed = [a for a in data["attempts"] if not a.get("ready")]
        for a in failed:
            notes.append(f"vLLM config '{a['name']}' failed to reach ready state: {a.get('startup_result') or a.get('error')}")
    else:
        data["usable_configs"] = []
        data["project_default"] = None
        notes.append("no vLLM configuration reached ready state on this machine")

    return {
        "status": C.STATUS_PASS if usable else C.STATUS_FAIL,
        "data": data,
        "notes": notes,
    }


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
