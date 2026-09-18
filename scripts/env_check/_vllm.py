"""Minimal vLLM OpenAI-server harness shared by checks 05 and 06."""

from __future__ import annotations

import functools
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

VENV_BIN = C.REPO / ".venv" / "bin"
VLLM_BIN = VENV_BIN / "vllm"

# Deliberately conservative for a 128 GiB unified-memory part shared with the
# desktop session: enough for a 7B in bf16 plus KV cache, not enough to wedge
# the machine.
BASE_ARGS = [
    "--max-model-len", "8192",
    "--gpu-memory-utilization", "0.45",
    "--max-num-seqs", "16",
    "--disable-log-requests",
    "--seed", "1234",
]


@functools.lru_cache(maxsize=1)
def supported_flags() -> frozenset:
    """Flags this vLLM build actually accepts, read from `vllm serve --help`.

    vLLM's CLI surface moves between releases -- 0.29 dropped
    --disable-log-requests -- and an unrecognised flag makes the server exit
    before it starts. Without this the check reports "no vLLM configuration
    reached ready state", which reads as a platform finding about CUDA graph
    capture on aarch64 when it is nothing of the sort. A harness bug must not be
    allowed to masquerade as failure mode (3).
    """
    try:
        p = subprocess.run([str(VLLM_BIN), "serve", "--help"],
                           capture_output=True, text=True, timeout=180)
        text = (p.stdout or "") + (p.stderr or "")
    except Exception:
        return frozenset()
    return frozenset(re.findall(r"(--[a-z0-9][a-z0-9-]*)", text))


def filter_args(args: list) -> tuple[list, list]:
    """Drop flags this build does not accept. Returns (kept, dropped)."""
    known = supported_flags()
    if not known:
        return list(args), []
    kept, dropped, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("--") and a not in known:
            dropped.append(a)
            # Drop its value too, if it takes one.
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                i += 1
            i += 1
            continue
        kept.append(a)
        i += 1
    return kept, dropped


class VLLMServer:
    def __init__(self, model, port, extra_args=(), env_extra=None, tag="default"):
        self.model = model
        self.port = port
        self.extra_args = list(extra_args)
        self.env_extra = dict(env_extra or {})
        self.tag = tag
        self.proc = None
        self.dropped_args: list = []
        self.log_path = C.LOG_DIR / f"vllm_{tag}.log"
        self.base = f"http://127.0.0.1:{port}"

    @property
    def cmd(self):
        wanted = BASE_ARGS + self.extra_args
        kept, dropped = filter_args(wanted)
        self.dropped_args = dropped
        return [str(VLLM_BIN), "serve", self.model, "--port", str(self.port)] + kept

    def start(self, timeout=1200):
        C.LOG_DIR.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update(self.env_extra)
        env.setdefault("VLLM_LOGGING_LEVEL", "INFO")
        cmd = self.cmd
        if self.dropped_args:
            print(f"[vllm:{self.tag}] dropped flags unsupported by this build: {self.dropped_args}")
        print(f"[vllm:{self.tag}] launching: {' '.join(cmd)}")
        if self.env_extra:
            print(f"[vllm:{self.tag}] env: {self.env_extra}")
        self.logfile = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            cmd,
            stdout=self.logfile,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                return False, round(time.time() - t0, 1), "process exited"
            try:
                with urllib.request.urlopen(self.base + "/health", timeout=3) as r:
                    if r.status == 200:
                        return True, round(time.time() - t0, 1), "ready"
            except Exception:
                pass
            time.sleep(3)
        return False, round(time.time() - t0, 1), "timeout waiting for /health"

    def log_tail(self, n=60):
        try:
            return "\n".join(self.log_path.read_text(errors="replace").splitlines()[-n:])
        except Exception as exc:
            return f"<no log: {exc}>"

    def complete(self, prompt, max_tokens=128, temperature=0.0, top_p=1.0, seed=1234, timeout=300):
        body = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
                "seed": seed,
                "stream": False,
            }
        ).encode()
        req = urllib.request.Request(
            self.base + "/v1/completions",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode())
        return payload["choices"][0]["text"], round(time.time() - t0, 3)

    def stop(self):
        if self.proc is None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except Exception:
            try:
                self.proc.terminate()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=90)
        except Exception:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                pass
        try:
            self.logfile.close()
        except Exception:
            pass
        self.proc = None
        # vLLM leaves the port bound for a moment after exit.
        time.sleep(8)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False
