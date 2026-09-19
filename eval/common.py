"""Shared plumbing for the P4 harness: settings enforcement, hashing, paths.

Two rules from earlier phases are load-bearing here.

Rule 1 (docs/engineering-rules.md): the stage that acts owns the record. The
runner generates and writes outputs.jsonl plus the run manifest; the scorers read
those files and never regenerate. A score is therefore always traceable to the
exact bytes that produced it.

Gate 0 (docs/determinism.md): greedy decoding on this machine is not
byte-reproducible without VLLM_BATCH_INVARIANT=1 -- 15 sequential samples
produced 2 distinct outputs -- and FlashInfer's sampler JIT-compiles at startup,
so VLLM_USE_FLASHINFER_SAMPLER=0 is required. Those settings are not advisory
here: a run whose manifest lacks them is refused by the scorers.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("SEC_LLM_DATA_DIR") or (REPO / "data"))
OUT = DATA / "out"
RUNS = Path(os.environ.get("SEC_LLM_RUNS_DIR") or (REPO / "runs"))
REPORTS = REPO / "reports"
MANIFESTS = REPO / "manifests"
SCHEMAS = REPO / "datasets" / "schemas"

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
EVAL_SPLITS = ("eval_post_cutoff", "eval_pre_cutoff")
DECODINGS = ("free", "constrained")
GENERAL = ("mmlu", "hellaswag")

# Required at run time. Values, not just presence: the wrong value is worse than
# a missing one because it looks configured.
REQUIRED_ENV = {
    "VLLM_BATCH_INVARIANT": "1",
    "VLLM_USE_FLASHINFER_SAMPLER": "0",
    "PIP_ONLY_BINARY": ":all:",
}
# Required sampling settings, recorded per run and checked before scoring.
REQUIRED_SAMPLING = {"temperature": 0.0, "top_p": 1.0}
SEED = 1234

# vLLM engine settings proven on this machine by Gate 0 check 05 (startup 111 s,
# no corruption) and check 06 (byte-identical under batch invariance). Reused
# verbatim rather than retuned, so this harness inherits measured behaviour.
VLLM_ENGINE = {
    "max_model_len": 8192,
    "gpu_memory_utilization": 0.45,
    "max_num_seqs": 16,
    "seed": SEED,
}
# Host memory ceiling for the run, the mechanism rule 2 requires. Gate 0 measured
# that on GB10 unified memory this bounds host RAM only; CUDA allocations are
# bounded by gpu_memory_utilization instead. Both are recorded.
MEMORY_CEILING = {"mechanism": "systemd-run --user --scope", "memory_max": "80G", "memory_swap_max": "0"}

# Model pin. The tokenizer commit in ingest/sources.lock.json is the same
# checkpoint commit, so the model is pinned by the same record as the data.
MODEL_REPO = "Qwen/Qwen2.5-7B-Instruct"


class HarnessError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def stable_int(s: str, mod: int) -> int:
    return int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:16], 16) % mod


def iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: Path, rows) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    h, n = hashlib.sha256(), 0
    with open(tmp, "wb") as fh:
        for r in rows:
            b = (json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            fh.write(b); h.update(b); n += 1
    tmp.replace(path)
    return n, h.hexdigest()


def write_json(path: Path, obj) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    b = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    path.write_bytes(b)
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------- settings gate
def enforce_env() -> dict:
    """Refuse to start unless the required environment is exactly right."""
    got = {k: os.environ.get(k) for k in REQUIRED_ENV}
    wrong = {k: (v, REQUIRED_ENV[k]) for k, v in got.items() if v != REQUIRED_ENV[k]}
    if wrong:
        raise HarnessError(
            "required runtime settings missing or wrong (got, want): "
            + json.dumps(wrong)
            + ". Gate 0 measured that greedy decoding is not byte-reproducible without "
              "VLLM_BATCH_INVARIANT=1 and that the FlashInfer sampler JIT-compiles at startup. "
              "Use `make eval-*`, which sets them."
        )
    return dict(got)


def check_manifest_settings(manifest: dict) -> None:
    """A run manifest lacking any required setting is invalid and is not scored."""
    missing = []
    env = manifest.get("env") or {}
    for k, v in REQUIRED_ENV.items():
        if env.get(k) != v:
            missing.append(f"env.{k}={env.get(k)!r} (want {v!r})")
    s = manifest.get("sampling") or {}
    for k, v in REQUIRED_SAMPLING.items():
        if s.get(k) != v:
            missing.append(f"sampling.{k}={s.get(k)!r} (want {v!r})")
    if s.get("seed") is None:
        missing.append("sampling.seed is not recorded")
    for k in ("vllm_version", "torch_version", "model_checkpoint_sha256", "dataset_manifest_sha256",
              "tokenizer_sha256", "gpu_name", "driver_version"):
        if not manifest.get(k):
            missing.append(f"{k} is not recorded")
    if missing:
        raise HarnessError("run manifest is invalid, refusing to score: " + "; ".join(missing))


# ------------------------------------------------------- dataset verification
def verify_dataset(required_files) -> dict:
    """Verify the dataset manifest against what is on disk, before anything else.

    A score computed against a dataset that has drifted is worse than no score,
    so this aborts rather than warns.
    """
    mpath = MANIFESTS / "datasets.manifest.json"
    manifest = json.loads(mpath.read_text())
    verified, missing, mismatched = {}, [], []
    for key in required_files:
        rec = manifest["files"].get(key)
        p = OUT / key
        if rec is None or not p.exists():
            missing.append(key); continue
        got = sha256_file(p)
        if got != rec["sha256"]:
            mismatched.append({"file": key, "on_disk": got, "in_manifest": rec["sha256"]})
        else:
            verified[key] = {"sha256": got, "count": rec["count"]}
    if missing or mismatched:
        raise HarnessError(f"dataset verification failed. missing={missing} mismatched={mismatched}")
    return {
        "dataset_manifest_sha256": sha256_file(mpath),
        "dataset_manifest_phase": manifest.get("phase"),
        "files_verified": verified,
        "near_threshold": manifest["contamination"]["index"]["near_threshold"],
        "near_threshold_source": manifest["contamination"]["index"]["near_threshold_source"],
        "coverage_applied_as_filter": manifest["decisions"]["coverage_stratification"]["applied_as_filter"],
        "scored": manifest["scored"],
        "not_scored_reason": manifest["not_scored_reason"],
    }


def eval_file_keys(tasks=TASKS, splits=EVAL_SPLITS):
    return [f"{t}/{sp}.jsonl" for t in tasks for sp in splits]


# ----------------------------------------------------------------- model pin
def pinned_model_commit() -> str:
    lock = json.loads((REPO / "ingest" / "sources.lock.json").read_text())["sources"]
    return lock["tokenizer_qwen25"]["commit_sha"]


def model_snapshot(commit: str | None = None) -> Path:
    commit = commit or pinned_model_commit()
    hub = Path(os.environ.get("HF_HOME") or (Path.home() / ".cache" / "huggingface")) / "hub"
    p = hub / f"models--{MODEL_REPO.replace('/', '--')}" / "snapshots" / commit
    if not p.exists():
        raise HarnessError(f"pinned checkpoint not on disk: {p}")
    return p


def checkpoint_digest(snapshot: Path) -> dict:
    """Digest of digests over the checkpoint's own files, so the manifest records
    the weights that produced the outputs, not just a directory name."""
    files = sorted(p for p in snapshot.rglob("*") if p.is_file())
    per = {}
    for p in files:
        per[str(p.relative_to(snapshot))] = sha256_file(p.resolve())
    roll = sha256_text("\n".join(f"{k} {v}" for k, v in sorted(per.items())))
    tok = [v for k, v in per.items() if "token" in k or k == "vocab.json" or k.endswith("merges.txt")]
    return {
        "model_checkpoint_sha256": roll,
        "n_files": len(per),
        "weight_files": sorted(k for k in per if k.endswith(".safetensors")),
        "tokenizer_sha256": sha256_text("\n".join(sorted(tok))),
        "per_file_sha256": per,
    }


def host_facts() -> dict:
    def run(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout.strip()
        except Exception:
            return ""
    gpu = run("nvidia-smi --query-gpu=name,driver_version --format=csv,noheader").split(",")
    import platform
    return {
        "gpu_name": (gpu[0].strip() if gpu and gpu[0] else ""),
        "driver_version": (gpu[1].strip() if len(gpu) > 1 else ""),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
    }


def versions() -> dict:
    import importlib.metadata as md
    def v(name):
        try:
            return md.version(name)
        except Exception:
            return ""
    return {"vllm_version": v("vllm"), "torch_version": v("torch"),
            "transformers_version": v("transformers"), "jsonschema_version": v("jsonschema"),
            "xgrammar_version": v("xgrammar"), "numpy_version": v("numpy")}


def run_dir(run_id: str) -> Path:
    d = RUNS / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_run(run_id: str) -> tuple[dict, Path]:
    d = RUNS / run_id
    mp = d / "manifest.json"
    if not mp.exists():
        raise HarnessError(f"no run manifest at {mp}")
    manifest = json.loads(mp.read_text())
    check_manifest_settings(manifest)
    return manifest, d


def harness_code_sha() -> dict:
    """Digest of the harness source, recorded in every run manifest so 'the
    harness was unchanged between conditions' is a checkable claim rather than a
    sentence. Two digests: the whole of eval/, and the SCORING subset -- the files
    that turn outputs into numbers -- which is the one that must be identical
    across every run being compared."""
    root = REPO / "eval"
    files = sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    per = {str(p.relative_to(REPO)): sha256_file(p) for p in files}
    scoring = {k: v for k, v in per.items()
               if k.startswith("eval/scorers/") or k in ("eval/sandbox.py", "eval/strata.py")}
    return {"harness_code_sha256": sha256_text("\n".join(f"{k} {v}" for k, v in per.items())),
            "scoring_code_sha256": sha256_text("\n".join(f"{k} {v}" for k, v in scoring.items())),
            "files": per}
