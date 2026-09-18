"""Check 01 -- host, GPU, driver, CUDA runtime, memory, disk inventory.

Everything later phases need to size themselves against: architecture, driver,
compute capability, unified memory, and -- explicitly -- free disk, because a
7B base model plus three LoRA runs has to fit somewhere.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import _probes  # noqa: E402

CHECK_ID = "01"
CHECK_NAME = "inventory"


def run():
    data = {}
    notes = []

    data["host"] = {
        "hostname": platform.node(),
        "machine": platform.machine(),
        "kernel": platform.release(),
        "system": platform.system(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
    }
    print(f"machine   : {data['host']['machine']}")
    print(f"kernel    : {data['host']['kernel']}")

    rc, out, _ = C.sh("nvidia-smi")
    data["nvidia_smi"] = out if rc == 0 else None
    print("\n--- nvidia-smi ---\n" + (out or "<unavailable>"))

    rc, out, _ = C.sh(
        "nvidia-smi --query-gpu=name,driver_version,compute_cap,memory.total,memory.used "
        "--format=csv,noheader"
    )
    data["gpu_query"] = out if rc == 0 else None
    print(f"\ngpu_query : {out}")

    rc, out, _ = C.sh("nvcc --version")
    data["nvcc"] = out if rc == 0 else None

    data["python"] = {
        "version": platform.python_version(),
        "executable": sys.executable,
        "implementation": platform.python_implementation(),
    }

    torch_info = {}
    try:
        import torch

        torch_info = {
            "version": torch.__version__,
            "cuda_runtime_linked": torch.version.cuda,
            "cudnn": torch.backends.cudnn.version(),
            "is_available": torch.cuda.is_available(),
            "arch_list": torch.cuda.get_arch_list(),
            "device_count": torch.cuda.device_count(),
        }
        if torch.cuda.is_available():
            cap = torch.cuda.get_device_capability(0)
            torch_info["device_name"] = torch.cuda.get_device_name(0)
            torch_info["compute_capability"] = f"sm_{cap[0]}{cap[1]}"
            torch_info["memory"] = C.gpu_mem_gb()
            torch_info["arch_list_contains_device_sm"] = (
                f"sm_{cap[0]}{cap[1]}" in torch_info["arch_list"]
            )
            if not torch_info["arch_list_contains_device_sm"]:
                notes.append(
                    f"torch was not compiled with a cubin for {torch_info['compute_capability']}; "
                    f"it ships {torch_info['arch_list']} and must rely on Blackwell "
                    "family-level binary compatibility (sm_120 -> sm_121). Check 02 proves "
                    "whether that actually works."
                )
    except Exception as exc:  # torch import itself can fail on an ABI mismatch
        torch_info = {"import_error": repr(exc)}
        notes.append("torch could not be imported -- check 02 cannot pass in this state")
    data["torch"] = torch_info
    print(f"\ntorch     : {torch_info.get('version')} (cuda {torch_info.get('cuda_runtime_linked')})")
    print(f"arch_list : {torch_info.get('arch_list')}")
    print(f"device    : {torch_info.get('device_name')} {torch_info.get('compute_capability')}")

    data["host_memory_gib"] = C.host_meminfo_gb()
    print(f"host mem  : {data['host_memory_gib']}")

    hf_home = os.environ.get("HF_HOME") or str(Path.home() / ".cache" / "huggingface")
    data["disk"] = {
        "repo": C.disk_free_gb(C.REPO),
        "home": C.disk_free_gb(Path.home()),
        "hf_cache": C.disk_free_gb(hf_home if Path(hf_home).exists() else Path.home()),
    }
    print(f"disk repo : {data['disk']['repo']}")
    print(f"disk hf   : {data['disk']['hf_cache']}")

    free = data["disk"]["hf_cache"].get("free_gib", 0)
    # 7B bf16 base ~15 GiB + three LoRA runs with checkpoints ~30 GiB + eval slack.
    data["disk_headroom_ok"] = free >= 100
    if not data["disk_headroom_ok"]:
        notes.append(
            f"only {free} GiB free where the HF cache lives; a 7B base plus three LoRA "
            "runs needs roughly 100 GiB of headroom"
        )

    rc, out, _ = C.sh("docker --version")
    data["docker_version"] = out if rc == 0 else None

    # --- no-build enforcement -------------------------------------------
    # A grep over the harness cannot establish that nothing compiles: pip builds
    # whenever it meets a source distribution, and no string in our code says so.
    # The rule is enforced in the environment instead, and recorded here as
    # evidence that it was active for this run rather than merely intended.
    data["no_build_enforcement"] = {
        "PIP_ONLY_BINARY": os.environ.get("PIP_ONLY_BINARY"),
        "UV_NO_BUILD": os.environ.get("UV_NO_BUILD"),
        "PIP_CONFIG_FILE": os.environ.get("PIP_CONFIG_FILE"),
        "repo_pip_conf_present": (C.REPO / "pip.conf").exists(),
        "repo_pip_conf": (C.REPO / "pip.conf").read_text() if (C.REPO / "pip.conf").exists() else None,
        "active": os.environ.get("PIP_ONLY_BINARY") == ":all:",
    }
    print(f"\nno-build enforcement: PIP_ONLY_BINARY={data['no_build_enforcement']['PIP_ONLY_BINARY']!r} "
          f"active={data['no_build_enforcement']['active']}")
    if not data["no_build_enforcement"]["active"]:
        notes.append(
            "PIP_ONLY_BINARY was not ':all:' during this run, so the no-source-build rule "
            "was not enforced by the environment -- only by intent."
        )

    # --- safeguard probes, before anything heavy runs --------------------
    print("\n--- A1: is the memory ceiling live? ---")
    a1 = _probes.probe_memory_ceiling_live()
    data["memory_ceiling_probe"] = a1
    print(f"verdict: {a1['verdict']} (enforced={a1.get('enforced')})")
    print(f"  scope rc={a1.get('scope_returncode')} control_ok={a1.get('control_succeeded')} "
          f"memory.max={a1.get('memory_max_inside_scope')}")
    print(f"  {a1['interpretation']}")
    notes.append(f"memory ceiling probe: {a1['verdict']} -- {a1['interpretation']}")

    print("\n--- A2: does the ceiling cover device memory? ---")
    if a1.get("enforced"):
        a2 = _probes.probe_cgroup_covers_device_memory()
    else:
        a2 = {"probe": "cgroup_covers_device_memory", "verdict": "skipped",
              "reason": "the ceiling is not enforced, so its coverage is moot"}
    data["cgroup_coverage_probe"] = a2
    print(f"verdict: {a2['verdict']}")
    if a2.get("interpretation"):
        print(f"  {a2['interpretation']}")
        notes.append(f"cgroup coverage probe: {a2['verdict']} -- {a2['interpretation']}")

    # --- OOM protection on this host -------------------------------------
    rc_oomd, oomd_active, _ = C.sh("systemctl is-active systemd-oomd")
    rc_e, earlyoom, _ = C.sh("command -v earlyoom")
    data["oom_protection"] = {
        "systemd_oomd_active": oomd_active if rc_oomd == 0 else oomd_active or "inactive",
        "earlyoom_present": bool(earlyoom),
        "userspace_oom_daemon": bool(rc_oomd == 0 and oomd_active == "active") or bool(earlyoom),
    }
    if not data["oom_protection"]["userspace_oom_daemon"]:
        notes.append(
            "NO userspace OOM daemon on this host: systemd-oomd is "
            f"'{data['oom_protection']['systemd_oomd_active']}' and earlyoom is absent. "
            "Installing one requires root and passwordless sudo is not available to this "
            "account, so it could not be enabled here. The kernel OOM killer does fire "
            "(the 2026-09-18 incident log shows 155 oom-kill events) but only after the "
            "host has already become unresponsive. Phase 5 runs far longer than this gate "
            "and should not start until this is addressed."
        )

    status = C.STATUS_PASS
    if not torch_info.get("is_available"):
        status = C.STATUS_FAIL
        notes.append("CUDA is not available to torch")
    elif not data["disk_headroom_ok"]:
        status = C.STATUS_WARN

    return {"status": status, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
