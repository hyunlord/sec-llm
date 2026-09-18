"""Probes that establish whether this harness's safeguards are real.

Both of these exist because a safeguard that was configured but not enforced is
worse than no safeguard: the whole harness is then built on an assumption that
reads as protection.

A1 -- is the memory ceiling live? `systemd-run --user` needs memory delegation
on the user slice. Where it is absent the command still succeeds and the limit
is silently ignored.

A2 -- what does the ceiling actually cover? On GB10 the GPU's memory is system
memory, and whether CUDA driver allocations are charged to the calling process's
cgroup is not documented in a way worth relying on. Either answer is fine; what
must not happen is documenting the ceiling as covering both when it covers one.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def probe_memory_ceiling_live() -> dict:
    """Allocate 2 GiB inside a 1 GiB scope. Being killed is the pass condition."""
    result = {
        "probe": "memory_ceiling_live",
        "question": "Does systemd-run --user --scope actually enforce MemoryMax on this host?",
    }
    if not _which("systemd-run"):
        result.update(verdict="unavailable", enforced=False,
                      detail="systemd-run not found on PATH")
        return result

    code = "b = bytearray(2 * 1024**3); print('NOT CAPPED')"
    rc, out, err = _run([
        "systemd-run", "--user", "--scope", "-q",
        "-p", "MemoryMax=1G", "-p", "MemorySwapMax=0",
        sys.executable, "-c", code,
    ])
    result["scope_returncode"] = rc
    result["scope_stdout"] = out
    result["scope_stderr"] = err[-600:]

    # Control: the same allocation must succeed unscoped, otherwise a kill
    # proves nothing about the ceiling.
    crc, cout, cerr = _run([sys.executable, "-c", "b = bytearray(2 * 1024**3); print('OK')"])
    result["control_returncode"] = crc
    result["control_succeeded"] = crc == 0

    # Read memory.max from inside a scope: direct evidence the value landed.
    mrc, mout, _ = _run([
        "systemd-run", "--user", "--scope", "-q",
        "-p", "MemoryMax=1G", "-p", "MemorySwapMax=0",
        "sh", "-c",
        'cat /sys/fs/cgroup/$(awk -F: \'/^0::/{print $3}\' /proc/self/cgroup)/memory.max 2>/dev/null || echo unreadable',
    ])
    result["memory_max_inside_scope"] = mout

    killed = rc in (137, -9) or "NOT CAPPED" not in out
    enforced = killed and result["control_succeeded"] and mout.strip() == "1073741824"
    result["enforced"] = bool(enforced)
    result["verdict"] = "live" if enforced else "NOT_ENFORCED"
    result["interpretation"] = (
        "The 2 GiB allocation was killed inside a 1 GiB scope, the same allocation "
        "succeeded unscoped, and memory.max inside the scope reads 1073741824. The "
        "ceiling is enforced."
        if enforced else
        "The ceiling did NOT take effect. Every memory limit in this harness is "
        "decorative; check 07 runs without an effective host-RAM ceiling and the risk "
        "is real rather than mitigated. Enabling it requires memory delegation on the "
        "user slice (systemctl set-property user-$(id -u).slice Delegate=memory, root)."
    )
    return result


def probe_cgroup_covers_device_memory(gib: int = 16, ceiling: str = "8G") -> dict:
    """Allocate `gib` on the GPU inside a scope capped below it.

    Killed  -> the ceiling covers device allocations as well as host RAM.
    Survives-> the ceiling bounds host RAM only, and GPU-side protection has to
               come from the CUDA allocator cap instead.
    """
    result = {
        "probe": "cgroup_covers_device_memory",
        "question": "Are CUDA device allocations charged to the process cgroup on this host?",
        "device_alloc_gib": gib,
        "scope_ceiling": ceiling,
    }
    if not _which("systemd-run"):
        result.update(verdict="unavailable", detail="systemd-run not found")
        return result

    script = (
        "import torch\n"
        "free, total = torch.cuda.mem_get_info()\n"
        "print(f'free={free/2**30:.1f} total={total/2**30:.1f}')\n"
        f"x = torch.empty(int({gib} * 2**30 // 2), dtype=torch.bfloat16, device='cuda')\n"
        "torch.cuda.synchronize()\n"
        "print('SURVIVED')\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(script)
        path = fh.name
    try:
        rc, out, err = _run([
            "systemd-run", "--user", "--scope", "-q",
            "-p", f"MemoryMax={ceiling}", "-p", "MemorySwapMax=0",
            sys.executable, path,
        ], timeout=600)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    result["returncode"] = rc
    result["stdout"] = out
    result["stderr"] = err[-600:]
    survived = "SURVIVED" in out
    killed = rc in (137, -9)
    if survived:
        result["verdict"] = "host_ram_only"
        result["covers_device_memory"] = False
        result["interpretation"] = (
            f"A {gib} GiB device allocation survived inside a {ceiling} scope, so CUDA "
            "device memory is NOT charged to the process cgroup. The ceiling bounds host "
            "RAM only. That is the failure the 2026-09-18 incident actually was -- a "
            "host-side compiler -- so the protection that matters is in place; GPU-side "
            "over-allocation is bounded separately by the CUDA allocator cap in check 07."
        )
    elif killed:
        result["verdict"] = "covers_device_memory"
        result["covers_device_memory"] = True
        result["interpretation"] = (
            f"The process was killed allocating {gib} GiB on device inside a {ceiling} "
            "scope, so device allocations ARE charged to the cgroup and the ceiling "
            "covers both host and device memory."
        )
    else:
        result["verdict"] = "inconclusive"
        result["covers_device_memory"] = None
        result["interpretation"] = f"Neither survived nor killed cleanly (rc={rc}); see stderr."
    return result


def _which(name):
    from shutil import which

    return which(name)
