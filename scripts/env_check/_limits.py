"""Hard memory ceilings for check subprocesses.

Why this exists: on Grace-Blackwell the GPU and the host share one physical
memory pool, so a host-side process that over-allocates does not get a clean
OOM -- it drags the machine into swap and the whole box, GPU work included,
stops responding. That happened on 2026-09-18 and cost a physical power cycle.

The important half of the ceiling is MemorySwapMax=0. Capping RSS alone still
lets a process thrash; forbidding swap makes the kernel OOM-kill the scope
promptly instead, which is the behaviour we want.

`ulimit -v` is deliberately NOT used as a fallback for CUDA checks. CUDA
reserves an enormous virtual address space at context creation, so an
RLIMIT_AS ceiling low enough to be useful kills torch on import. When
systemd-run is unavailable we record that no ceiling could be applied rather
than applying one that breaks the check it is meant to protect.
"""

from __future__ import annotations

import functools
import os
import subprocess

# Host-RSS ceilings. Note these bound host memory, not CUDA allocations, which
# the NVIDIA driver manages outside the process cgroup. The torch-side cap in
# check 07 covers the GPU allocator; this covers everything else.
DEFAULT_MEMORY_MAX = os.environ.get("GATE0_MEMORY_MAX", "32G")
HEAVY_MEMORY_MAX = os.environ.get("GATE0_HEAVY_MEMORY_MAX", "80G")


@functools.lru_cache(maxsize=1)
def systemd_scope_available():
    """Can we actually get a memory-limited user scope on this host?

    Probed rather than assumed: --user scopes need cgroup delegation, which is
    present on a normal systemd login session and absent in plenty of others.
    """
    if not shutil_which("systemd-run"):
        return False, "systemd-run not found"
    try:
        p = subprocess.run(
            [
                "systemd-run", "--user", "--scope", "--quiet",
                "-p", "MemoryMax=256M", "-p", "MemorySwapMax=0",
                "true",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if p.returncode == 0:
            return True, "ok"
        return False, (p.stderr or p.stdout or "non-zero exit").strip()[:300]
    except Exception as exc:
        return False, repr(exc)[:300]


def shutil_which(name):
    from shutil import which

    return which(name)


def wrap(cmd, memory_max=None, tag=""):
    """Return (wrapped_cmd, info) applying a memory ceiling where possible."""
    mem = memory_max or DEFAULT_MEMORY_MAX
    ok, why = systemd_scope_available()
    if ok:
        wrapped = [
            "systemd-run", "--user", "--scope", "--quiet",
            "--unit", f"gate0-{tag}" if tag else "gate0-check",
            "-p", f"MemoryMax={mem}",
            "-p", "MemorySwapMax=0",
        ] + list(cmd)
        return wrapped, {
            "mechanism": "systemd-run --user --scope",
            "memory_max": mem,
            "memory_swap_max": "0",
            "applied": True,
        }
    return list(cmd), {
        "mechanism": None,
        "memory_max": None,
        "applied": False,
        "reason": (
            f"systemd-run unusable ({why}); no ceiling applied. ulimit -v is not an "
            "acceptable substitute for a CUDA process -- RLIMIT_AS low enough to bound "
            "RSS kills torch at context creation."
        ),
    }
