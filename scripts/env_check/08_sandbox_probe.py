"""Check 08 -- is Docker usable as a Phase 4 evaluation sandbox on aarch64?

A probe, not a harness. It confirms three things and then gets out of the way:
the daemon runs on arm64, a container starts under the isolation flags Phase 4
intends to use, and outbound network is genuinely blocked rather than merely
declared blocked. The container is destroyed afterwards and nothing is left
behind.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "08"
CHECK_NAME = "sandbox_probe"

IMAGE = "docker.io/library/alpine:3.20"
ISOLATION_FLAGS = [
    "--network=none",
    "--memory=512m",
    "--pids-limit=128",
    "--read-only",
    "--tmpfs", "/tmp",
    "--security-opt", "no-new-privileges:true",
]


def run():
    notes = []
    data = {"image": IMAGE, "isolation_flags": ISOLATION_FLAGS}

    rc, out, err = C.sh("docker version --format json", timeout=60)
    data["docker_available"] = rc == 0
    if rc != 0:
        data["docker_error"] = err or out
        return {
            "status": C.STATUS_FAIL,
            "data": data,
            "notes": ["docker is not usable on this host; Phase 4 needs another isolation mechanism"],
        }
    try:
        v = json.loads(out)
        data["docker"] = {
            "client_version": v.get("Client", {}).get("Version"),
            "server_version": (v.get("Server") or {}).get("Version"),
            "server_arch": (v.get("Server") or {}).get("Arch"),
            "server_os": (v.get("Server") or {}).get("Os"),
        }
    except Exception:
        data["docker_raw"] = out[:2000]
    print(f"docker: {data.get('docker')}")

    rc, out, err = C.sh(f"docker pull -q {IMAGE}", timeout=600)
    data["image_pull_rc"] = rc
    data["image_pull_output"] = (out or err)[:500]
    if rc != 0:
        notes.append(f"could not pull {IMAGE}: {(err or out)[:200]}")
        return {"status": C.STATUS_FAIL, "data": data, "notes": notes}

    name = f"gate0-probe-{uuid.uuid4().hex[:8]}"
    data["container_name"] = name
    flags = " ".join(ISOLATION_FLAGS)

    # 1. Does it start and run under the full flag set?
    rc, out, err = C.sh(
        f"docker run --name {name} {flags} {IMAGE} "
        "sh -c 'echo STARTED; id -u; uname -m; touch /tmp/ok && echo TMPFS_WRITABLE; "
        "(touch /rootfs_probe 2>/dev/null && echo ROOTFS_WRITABLE) || echo ROOTFS_READONLY'",
        timeout=180,
    )
    data["run"] = {"rc": rc, "stdout": out, "stderr": err[:800]}
    data["container_started"] = rc == 0 and "STARTED" in out
    data["read_only_enforced"] = "ROOTFS_READONLY" in out
    data["tmpfs_writable"] = "TMPFS_WRITABLE" in out
    print(f"run rc={rc}\n{out}\n{err[:500]}")

    # 2. Is outbound network actually dead, not just configured off?
    rc2, out2, err2 = C.sh(
        f"docker run --rm {flags} {IMAGE} "
        "sh -c 'ip -o addr show 2>/dev/null | wc -l; "
        "(wget -q -T 5 -O - http://1.1.1.1 >/dev/null 2>&1 && echo NET_REACHABLE) || echo NET_BLOCKED; "
        "(ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo PING_OK) || echo PING_BLOCKED'",
        timeout=180,
    )
    data["network_probe"] = {"rc": rc2, "stdout": out2, "stderr": err2[:800]}
    data["network_blocked"] = "NET_BLOCKED" in out2 and "NET_REACHABLE" not in out2
    data["ping_blocked"] = "PING_BLOCKED" in out2
    print(f"network probe rc={rc2}\n{out2}")

    # 3. Is it destroyed afterwards?
    C.sh(f"docker rm -f {name}", timeout=120)
    rc3, out3, _ = C.sh(f"docker ps -a --filter name={name} --format '{{{{.Names}}}}'", timeout=60)
    data["container_destroyed"] = out3.strip() == ""
    print(f"container destroyed: {data['container_destroyed']}")

    ok = all(
        [
            data["container_started"],
            data["read_only_enforced"],
            data["tmpfs_writable"],
            data["network_blocked"],
            data["container_destroyed"],
        ]
    )
    notes.append(
        "docker "
        f"{data.get('docker', {}).get('server_version')} on "
        f"{data.get('docker', {}).get('server_os')}/{data.get('docker', {}).get('server_arch')}"
    )
    notes.append(
        f"isolation flags verified: started={data['container_started']}, "
        f"read_only={data['read_only_enforced']}, tmpfs={data['tmpfs_writable']}, "
        f"outbound_network_blocked={data['network_blocked']}, destroyed={data['container_destroyed']}"
    )
    notes.append("probe only -- the Phase 4 sandbox harness is out of scope for this work order")
    if not ok:
        notes.append("at least one isolation property did not hold; see data.run / data.network_probe")

    return {"status": C.STATUS_PASS if ok else C.STATUS_FAIL, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
