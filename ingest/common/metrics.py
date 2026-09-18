"""Per-source run metrics.

Kept out of the manifests deliberately -- a wall-clock number would break the
byte-identical reproducibility the manifests exist to provide. These live in the
run record and are rendered into reports/ingest.md, which is where run-time
facts belong.

The cached/network distinction matters and is not cosmetic: re-deriving records
from a retained local snapshot takes a fraction of the time the original fetch
took, and presenting a cache-warm number as a fetch cost would understate what
this pipeline actually costs anyone who runs it from nothing.
"""

from __future__ import annotations

import time


class RunMetrics:
    def __init__(self, source_id: str):
        self.source_id = source_id
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.requests = 0
        self.bytes = 0
        self.network_used = False
        self.notes: list[str] = []

    @property
    def stats(self) -> dict:
        """The dict fetch.py mutates; reading it back keeps the counters in sync."""
        return self._stats

    _stats: dict = None  # set in __post_init__ style below

    def new_stats(self) -> dict:
        self._stats = {"requests": 0, "bytes": 0}
        return self._stats

    def absorb(self, stats: dict) -> None:
        self.requests += int(stats.get("requests", 0))
        self.bytes += int(stats.get("bytes", 0))
        if stats.get("requests"):
            self.network_used = True

    def finish(self) -> dict:
        self.finished_at = time.time()
        elapsed = round(self.finished_at - self.started_at, 2)
        key = "elapsed_seconds_network" if self.network_used else "elapsed_seconds_cached"
        out = {
            "source_id": self.source_id,
            "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at)),
            "finished_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.finished_at)),
            "elapsed_seconds": elapsed,
            key: elapsed,
            "used_network": self.network_used,
            "http_requests": self.requests,
            "bytes_transferred": self.bytes,
            "notes": self.notes,
        }
        return out
