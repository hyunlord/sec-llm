"""HTTP with rate limiting, retry, resume, and checksum verification.

Stdlib only, on purpose: rule 1 carried over from P0.1 forbids source
compilation, and the ingester has to run unchanged on the DGX (aarch64 Linux)
later. urllib is the one HTTP client guaranteed present on both.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

from .lineage import file_sha256

USER_AGENT = "sec-llm-ingest/0.1 (+https://github.com/hyunlord/sec-llm)"
DEFAULT_TIMEOUT = 120


class FetchError(RuntimeError):
    pass


class RateLimiter:
    """Sliding-window limiter plus a minimum inter-request sleep.

    Both halves matter. The window enforces the documented hard limit; the
    minimum interval implements the source's "please sleep between requests"
    guidance, which is a separate and softer request.
    """

    def __init__(self, max_requests: int, window_sec: float, min_interval_sec: float = 0.0):
        self.max_requests = max_requests
        self.window_sec = window_sec
        self.min_interval_sec = min_interval_sec
        self._times: deque[float] = deque()
        self._last = 0.0

    def acquire(self) -> float:
        waited = 0.0
        if self.min_interval_sec:
            gap = time.monotonic() - self._last
            if self._last and gap < self.min_interval_sec:
                d = self.min_interval_sec - gap
                time.sleep(d)
                waited += d
        now = time.monotonic()
        while self._times and now - self._times[0] > self.window_sec:
            self._times.popleft()
        if len(self._times) >= self.max_requests:
            d = self.window_sec - (now - self._times[0]) + 0.05
            if d > 0:
                time.sleep(d)
                waited += d
            now = time.monotonic()
            while self._times and now - self._times[0] > self.window_sec:
                self._times.popleft()
        self._times.append(time.monotonic())
        self._last = time.monotonic()
        return waited


def _opener():
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def http_get(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 5,
    backoff: float = 4.0,
    limiter: RateLimiter | None = None,
    stats: dict | None = None,
) -> bytes:
    """GET with retry and exponential backoff. Returns the body bytes."""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})

    last_exc = None
    for attempt in range(1, retries + 1):
        if limiter:
            limiter.acquire()
        try:
            req = urllib.request.Request(url, headers=hdrs, method="GET")
            with _opener().open(req, timeout=timeout) as resp:
                body = resp.read()
            if stats is not None:
                stats["requests"] = stats.get("requests", 0) + 1
                stats["bytes"] = stats.get("bytes", 0) + len(body)
            return body
        except urllib.error.HTTPError as exc:
            last_exc = exc
            # 403/404 on a pinned URL is a real failure, not a transient one.
            if exc.code in (400, 401, 403, 404):
                raise FetchError(f"HTTP {exc.code} for {url}: {exc.reason}") from exc
            wait = backoff * (2 ** (attempt - 1))
            print(f"    HTTP {exc.code} on attempt {attempt}/{retries}; sleeping {wait:.0f}s", flush=True)
            time.sleep(wait)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError) as exc:
            last_exc = exc
            wait = backoff * (2 ** (attempt - 1))
            print(f"    {type(exc).__name__} on attempt {attempt}/{retries}; sleeping {wait:.0f}s", flush=True)
            time.sleep(wait)
    raise FetchError(f"GET failed after {retries} attempts: {url}: {last_exc!r}")


def get_json(url: str, **kw) -> dict:
    return json.loads(http_get(url, **kw).decode("utf-8"))


def head(url: str, timeout: int = 60) -> dict:
    """HEAD for a size estimate before committing to a download."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return {
                "status": resp.status,
                "content_length": int(resp.headers.get("Content-Length") or 0),
                "last_modified": resp.headers.get("Last-Modified"),
                "etag": resp.headers.get("ETag"),
            }
    except Exception as exc:
        return {"status": None, "content_length": 0, "error": repr(exc)}


def download(
    url: str,
    dest: Path,
    *,
    expected_sha256: str | None = None,
    resume: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 5,
    stats: dict | None = None,
) -> dict:
    """Download to `dest`, resuming a partial file via HTTP Range.

    A run that dies at 80% must not restart from zero -- that is the whole point
    of the .part file and the Range header.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")

    if dest.exists() and expected_sha256:
        got = file_sha256(dest)
        if got == expected_sha256:
            return {"path": str(dest), "bytes": dest.stat().st_size, "sha256": got, "cached": True}
        print(f"    existing {dest.name} hash mismatch; refetching", flush=True)
        dest.unlink()

    meta = head(url)
    total = meta.get("content_length") or 0

    for attempt in range(1, retries + 1):
        have = part.stat().st_size if (resume and part.exists()) else 0
        if have and total and have >= total:
            break
        hdrs = {"User-Agent": USER_AGENT}
        mode = "wb"
        if have:
            hdrs["Range"] = f"bytes={have}-"
            mode = "ab"
            print(f"    resuming {dest.name} at {have/2**20:.1f} MiB", flush=True)
        try:
            req = urllib.request.Request(url, headers=hdrs, method="GET")
            with _opener().open(req, timeout=timeout) as resp:
                if have and resp.status != 206:
                    # Server ignored Range; start clean rather than corrupt the file.
                    mode, have = "wb", 0
                with open(part, mode) as fh:
                    done = have
                    last_print = time.monotonic()
                    while True:
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        fh.write(chunk)
                        done += len(chunk)
                        if time.monotonic() - last_print > 5:
                            pct = f"{done/total*100:5.1f}%" if total else "  ?  "
                            print(f"      {dest.name}: {pct} {done/2**20:8.1f} MiB", flush=True)
                            last_print = time.monotonic()
            break
        except urllib.error.HTTPError as exc:
            # A 4xx on a *pinned* URL is the pin being wrong, not the network
            # being flaky. Retrying it with backoff just delays the real answer.
            if exc.code in (400, 401, 403, 404, 410):
                raise FetchError(
                    f"HTTP {exc.code} for {url} -- the pinned artifact is not there. "
                    "This is a bad or stale pin, not a transient error; re-run `make pin`."
                ) from exc
            wait = 4.0 * (2 ** (attempt - 1))
            print(f"    download attempt {attempt}/{retries} failed: HTTP {exc.code}; sleeping {wait:.0f}s", flush=True)
            if attempt == retries:
                raise FetchError(f"download failed after {retries} attempts: {url}") from exc
            time.sleep(wait)
        except Exception as exc:
            wait = 4.0 * (2 ** (attempt - 1))
            print(f"    download attempt {attempt}/{retries} failed: {exc!r}; sleeping {wait:.0f}s", flush=True)
            if attempt == retries:
                raise FetchError(f"download failed after {retries} attempts: {url}") from exc
            time.sleep(wait)

    part.replace(dest)
    got = file_sha256(dest)
    size = dest.stat().st_size
    if expected_sha256 and got != expected_sha256:
        raise FetchError(
            f"checksum mismatch for {url}\n  expected {expected_sha256}\n  got      {got}"
        )
    if stats is not None:
        stats["requests"] = stats.get("requests", 0) + 1
        stats["bytes"] = stats.get("bytes", 0) + size
    return {"path": str(dest), "bytes": size, "sha256": got, "cached": False}


class ResumeState:
    """Tiny JSON state file so a long paged fetch can pick up where it died."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data: dict = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except Exception:
                self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True))
        tmp.replace(self.path)

    def clear(self):
        self.data = {}
        if self.path.exists():
            self.path.unlink()


def human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TiB"
