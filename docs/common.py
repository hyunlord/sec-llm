# -*- coding: utf-8 -*-
"""Sources, resolution, and the traced number formatter.

The rule this file exists to enforce is one line long: a number that reaches a
published document must have come from a file on disk, and the path it came
from must be recorded beside it.

So there is no way to print a number except through `F`, and every `F` call
records `{kind, args}` -- never a pre-rendered string. `docs/trace_check.py`
re-resolves those args against the files on disk and re-renders them with the
same functions. If the builder had typed a figure, or if a manifest changed
after a document was written, the re-render disagrees and the check fails.

`derive` exists because some published figures are arithmetic on manifest
values (hours from seconds, a total from two parts). Those are registered with
the operation name and its operand paths, and the checker recomputes rather
than trusting the recorded result.
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
DOCS = REPO / "docs"
MANIFESTS = REPO / "manifests"
RUNS = REPO / "runs"
ENV = REPO / "env"

# ---------------------------------------------------------------- sources
#
# Every one of these is committed. `versions` is the only non-JSON entry: it is
# parsed from env/versions.lock by the same function in both the builder and
# the checker, so the SBOM's package versions are traceable to the lock file
# rather than to a snapshot taken at build time.
JSON_SOURCES = {
    "datasets": MANIFESTS / "datasets.manifest.json",
    "process": MANIFESTS / "process.manifest.json",
    "cve_list": MANIFESTS / "cve_list.manifest.json",
    "nvd": MANIFESTS / "nvd.manifest.json",
    "cwe": MANIFESTS / "cwe.manifest.json",
    "attack": MANIFESTS / "attack.manifest.json",
    "lock": REPO / "ingest" / "sources.lock.json",
    "costs": REPO / "ingest" / "acquisition_costs.json",
    "gate0": ENV / "gate0.json",
    "gate4": RUNS / "gate4.json",
    "compare": RUNS / "compare.json",
    "compare_p5": RUNS / "compare_p5_uncorrected.json",
    "baseline": RUNS / "baseline" / "scores.json",
    "cond1": RUNS / "cond1" / "scores.json",
    "cond2": RUNS / "cond2" / "scores.json",
    "baseline_run": RUNS / "baseline" / "manifest.json",
    "cond1_run": RUNS / "cond1" / "manifest.json",
    "cond2_run": RUNS / "cond2" / "manifest.json",
    "cond1_train": RUNS / "cond1" / "train_manifest.json",
    "cond2_train": RUNS / "cond2" / "train_manifest.json",
    "cond1_analysis": RUNS / "cond1" / "analysis.json",
    "probe": RUNS / "probe" / "rebuilt_scores.json",
    "probe_sets": RUNS / "probe" / "rebuilt_sets.json",
    "probe_p5": RUNS / "probe" / "scores.json",
    "refs": DOCS / "refs.json",
    "pkglic": ENV / "package_licenses.json",
}
LOCKFILE = ENV / "versions.lock"

# Seed-5678 replication. Absent until that run lands, so these are loaded when
# present and the documents render a single-seed finding when they are not.
# Every one of them must be there before the two-seed branch turns on: a
# document that reports one seed's replication and silently drops the other's
# would be worse than one that reports neither.
OPTIONAL_JSON_SOURCES = {
    "compare_s2": RUNS / "compare_seed2.json",
    "seedvar_cond1": RUNS / "compare_seedvar_cond1.json",
    "seedvar_cond2": RUNS / "compare_seedvar_cond2.json",
    "cond1_s2": RUNS / "cond1_s2" / "scores.json",
    "cond2_s2": RUNS / "cond2_s2" / "scores.json",
    "cond1_s2_run": RUNS / "cond1_s2" / "manifest.json",
    "cond2_s2_run": RUNS / "cond2_s2" / "manifest.json",
    "cond1_s2_train": RUNS / "cond1_s2" / "train_manifest.json",
    "cond2_s2_train": RUNS / "cond2_s2" / "train_manifest.json",
    "probe_s2": RUNS / "probe" / "rebuilt_scores_seed2.json",
}

# The pair keys compare_multi produces for each of those records, given the
# run order the finalizer passes. Named here so a renderer never guesses one.
# The RLVR demonstration, gated separately from the seed-2 records: one landing
# must not switch on a section that depends on the other.
RLVR_SOURCES = {
    "rlvr_run": RUNS / "rlvr" / "manifest.json",
    "rlvr_inspect": RUNS / "rlvr" / "reward_inspection.json",
    "rlvr_compare": RUNS / "compare_rlvr.json",
}
RLVR_PAIR = "rlvr vs cond2"

S2_PAIR = "cond1_s2 vs cond2_s2"
S1_PAIR = "cond1 vs cond2"
SEEDVAR_PAIR = {"cond1": "cond1 vs cond1_s2", "cond2": "cond2 vs cond2_s2"}

TASKS = ("cve_to_cwe", "cvss_vector", "structured_extract", "attack_technique")
SCORED_TASKS = ("cve_to_cwe", "cvss_vector", "structured_extract")
SPLITS = ("eval_post_cutoff", "eval_pre_cutoff")
DECODINGS = ("constrained", "free")
CONDS = ("baseline", "cond1", "cond2")
PAIRS = ("cond1 vs baseline", "cond2 vs baseline", "cond1 vs cond2")

TASK_KO = {
    "cve_to_cwe": "CVE→CWE 분류",
    "cvss_vector": "CVSS v3.1 벡터",
    "structured_extract": "구조화 추출",
    "attack_technique": "ATT&CK 기법 식별",
}
SPLIT_KO = {"eval_post_cutoff": "컷오프 이후", "eval_pre_cutoff": "컷오프 이전"}
DEC_KO = {"constrained": "제약 디코딩", "free": "자유 생성"}
COND_KO = {"baseline": "Cond-0 (베이스)", "cond1": "Cond-1 (도메인만)", "cond2": "Cond-2 (도메인+리플레이)"}


class TraceError(RuntimeError):
    pass


def parse_lock(text: str) -> dict:
    """env/versions.lock -> {name: version}. Same parse in builder and checker."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, _, ver = line.partition("==")
            out[name.strip()] = ver.strip()
    return out


class Resolver:
    """Loads every source once and resolves ['source', k1, k2, ...] paths."""

    def __init__(self):
        self.data = {}
        for name, path in JSON_SOURCES.items():
            if not path.exists():
                raise TraceError(f"source {name!r} is missing: {path}")
            self.data[name] = json.loads(path.read_text())
        if not LOCKFILE.exists():
            raise TraceError(f"env/versions.lock is missing: {LOCKFILE}")
        self.data["versions"] = parse_lock(LOCKFILE.read_text())
        # The license findings and their quoted evidence live in ingest/sources.py
        # and nowhere else; the per-source manifests carry the verdicts but not
        # the sentences they rest on. Imported, not copied, so the matrix cannot
        # drift from the audited record.
        from ingest.sources import DOC_ORDER, LICENSE_CHECK_DATE, SOURCES  # noqa: E402
        self.data["licenses"] = SOURCES
        self.data["license_meta"] = {"order": DOC_ORDER, "checked_on": LICENSE_CHECK_DATE}
        # All or nothing: a partial seed-2 landing renders as no seed 2.
        present = {k: p for k, p in OPTIONAL_JSON_SOURCES.items() if p.exists()}
        self.seed2 = len(present) == len(OPTIONAL_JSON_SOURCES)
        self.seed2_missing = sorted(set(OPTIONAL_JSON_SOURCES) - set(present))
        if self.seed2:
            for name, path in present.items():
                self.data[name] = json.loads(path.read_text())
        rl = {k: p for k, p in RLVR_SOURCES.items() if p.exists()}
        self.rlvr = len(rl) == len(RLVR_SOURCES)
        self.rlvr_missing = sorted(set(RLVR_SOURCES) - set(rl))
        if self.rlvr:
            for name, path in rl.items():
                self.data[name] = json.loads(path.read_text())

    def ref(self, path):
        if not path:
            raise TraceError("empty reference")
        src, keys = path[0], list(path[1:])
        if src not in self.data:
            raise TraceError(f"unknown source {src!r}")
        cur = self.data[src]
        walked = [src]
        for k in keys:
            walked.append(str(k))
            try:
                cur = cur[k] if not isinstance(cur, list) else cur[int(k)]
            except (KeyError, IndexError, ValueError, TypeError):
                raise TraceError(f"path not found: {'.'.join(walked)}")
        return cur

    def has(self, path) -> bool:
        try:
            self.ref(path)
            return True
        except TraceError:
            return False


# ------------------------------------------------------------- renderers
#
# One function per `kind`. Both the builder and the checker call these, so a
# published string is reproducible from (kind, args, files on disk) alone.
RENDERERS = {}


def renderer(name):
    def deco(fn):
        RENDERERS[name] = fn
        return fn
    return deco


OPS = {
    "sum": lambda vs: sum(vs),
    "diff": lambda vs: vs[0] - vs[1],
    "ratio": lambda vs: vs[0] / vs[1],
    "product": lambda vs: vs[0] * vs[1],
    "hours": lambda vs: sum(vs) / 3600.0,
    "minutes": lambda vs: sum(vs) / 60.0,
    "gib": lambda vs: sum(vs) / (1024.0 ** 3),
    "count": lambda vs: float(len(vs[0])),
    "pct_ratio": lambda vs: 100.0 * vs[0] / vs[1],
}


def _group(v) -> str:
    return f"{int(v):,}"


@renderer("n")
def _r_n(R, a):
    return _group(R.ref(a["ref"]))


@renderer("plain")
def _r_plain(R, a):
    return str(int(R.ref(a["ref"])))


@renderer("s")
def _r_s(R, a):
    return str(R.ref(a["ref"]))


@renderer("d")
def _r_d(R, a):
    return f"{float(R.ref(a['ref'])):.{a['nd']}f}"


@renderer("pct")
def _r_pct(R, a):
    return f"{float(R.ref(a['ref'])) * 100:.{a['nd']}f}%"


@renderer("pp")
def _r_pp(R, a):
    v = float(R.ref(a["ref"])) * 100
    return f"{v:+.{a['nd']}f}pp"


@renderer("abspp")
def _r_abspp(R, a):
    return f"{abs(float(R.ref(a['ref']))) * 100:.{a['nd']}f}pp"


@renderer("p")
def _r_p(R, a):
    v = float(R.ref(a["ref"]))
    if v == 0.0:
        return "0"
    if v >= 1e-4:
        return f"{v:.2g}"
    return f"{v:.1e}".replace("e-0", "e-")


@renderer("ci")
def _r_ci(R, a):
    lo, hi = R.ref(a["ref"])
    nd, sc = a["nd"], a["scale"]
    unit = a.get("unit", "")
    return f"[{lo * sc:+.{nd}f}, {hi * sc:+.{nd}f}]{unit}"


@renderer("ci_abs")
def _r_ci_abs(R, a):
    lo, hi = R.ref(a["ref"])
    nd, sc = a["nd"], a["scale"]
    unit = a.get("unit", "")
    return f"[{lo * sc:.{nd}f}, {hi * sc:.{nd}f}]{unit}"


@renderer("count")
def _r_count(R, a):
    return _group(len(R.ref(a["ref"])))


@renderer("verdict_count")
def _r_verdict_count(R, a):
    """How many cells in a comparison record carry a given verdict.

    A pure function of committed data, so the checker recomputes it rather
    than trusting the number the builder wrote. Used for statements of the
    form "seed sensitivity appears in N of M domain sets", which have no
    single path to point at.
    """
    cells = R.ref(a["ref"])
    n = 0
    for k in sorted(cells):
        rec = cells[k]["pairs"][a["pair"]]
        if a.get("sub"):
            rec = rec[a["sub"]]
        if rec["verdict"] == a["verdict"]:
            n += 1
    return str(n)


@renderer("calc")
def _r_calc(R, a):
    vals = [float(R.ref(r)) for r in a["refs"]]
    v = OPS[a["op"]](vals)
    nd = a["nd"]
    if nd == 0 and a.get("group", True):
        return _group(round(v))
    return f"{v:.{nd}f}"


@renderer("mdd")
def _r_mdd(R, a):
    """MDD, or an explicit refusal when the normal approximation does not hold.

    The minimum detectable difference is computed from a normal approximation
    to a binomial proportion. Within a few standard errors of 0 or 1 that
    approximation collapses and the formula returns a number far smaller than
    anything the experiment could resolve. Three standard errors is the
    conventional boundary for the approximation; inside it the cell refuses to
    print a figure rather than printing one that is wrong by orders of
    magnitude.
    """
    rate = float(R.ref(a["rate_ref"]))
    n = float(R.ref(a["n_ref"]))
    se = math.sqrt(max(rate * (1.0 - rate), 0.0) / n) if n > 0 else 0.0
    if rate <= 3.0 * se or (1.0 - rate) <= 3.0 * se:
        return a.get("na_text", "n/a (경계값)")
    return f"±{float(R.ref(a['ref'])) * 100:.{a['nd']}f}pp"


def at_boundary(R, rate_ref, n_ref) -> bool:
    rate = float(R.ref(rate_ref))
    n = float(R.ref(n_ref))
    se = math.sqrt(max(rate * (1.0 - rate), 0.0) / n) if n > 0 else 0.0
    return rate <= 3.0 * se or (1.0 - rate) <= 3.0 * se


# ---------------------------------------------------------- token extraction
NUM_RE = re.compile(r"\d+(?:,\d{3})*(?:\.\d+)?")
FENCE_RE = re.compile(r"```.*?```", re.S)
INLINE_RE = re.compile(r"`[^`\n]*`")
LINKTARGET_RE = re.compile(r"\]\([^)]*\)")
URL_RE = re.compile(r"https?://\S+")
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
# An identifier-shaped token -- a letter followed by letters, digits, dots,
# dashes or underscores -- is a name, not a figure: `sha256`, `v3.1`, `oasst2`,
# `P3.1`, `Qwen2.5`. Only those that actually contain a digit are removed, so
# ordinary words are left alone and the digits beside them are still checked.
IDENT_RE = re.compile(r"(?<![A-Za-z0-9._-])[A-Za-z][A-Za-z0-9._-]*")


def strip_exempt(md: str) -> str:
    """Remove the contexts where a digit is not a published figure.

    Exempt, and only these: fenced code blocks and inline code spans (commands,
    hashes, identifiers, model names, file paths), markdown link targets and
    bare URLs (issue numbers, revisions), and HTML comments. Everything left is
    prose and tables, where every digit must be traceable.
    """
    md = COMMENT_RE.sub(" ", md)
    md = FENCE_RE.sub(" ", md)
    md = INLINE_RE.sub(" ", md)
    md = LINKTARGET_RE.sub("] ", md)
    md = URL_RE.sub(" ", md)
    md = IDENT_RE.sub(lambda m: " " if any(c.isdigit() for c in m.group(0)) else m.group(0), md)
    return md


def tokens(text: str):
    return [m.group(0) for m in NUM_RE.finditer(text)]


class Fmt:
    """The only way a number reaches a document. Registers as it renders."""

    def __init__(self, resolver: Resolver):
        self.R = resolver
        self.entries = []          # ordered list of {kind, args, text}
        self.allowed = {}          # token -> list of entry indexes

    # -- registration ------------------------------------------------------
    def _emit(self, kind, **args) -> str:
        text = RENDERERS[kind](self.R, args)
        idx = len(self.entries)
        self.entries.append({"kind": kind, "args": args, "text": text})
        for t in tokens(text):
            self.allowed.setdefault(t, []).append(idx)
        return text

    # -- public formatters -------------------------------------------------
    def n(self, *ref):
        return self._emit("n", ref=list(ref))

    def plain(self, *ref):
        return self._emit("plain", ref=list(ref))

    def s(self, *ref):
        return self._emit("s", ref=list(ref))

    def d(self, *ref, nd=2):
        return self._emit("d", ref=list(ref), nd=nd)

    def pct(self, *ref, nd=1):
        return self._emit("pct", ref=list(ref), nd=nd)

    def pp(self, *ref, nd=1):
        return self._emit("pp", ref=list(ref), nd=nd)

    def abspp(self, *ref, nd=1):
        return self._emit("abspp", ref=list(ref), nd=nd)

    def p(self, *ref):
        return self._emit("p", ref=list(ref))

    def ci(self, *ref, nd=1, scale=100, unit="pp"):
        return self._emit("ci", ref=list(ref), nd=nd, scale=scale, unit=unit)

    def ci_abs(self, *ref, nd=1, scale=100, unit="%"):
        return self._emit("ci_abs", ref=list(ref), nd=nd, scale=scale, unit=unit)

    def count(self, *ref):
        return self._emit("count", ref=list(ref))

    def verdict_count(self, ref, pair, verdict="difference detected", sub=None):
        return self._emit("verdict_count", ref=list(ref), pair=pair, verdict=verdict, sub=sub)

    def calc(self, op, refs, nd=0, group=True):
        return self._emit("calc", op=op, refs=[list(r) for r in refs], nd=nd, group=group)

    def mdd(self, ref, rate_ref, n_ref, nd=1, na_text="n/a (비율이 경계값)"):
        return self._emit("mdd", ref=list(ref), rate_ref=list(rate_ref),
                          n_ref=list(n_ref), nd=nd, na_text=na_text)

    # -- helpers used by the renderers ------------------------------------
    def get(self, *ref):
        return self.R.ref(list(ref))

    def trace(self) -> dict:
        return {
            "note": ("every number published by `make docs`, with the file and path it was read "
                     "from. Regenerated by `make docs`; verified by `python -m docs.trace_check "
                     "--assert-all`, which re-resolves each path and re-renders it."),
            "sources": {k: str(v.relative_to(REPO)) for k, v in JSON_SOURCES.items()},
            "lockfile": str(LOCKFILE.relative_to(REPO)),
            "entries": self.entries,
        }


def cell(task, split, dec) -> str:
    return f"{task}/{split}/{dec}"


def gen_note(make_target="make docs") -> str:
    return (f"> 이 문서는 매니페스트와 실행 산출물에서 **자동 생성**된다. 손으로 고치지 말고 "
            f"`{make_target}`로 다시 만들 것. 모든 수치의 출처는 `docs/trace.json`에 경로로 기록되어 있고 "
            f"`python -m docs.trace_check --assert-all`이 이를 독립적으로 재확인한다.\n")
