"""Fixture test: render the seed-2 branch in both directions before it lands.

The fixtures are the seed-1 records with run names rewritten, so the shapes are
exactly what compare_multi and score_rebuilt actually emit. One variant leaves
the hellaswag direction alone (agreement); the other flips its sign and verdict
(disagreement). Neither touches runs/.
"""
import copy, json, sys
REPO = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from docs.common import Resolver, Fmt, strip_exempt, tokens
from docs import model_card, readme, seed2

def rename_pairs(rec, mapping):
    out = copy.deepcopy(rec)
    for sect in ("domain", "general"):
        for k, v in out.get(sect, {}).items():
            v["pairs"] = {mapping.get(pk, pk): pv for pk, pv in v["pairs"].items()}
    return out

def build(flip_hellaswag: bool):
    R = Resolver()
    c1 = json.loads(open(REPO / "runs" / "compare.json").read())
    s2 = rename_pairs(c1, {"cond1 vs cond2": "cond1_s2 vs cond2_s2",
                           "cond1 vs baseline": "cond1_s2 vs baseline",
                           "cond2 vs baseline": "cond2_s2 vs baseline"})
    if flip_hellaswag:
        p = s2["general"]["hellaswag"]["pairs"]["cond1_s2 vs cond2_s2"]
        p["paired_difference"]["diff"] = -p["paired_difference"]["diff"]
        p["verdict"] = "no difference detected"
        p["mcnemar_p_holm"] = 0.41
    R.data["compare_s2"] = s2
    for c in ("cond1", "cond2"):
        R.data[f"seedvar_{c}"] = rename_pairs(
            c1, {"cond1 vs cond2": f"{c} vs {c}_s2",
                 "cond1 vs baseline": f"{c} vs baseline",
                 "cond2 vs baseline": f"{c}_s2 vs baseline"})
    pr = json.loads(open(REPO / "runs" / "probe" / "rebuilt_scores.json").read())
    pr["conditions"] = {f"{k}_s2": v for k, v in pr["conditions"].items()}
    R.data["probe_s2"] = pr
    for a, b in (("cond1_s2_train", "cond1_train"), ("cond2_s2_train", "cond2_train")):
        d = copy.deepcopy(R.data[b]); d["config"]["seed"] = 5678; R.data[a] = d
    for a, b in (("cond1_s2", "cond1"), ("cond2_s2", "cond2"),
                 ("cond1_s2_run", "cond1_run"), ("cond2_s2_run", "cond2_run")):
        R.data[a] = R.data[b]
    R.seed2 = True
    return R

for flip in (False, True):
    R = build(flip)
    label = "DISAGREE" if flip else "AGREE"
    for mod in (model_card, readme):
        F = Fmt(R)
        t = mod.render(F)
        bad = sorted(set(tk for tk in tokens(strip_exempt(t)) if tk not in F.allowed))
        assert not bad, f"{label} {mod.__name__}: untraceable {bad}"
        print(f"{label:9} {mod.__name__:18} {len(t):6,} bytes  trace OK")
    F = Fmt(R)
    print("           conclusion ->", " ".join(seed2.conclusion(F)[2].split())[:110])
    print("           readme     ->", " ".join(seed2.readme_clause(F).split())[:110])
print("\nFIXTURE TEST PASSED: both branches render and every number traces")
