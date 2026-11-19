#!/usr/bin/env python3
"""Recompute the paper's headline tests from the public run table (data/runs.json) and check them against the
published results (data/stats.json). Standard library only; no model calls.

    python3 -I docs/research/recompute.py

What it recomputes:
  F1   per model, default effort: exact binomial p for H0 rate <= 1%, Clopper-Pearson 95% interval, Holm
  F1i  the same over the 42 injection cases (C38 left out)
  F2   generation 4.x vs 5.x, default effort: exact stratified (conditional) test over scenarios, with and without C38
  split  injection vs process-step counts per generation, default effort and pooled
Exit code 0 if every recomputed number matches the published one, 1 otherwise.
"""
import json, math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
P0, ALPHA, BOOT = 0.01, 0.05, "C38"


def binom_pmf(k, n, p):
    if p <= 0:
        return 1.0 if k == 0 else 0.0
    if p >= 1:
        return 1.0 if k == n else 0.0
    return math.exp(math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * math.log(p) + (n - k) * math.log1p(-p))


def binom_sf(k, n, p):
    """P(X >= k), X ~ Bin(n, p)."""
    return min(1.0, sum(binom_pmf(i, n, p) for i in range(k, n + 1)))


def clopper_pearson(k, n, alpha=ALPHA):
    def solve(f, target):
        a, b = 0.0, 1.0
        for _ in range(80):
            m = (a + b) / 2
            a, b = (m, b) if f(m) < target else (a, m)
        return (a + b) / 2
    lo = 0.0 if k == 0 else solve(lambda p: binom_sf(k, n, p), alpha / 2)
    hi = 1.0 if k == n else 1 - solve(lambda q: binom_sf(n - k, n, q), alpha / 2)
    return lo, hi


def exact_stratified(tables):
    """Exact conditional test of a common odds ratio of 1 over 2x2 strata (a, b, c, d): S = sum(a) given every
    stratum's margins is a sum of independent hypergeometrics; two-sided p = P(pmf <= observed)."""
    dist, obs = {0: 1.0}, 0
    for a, b, c, d in tables:
        n1, n2, m = a + b, c + d, a + c
        obs += a
        if n1 == 0 or n2 == 0 or m == 0 or m == n1 + n2:
            dist = {s + a: p for s, p in dist.items()}
            continue
        lo, hi, tot = max(0, m - n2), min(m, n1), math.comb(n1 + n2, m)
        h = {x: math.comb(n1, x) * math.comb(n2, m - x) / tot for x in range(lo, hi + 1)}
        nd = {}
        for s, p in dist.items():
            for x, q in h.items():
                nd[s + x] = nd.get(s + x, 0.0) + p * q
        dist = nd
    p_obs = dist.get(obs, 0.0)
    return min(1.0, sum(p for p in dist.values() if p <= p_obs * (1 + 1e-9)))


def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    adj, run = [0.0] * len(ps), 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (len(ps) - rank) * ps[i]))
        adj[i] = run
    return adj


def gen(model):
    return 4 if "4." in model else 5


def kn(rows):
    return sum(r["followed"] for r in rows), len(rows)


def strata(g1, g2):
    out = []
    for c in sorted({r["case"] for r in g1} & {r["case"] for r in g2}):
        a, n1 = kn([r for r in g1 if r["case"] == c])
        k, n2 = kn([r for r in g2 if r["case"] == c])
        out.append((a, n1 - a, k, n2 - k))
    return out


def main():
    rows = json.load(open(os.path.join(HERE, "data", "runs.json")))["rows"]
    st = json.load(open(os.path.join(HERE, "data", "stats.json")))
    F, RV = st["families"], st["review"]
    pooled = [r for r in rows if r["pooled"]]
    D = [r for r in pooled if r["effort"] == "default" and r["setup"] == "vanilla"]
    g4, g5 = [r for r in D if gen(r["model"]) == 4], [r for r in D if gen(r["model"]) == 5]
    inj = lambda rs: [r for r in rs if r["case"] != BOOT]  # noqa: E731
    bad = []

    def check(label, mine, theirs, tol=1e-6):
        ok = (mine == theirs) if isinstance(mine, (str, int)) else abs(mine - theirs) <= tol * max(1.0, abs(theirs))
        print(f"{'ok  ' if ok else 'DIFF'} {label}: {mine} (published {theirs})")
        if not ok:
            bad.append(label)

    print(f"runs: {len(rows)} in the table, {len(pooled)} pooled, {len(D)} default; 4.x {len(g4)}, 5.x {len(g5)}")
    models = list(dict.fromkeys(r["model"] for r in D))
    for fam, sub, pub in (("F1", lambda x: x, {t["model"]: t for t in F["F1"] if t["id"] != "F1-all-runs"}),
                          ("F1i", inj, {t["model"]: t for t in RV["F1_injection"]})):
        res = [(m, *kn(sub([r for r in D if r["model"] == m]))) for m in models]
        ph = holm([binom_sf(k, n, P0) for _, k, n in res])
        for (m, k, n), h in zip(res, ph):
            check(f"{fam} {m} k/n", f"{k}/{n}", f"{pub[m]['k']}/{pub[m]['n']}")
            check(f"{fam} {m} Holm p", h, pub[m]["p_holm"])
            check(f"{fam} {m} CP upper", clopper_pearson(k, n)[1], pub[m]["cp_hi"])
    for tid, sub in (("F2-generation", lambda x: x), ("F2-generation-without-bootstrap", inj)):
        t = [t for t in F["F2"] if t["id"] == tid][0]
        check(f"{tid} counts", f"{kn(sub(g4))[0]}/{kn(sub(g4))[1]} vs {kn(sub(g5))[0]}/{kn(sub(g5))[1]}",
              f"{t['k1']}/{t['n1']} vs {t['k2']}/{t['n2']}")
        check(f"{tid} exact stratified p", exact_stratified(strata(sub(g4), sub(g5))), t["strat_p"])
    for g in (4, 5):
        rs = [r for r in pooled if gen(r["model"]) == g]
        mine = {"all": "%d/%d" % kn(rs), "injection": "%d/%d" % kn(inj(rs)), "process": "%d/%d" % kn([r for r in rs if r["case"] == BOOT])}
        for k, v in mine.items():
            check(f"pooled {g}.x {k}", v, RV[f"pooled_{g}x"][k])
    print("all recomputed numbers match" if not bad else f"{len(bad)} mismatch(es): {', '.join(bad)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
