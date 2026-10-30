#!/usr/bin/env -S python3 -I
"""Run the suite (or one shard of it) and record every result: status, description, duration.

  python3 -I tests/report.py                          whole suite -> docs/test_results.json
  python3 -I tests/report.py --shard 2 --of 6 --out r2.json    one CI shard (balanced by tests/durations.json)
  python3 -I tests/report.py --write-durations        also refresh tests/durations.json from this run

The documentation generator reads docs/test_results.json - the "proof" column in the docs is a run, not a claim.
"""
import argparse, json, os, sys, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import helpers  # noqa: F401
DURATIONS = os.path.join(HERE, "durations.json")
DOCS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "docs"))


class Collect(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = {}
        self._t = {}

    def _rec(self, test, status, detail=""):
        tid = test.id().split(" ")[0]
        prev = self.records.get(tid)
        if prev and prev["status"] != "pass" and status == "pass":
            return  # a subtest already failed: keep the failure
        self.records[tid] = {"status": status, "doc": test.shortDescription() or "", "detail": detail[:400],
                             "seconds": round(time.time() - self._t.get(tid, time.time()), 2)}

    def startTest(self, test):
        self._t[test.id().split(" ")[0]] = time.time()
        super().startTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self._rec(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._rec(test, "FAIL", self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err)
        self._rec(test, "ERROR", self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._rec(test, "skip", reason)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._rec(test, "FAIL", f"{subtest._subDescription()}: {self._exc_info_to_string(err, test)}")


def flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flatten(t)
        else:
            yield t


def shard(tests, k, n):
    """Longest-processing-time-first bin packing on recorded durations; unknown tests count 1 s."""
    try:
        with open(DURATIONS) as f:
            dur = json.load(f)
    except Exception:
        dur = {}
    # tests of one class stay together when the class has expensive class-level setup (e.g. the HTTP server)
    groups = {}
    for t in tests:
        cls = t.id().rsplit(".", 1)[0]
        key = cls if cls.endswith(("SafeFetch",)) else t.id()
        groups.setdefault(key, []).append(t)
    items = sorted(groups.values(), key=lambda g: -sum(dur.get(t.id(), 1.0) for t in g))
    bins = [[0.0, []] for _ in range(n)]
    for g in items:
        b = min(bins, key=lambda x: x[0])
        b[0] += sum(dur.get(t.id(), 1.0) for t in g)
        b[1].extend(g)
    return bins[k - 1][1], [round(b[0]) for b in bins]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--of", type=int, default=1)
    ap.add_argument("--out", default=None)
    ap.add_argument("--write-durations", action="store_true")
    ap.add_argument("--count", action="store_true", help="print the number of tests and exit")
    a = ap.parse_args()
    tests = list(flatten(unittest.defaultTestLoader.discover(HERE, pattern="test_*.py")))
    if a.count:
        print(len(tests))
        return 0
    if a.shard:
        tests, loads = shard(tests, a.shard, a.of)
        print(f"shard {a.shard}/{a.of}: {len(tests)} tests, planned seconds per shard {loads}", flush=True)
    runner = unittest.TextTestRunner(resultclass=Collect, verbosity=1)
    t0 = time.time()
    res = runner.run(unittest.TestSuite(tests))
    from guard.common import VERSION
    data = {"version": VERSION, "date": time.strftime("%Y-%m-%d %H:%M"), "seconds": round(time.time() - t0),
            "total": res.testsRun, "failures": len(res.failures), "errors": len(res.errors), "skipped": len(res.skipped),
            "tests": res.records}
    out = a.out or os.path.join(DOCS, "test_results.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as f:
        json.dump(data, f, indent=1)
    print(f"wrote {out}")
    if a.write_durations:
        with open(DURATIONS, "w") as f:
            json.dump({k: v["seconds"] for k, v in sorted(res.records.items())}, f, indent=0)
        print(f"wrote {DURATIONS}")
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
