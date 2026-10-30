#!/usr/bin/env -S python3 -I
"""Run the whole suite and write docs/test_results.json: one record per test (status, description, time).
The documentation generator reads this file - the "proof" column in the docs is this run, not a claim."""
import json, os, sys, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import helpers  # noqa: F401


class Collect(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = {}
        self._t = {}

    def _rec(self, test, status, detail=""):
        tid = test.id().split(" ")[0]
        sub = getattr(test, "_subDescription", lambda: "")()
        key = tid
        prev = self.records.get(key)
        if prev and prev["status"] != "pass" and status == "pass":
            return  # a subtest already failed: keep the failure
        self.records[key] = {"status": status, "doc": (test.shortDescription() or "") if hasattr(test, "shortDescription") else "",
                             "detail": detail[:400], "subtest": sub}

    def startTest(self, test):
        self._t[test.id()] = time.time()
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


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py")
    runner = unittest.TextTestRunner(resultclass=Collect, verbosity=1)
    t0 = time.time()
    res = runner.run(suite)
    out = os.path.normpath(os.path.join(HERE, "..", "..", "..", "docs"))
    os.makedirs(out, exist_ok=True)
    from guard.common import VERSION
    data = {"version": VERSION, "date": time.strftime("%Y-%m-%d %H:%M"), "seconds": round(time.time() - t0),
            "total": res.testsRun, "failures": len(res.failures), "errors": len(res.errors), "skipped": len(res.skipped),
            "tests": res.records}
    with open(os.path.join(out, "test_results.json"), "w") as f:
        json.dump(data, f, indent=1)
    print(f"wrote {out}/test_results.json")
    sys.exit(0 if res.wasSuccessful() else 1)
