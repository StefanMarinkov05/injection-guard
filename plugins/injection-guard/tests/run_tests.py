#!/usr/bin/env -S python3 -I
"""Run the injection-guard regression suite: python3 -I tests/run_tests.py [-v] [pattern]

Every detection that ever worked is pinned here. After changing the scanner, run this; a failure means
a technique that used to be caught is no longer caught (or a clean file became flagged).
"""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import helpers  # noqa: F401  (isolates HOME before guard is imported)

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbosity = 2 if "-v" in sys.argv else 1
    suite = unittest.defaultTestLoader.discover(HERE, pattern=(args[0] if args else "test_*.py"))
    res = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
