#!/usr/bin/env -S python3 -I
"""Merge shard result files into one docs/test_results.json (same format as an unsharded run).

  python3 -I tests/merge_results.py OUT.json shard1.json shard2.json ... [--expect N]
Exit code 1 if any shard had failures/errors, a test ran in more than one shard, or (with --expect) tests are missing.
"""
import json, sys

args = sys.argv[1:]
expect = None
if "--expect" in args:
    i = args.index("--expect")
    expect = int(args[i + 1])
    del args[i:i + 2]
out, parts = args[0], args[1:]
merged = {"tests": {}, "total": 0, "failures": 0, "errors": 0, "skipped": 0, "seconds": 0}
dup = []
for p in parts:
    with open(p) as f:
        d = json.load(f)
    for k in ("version", "date"):
        merged[k] = d[k]
    for k in ("total", "failures", "errors", "skipped"):
        merged[k] += d[k]
    merged["seconds"] = max(merged["seconds"], d["seconds"])  # wall time = slowest shard
    for tid, rec in d["tests"].items():
        if tid in merged["tests"]:
            dup.append(tid)
        merged["tests"][tid] = rec
merged["shards"] = len(parts)
with open(out, "w") as f:
    json.dump(merged, f, indent=1)
print(f"{len(parts)} shard(s): {merged['total']} tests, {merged['failures']} failures, {merged['errors']} errors, "
      f"{merged['skipped']} skipped, slowest shard {merged['seconds']} s")
if dup:
    print("tests run in more than one shard:", dup[:10])
missing = expect is not None and merged["total"] != expect
if missing:
    print(f"expected {expect} tests, got {merged['total']} - a shard did not report")
sys.exit(1 if merged["failures"] or merged["errors"] or dup or missing else 0)
