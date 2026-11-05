"""Golden run: regenerate the checked-in example output and prove it end to end."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import NOW, ROOT, Selftest, result, statuses, tool

EX = os.path.join(ROOT, "examples")
OUT = os.path.join(EX, "out", "assessment-results.json")


def golden(t):
    regen = tool("receipts-to-oscal", os.path.join(EX, "receipts"), os.path.join(EX, "control-map.tsv"), "--now", NOW)
    t.eq(regen.returncode, 0, "example regenerates")
    with open(OUT) as fh:
        stored = fh.read()
    t.check(regen.stdout == stored and stored != "", "regenerated output is byte-identical to examples/out")
    counts = {}
    for s in statuses(json.loads(stored)).values():
        counts[s] = counts.get(s, 0) + 1
    t.eq(counts, {"satisfied": 5, "not-satisfied": 2, "not-assessed": 1}, "example shows all three finding states")
    t.eq(len(result(json.loads(stored))["observations"]), 7, "one observation per example receipt")
    v = tool("oscal-verify", OUT, "--receipts", os.path.join(EX, "receipts"))
    t.check(v.returncode == 0 and "chain: 7/7 links verify" in v.stdout, "example chain verifies against its receipts")
    t.eq(tool("oscal-validate", OUT).returncode, 0, "example passes the structural validator")


if __name__ == "__main__":
    sys.exit(Selftest("golden").run([golden]))
