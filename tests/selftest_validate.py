"""Selftest: the stdlib structural validator, and the optional compliance-trestle hook."""
import copy
import importlib.util
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import FRESH, NOW, ROOT, Selftest, kv, result, tool, write
from selftest_verify import FILES, MAP, built

FAKE = os.path.join(ROOT, "tests", "fixtures", "fake-trestle")


def validate(doc, env=None, raw=None):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "o.json")
        write(path, raw if raw is not None else json.dumps(doc, indent=2))
        return tool("oscal-validate", path, env=env)


def rejects(t, label, edit, needle="structural: FAIL"):
    with built() as (doc, _):
        bad = copy.deepcopy(doc)
        edit(bad)
    p = validate(bad)
    t.eq(p.returncode, 1, "rejects %s: rc" % label)
    t.check(needle in p.stdout, "rejects %s: says so" % label)


def accepts(t):
    with built() as (doc, _):
        p = validate(doc)
    n = p.stdout.split("structural: ")[1].split("/")[0] if "structural: " in p.stdout else "0"
    t.eq(p.returncode, 0, "valid document: rc")
    t.check(n.isdigit() and int(n) > 30 and ("structural: %s/%s checks pass" % (n, n)) in p.stdout,
            "valid document: N/N checks pass with a non-trivial N")


def required_keys(t):
    ar = lambda d: d["assessment-results"]
    rejects(t, "missing metadata", lambda d: ar(d).pop("metadata"))
    rejects(t, "missing import-ap", lambda d: ar(d).pop("import-ap"))
    rejects(t, "no results", lambda d: ar(d).update(results=[]))
    rejects(t, "missing result description", lambda d: result(d).pop("description"))
    rejects(t, "missing observation collected", lambda d: result(d)["observations"][0].pop("collected"))
    rejects(t, "missing finding target", lambda d: result(d)["findings"][0].pop("target"))
    rejects(t, "wrong top-level key", lambda d: d.update({"catalog": d.pop("assessment-results")}))


def values(t):
    ar = lambda d: d["assessment-results"]
    rejects(t, "uuid not a uuid", lambda d: ar(d).update(uuid="not-a-uuid"))
    rejects(t, "uuid version 1", lambda d: ar(d).update(uuid="6ba7b810-9dad-11d1-80b4-00c04fd430c8"))
    rejects(t, "duplicate uuid", lambda d: result(d)["findings"][1].update(uuid=result(d)["findings"][0]["uuid"]))
    rejects(t, "date without zone", lambda d: ar(d)["metadata"].update({"last-modified": "2026-11-05T00:00:00"}))
    rejects(t, "impossible date", lambda d: ar(d)["metadata"].update({"last-modified": "2026-13-45T00:00:00Z"}))
    rejects(t, "bad collected date", lambda d: result(d)["observations"][0].update(collected="yesterday"))
    rejects(t, "unknown method", lambda d: result(d)["observations"][0].update(methods=["GUESS"]))
    rejects(t, "empty methods", lambda d: result(d)["observations"][0].update(methods=[]))
    rejects(t, "status state not-assessed", lambda d: result(d)["findings"][0]["target"]["status"].update(state="not-assessed"))
    rejects(t, "dangling related observation",
            lambda d: result(d)["findings"][0].update({"related-observations": [{"observation-uuid": "6ba7b810-9dad-41d1-80b4-00c04fd430c8"}]}))
    rejects(t, "prop without value", lambda d: result(d)["props"].append({"name": "x"}))
    rejects(t, "bad control-id token", lambda d: result(d)["reviewed-controls"]["control-selections"][0]["include-controls"].append({"control-id": "has space"}))
    p = validate(None, raw="not json")
    t.eq(p.returncode, 1, "rejects non-JSON: rc")
    t.check("structural: FAIL" in p.stdout, "rejects non-JSON: says so")


def trestle(t):
    with built() as (doc, _):
        installed = importlib.util.find_spec("trestle") is not None
        p = validate(doc)
        lines = [l for l in p.stdout.splitlines() if l.startswith("trestle:")]
        t.eq(len(lines), 1, "exactly one trestle line is printed")
        if installed:
            t.check(lines and "SKIPPED" not in lines[0], "trestle installed: not reported as skipped")
        else:
            t.eq(lines, ["trestle: SKIPPED (not installed)"], "trestle absent: SKIPPED, never valid")
            t.check("valid" not in lines[0].replace("invalid", ""), "skipped line does not say valid")
        ok = validate(doc, env={"PYTHONPATH": FAKE})
        t.check(ok.returncode == 0 and "trestle: PASS" in ok.stdout, "trestle present and accepting: PASS")
        bad = validate(doc, env={"PYTHONPATH": FAKE, "FAKE_TRESTLE_FAIL": "1"})
        t.check(bad.returncode == 1 and "trestle: FAIL" in bad.stdout, "trestle present and rejecting: FAIL, rc 1")


def usage(t):
    t.eq(tool("oscal-validate").returncode, 2, "no argument: rc 2")


if __name__ == "__main__":
    sys.exit(Selftest("validate").run([accepts, required_keys, values, trestle, usage]))
