"""Selftest: oscal-verify recomputes the hash chain; every tamper must exit 1."""
import contextlib
import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import FRESH, NOW, ROOT, Selftest, kv, prop, result, tool, write

MAP = ("framework\tcontrol_id\tgate\ttitle\n"
       "NIST-800-53r5\tCM-3\tgate-a\tx\nNIST-800-53r5\tSI-7\tgate-b\tx\n"
       "NIST-800-53r5\tSA-11\tgate-c\tx\nNIST-800-53r5\tRA-5\tgate-d\tx\n")
FILES = {"a.txt": kv("gate-a", 0, "2026-11-04T10:00:00Z"), "b.txt": kv("gate-b", 1, "2026-11-04T11:00:00Z"),
         "c.txt": kv("gate-c", 0, FRESH)}


@contextlib.contextmanager
def built():
    """Yield (doc, receipts_dir) for a fresh run with 3 receipts and 4 controls."""
    with tempfile.TemporaryDirectory() as d:
        rd = os.path.join(d, "r")
        os.mkdir(rd)
        for n, c in FILES.items():
            write(os.path.join(rd, n), c)
        write(os.path.join(d, "m.tsv"), MAP)
        p = tool("receipts-to-oscal", rd, os.path.join(d, "m.tsv"), "--now", NOW)
        yield json.loads(p.stdout), rd


def verify(doc, *extra, raw=None):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "o.json")
        write(path, raw if raw is not None else json.dumps(doc, indent=2))
        return tool("oscal-verify", path, *extra)


def tampered(t, label, edit, *extra):
    with built() as (doc, rd):
        bad = copy.deepcopy(doc)
        edit(bad)
        args = ("--receipts", rd) if extra else ()
        p = verify(bad, *args)
    t.eq(p.returncode, 1, "tamper (%s): rc" % label)
    t.check("TAMPER" in p.stdout or "not valid" in p.stdout, "tamper (%s): says what broke" % label)


def setprop(obj, name, value):
    for p in obj["props"]:
        if p["name"] == name:
            p["value"] = value


def intact(t):
    with built() as (doc, rd):
        p = verify(doc)
        q = verify(doc, "--receipts", rd)
    t.eq(p.returncode, 0, "intact rc")
    t.check("chain: 3/3 links verify" in p.stdout and "head: ok" in p.stdout, "intact prints N/N links and head ok")
    t.eq(q.returncode, 0, "intact with --receipts rc")


def edits(t):
    obs = lambda d: result(d)["observations"]
    tampered(t, "observation rc flipped", lambda d: setprop(obs(d)[1], "rc", "0"))
    tampered(t, "observation description", lambda d: obs(d)[0].update(description="all good"))
    tampered(t, "finding status flipped", lambda d: [f["props"].__setitem__(i, dict(p, value="satisfied"))
                                                      for f in result(d)["findings"] for i, p in enumerate(f["props"])
                                                      if p["name"] == "assessment-status"])
    tampered(t, "finding state flipped", lambda d: result(d)["findings"][1]["target"]["status"].update(state="satisfied"))
    tampered(t, "metadata title", lambda d: d["assessment-results"]["metadata"].update(title="other"))
    tampered(t, "max-age prop widened", lambda d: setprop(result(d), "max-age-hours", "99999"))
    tampered(t, "chain-head edited", lambda d: setprop(result(d), "chain-head", "0" * 64))
    tampered(t, "chain-hash edited", lambda d: setprop(obs(d)[1], "chain-hash", "f" * 64))
    tampered(t, "chain-prev edited", lambda d: setprop(obs(d)[0], "chain-prev", "f" * 64))
    tampered(t, "chain-head removed", lambda d: result(d).update(props=[p for p in result(d)["props"] if p["name"] != "chain-head"]))


def structure(t):
    obs = lambda d: result(d)["observations"]
    tampered(t, "observations reordered", lambda d: obs(d).reverse())
    tampered(t, "middle observation deleted", lambda d: obs(d).pop(1))
    tampered(t, "last observation deleted", lambda d: obs(d).pop())
    tampered(t, "all observations deleted", lambda d: obs(d).clear())
    tampered(t, "second result appended", lambda d: d["assessment-results"]["results"].append({}))
    tampered(t, "observation props removed", lambda d: obs(d)[0].pop("props"))
    for label, raw in (("not json", "{nope"), ("empty object", "{}"), ("list", "[]"), ("empty file", "")):
        p = verify(None, raw=raw)
        t.eq(p.returncode, 1, "garbage input (%s): rc" % label)


def against_receipts(t):
    with built() as (doc, rd):
        write(os.path.join(rd, "a.txt"), kv("gate-a", 0, "2026-11-04T10:00:01Z"))
        p = verify(doc, "--receipts", rd)
        q = verify(doc)
    t.eq(p.returncode, 1, "receipt edited after the fact: rc")
    t.check("a.txt" in p.stdout, "receipt mismatch names the file")
    t.eq(q.returncode, 0, "same doc without --receipts cannot see the edit (stated limit)")
    with built() as (doc, rd):
        write(os.path.join(rd, "b.txt"), b"")
        p = verify(doc, "--receipts", rd)
    t.eq(p.returncode, 1, "receipt emptied: rc")
    with built() as (doc, rd):
        p = verify(doc, "--receipts", os.path.join(rd, "gone"))
    t.eq(p.returncode, 1, "receipts dir missing: rc")


def forged_reseal_is_a_documented_limit(t):
    """A forger who recomputes every hash passes verify; regeneration from receipts still exposes it."""
    sys.path.insert(0, os.path.join(ROOT, "lib"))
    import chain
    with built() as (doc, rd):
        forged = copy.deepcopy(doc)
        res = result(forged)
        for f in res["findings"]:
            f["target"]["status"]["state"] = "satisfied"
        for o in res["observations"]:
            o["props"] = [p for p in o["props"] if p["name"] not in ("chain-prev", "chain-hash")]
        res["props"] = [p for p in res["props"] if p["name"] != "chain-head"]
        chain.seal(forged)
        t.eq(verify(forged).returncode, 0, "limit: a fully resealed forgery verifies (integrity, not authenticity)")
        t.check(forged != doc, "forgery differs from the honest document")
        mp = os.path.join(os.path.dirname(rd), "m.tsv")
        again = tool("receipts-to-oscal", rd, mp, "--now", prop(res, "assessed-at"))
        t.check(json.loads(again.stdout) != forged, "regeneration from the receipts exposes the forgery")
    with built() as (doc, rd):
        p = tool("receipts-to-oscal", rd, os.path.join(os.path.dirname(rd), "m.tsv"), "--now", prop(result(doc), "assessed-at"))
        t.eq(json.loads(p.stdout), doc, "honest regeneration reproduces the document exactly")


def usage(t):
    t.eq(tool("oscal-verify").returncode, 2, "no argument: rc 2")
    t.eq(tool("oscal-verify", os.path.join(ROOT, "no-such-file.json")).returncode, 2, "missing file: rc 2")


if __name__ == "__main__":
    sys.exit(Selftest("verify").run([intact, edits, structure, against_receipts,
                                     forged_reseal_is_a_documented_limit, usage]))
