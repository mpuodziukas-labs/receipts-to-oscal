"""Selftest: receipts + control map -> OSCAL findings. Planted failures included."""
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import (EDGE, FRESH, FUTURE, MAP, NOW, SHA, STALE, Selftest, conv, kv,
                     prop, result, statuses, tool, write)

GOOD = {"a.txt": kv("gate-a", 0, FRESH), "b.txt": kv("gate-b", 0, FRESH)}


def input_error(t, proc, label, needle=None):
    t.eq(proc.returncode, 2, label + ": rc")
    t.check("input error" in proc.stderr and (needle is None or needle in proc.stderr), label + ": names the cause")
    t.eq(proc.stdout, "", label + ": no output document")


def happy(t):
    proc, doc = conv(GOOD)
    t.eq(proc.returncode, 0, "happy rc")
    t.eq(statuses(doc), {"cm-3": "satisfied", "si-7": "satisfied"}, "happy statuses")
    t.eq(len(result(doc)["observations"]), 2, "one observation per receipt")


def missing_receipt(t):
    proc, doc = conv({"a.txt": kv("gate-a", 0, FRESH)})
    t.eq(proc.returncode, 0, "missing: report still produced")
    t.eq(statuses(doc)["si-7"], "not-assessed", "missing receipt is not-assessed")
    f = [x for x in result(doc)["findings"] if x["target"]["target-id"] == "si-7"][0]
    t.eq(f["target"]["status"]["state"], "not-satisfied", "missing receipt never maps to state satisfied")
    t.eq(conv({"a.txt": kv("gate-a", 0, FRESH)}, extra=("--require-all",))[0].returncode, 1, "--require-all: gap exits 1")
    t.eq(conv(GOOD, extra=("--require-all",))[0].returncode, 0, "--require-all: clean exits 0")


def stale(t):
    _, doc = conv({"a.txt": kv("gate-a", 0, STALE), "b.txt": kv("gate-b", 0, FRESH)})
    t.eq(statuses(doc)["cm-3"], "not-satisfied", "stale receipt is not-satisfied")
    f = [x for x in result(doc)["findings"] if x["target"]["target-id"] == "cm-3"][0]
    t.eq(prop(f, "finding-reason"), "stale", "stale reason recorded")
    _, doc = conv({"a.txt": kv("gate-a", 0, EDGE), "b.txt": kv("gate-b", 0, FRESH)})
    t.eq(statuses(doc)["cm-3"], "satisfied", "exactly max age is still fresh")
    _, doc = conv(GOOD, extra=("--max-age-hours", "1"))
    t.eq(statuses(doc)["cm-3"], "not-satisfied", "--max-age-hours tightens the window")


def bad_rc_and_future(t):
    _, doc = conv({"a.txt": kv("gate-a", 1, FRESH), "b.txt": kv("gate-b", 0, FRESH)})
    t.eq(statuses(doc)["cm-3"], "not-satisfied", "rc 1 is not-satisfied")
    _, doc = conv({"a.txt": kv("gate-a", 2, STALE), "b.txt": kv("gate-b", 0, FRESH)})
    f = [x for x in result(doc)["findings"] if x["target"]["target-id"] == "cm-3"][0]
    t.eq(prop(f, "finding-reason"), "rc-nonzero", "rc failure outranks staleness")
    _, doc = conv({"a.txt": kv("gate-a", 0, FUTURE), "b.txt": kv("gate-b", 0, FRESH)})
    t.eq(statuses(doc)["cm-3"], "not-satisfied", "timestamp in the future is not-satisfied")


def malformed(t):
    cases = {
        "missing field": "gate=gate-a\nrc=0\nts=%s\n" % FRESH,
        "rc not integer": kv("gate-a", "abc", FRESH),
        "ts not rfc3339": kv("gate-a", 0, "yesterday"),
        "sha not hex": kv("gate-a", 0, FRESH, "XYZ"),
        "gate with space": kv("a b", 0, FRESH),
        "truncated json": '{"gate": "gate-a", "rc": 0',
        "duplicate key": kv("gate-a", 0, FRESH) + "rc=1\n",
        "not key=value": "hello world\n",
        "empty file": "",
    }
    for label, text in cases.items():
        proc, _ = conv({"a.txt": text, "b.txt": kv("gate-b", 0, FRESH)})
        input_error(t, proc, "malformed (%s)" % label, "a.txt")
    proc, _ = conv({"a.txt": b"\xff\xfe\x00garbage", "b.txt": kv("gate-b", 0, FRESH)})
    input_error(t, proc, "malformed (binary)", "a.txt")


def empty_inputs(t):
    proc, _ = conv({})
    input_error(t, proc, "empty receipts dir", "0 receipts")
    proc, _ = conv({".hidden": kv("gate-a", 0, FRESH)})
    input_error(t, proc, "only a dotfile", "0 receipts")
    proc, _ = conv(GOOD, mapping="framework\tcontrol_id\tgate\n")
    input_error(t, proc, "map without rows")
    with tempfile.TemporaryDirectory() as d:
        write(os.path.join(d, "m.tsv"), MAP)
        proc = tool("receipts-to-oscal", os.path.join(d, "nope"), os.path.join(d, "m.tsv"))
        input_error(t, proc, "receipts dir does not exist")


def bad_maps(t):
    head = "framework\tcontrol_id\tgate\n"
    bad = {
        "unknown framework": head + "PCI\tCM-3\tgate-a\n",
        "malformed 800-53 id": head + "NIST-800-53r5\tCM3\tgate-a\n",
        "malformed ai rmf id": head + "NIST-AI-RMF\tMEASURE 9\tgate-a\n",
        "wrong header": "gate\tcontrol\tframework\nx\ty\tz\n",
        "short row": head + "NIST-800-53r5\tCM-3\n",
        "duplicate row": head + "NIST-800-53r5\tCM-3\tgate-a\nNIST-800-53r5\tCM-3\tgate-a\n",
    }
    for label, text in bad.items():
        proc, _ = conv(GOOD, mapping=text)
        input_error(t, proc, "bad map (%s)" % label)


def formats_and_hashes(t):
    files = {
        "a.json": json.dumps({"gate": "gate-a", "rc": 0, "ts": FRESH, "sha": SHA}),
        "b.tsv": "gate\trc\tts\tsha\ngate-b\t0\t%s\t%s\n" % (FRESH, SHA),
        "c.txt": "# comment\n" + kv("gate-c", 0, FRESH),
    }
    proc, doc = conv(files)
    t.eq(proc.returncode, 0, "three formats rc")
    t.eq(len(result(doc)["observations"]), 3, "json, tsv and key=value all parse")
    t.eq(statuses(doc), {"cm-3": "satisfied", "si-7": "satisfied"}, "formats feed findings")
    want = {hashlib.sha256(v.encode()).hexdigest() for v in files.values()}
    got = {prop(o, "receipt-sha256") for o in result(doc)["observations"]}
    t.eq(got, want, "observation carries sha256 of the receipt bytes")


def multi_gate_and_history(t):
    mp = MAP + "NIST-800-53r5\tSA-11\tgate-a\tx\nNIST-800-53r5\tSA-11\tgate-c\tx\n"
    _, doc = conv(GOOD, mapping=mp)
    t.eq(statuses(doc)["sa-11"], "not-assessed", "one of two gates missing: not-assessed")
    _, doc = conv({"a.txt": kv("gate-a", 1, FRESH), "b.txt": kv("gate-b", 0, FRESH)}, mapping=mp)
    t.eq(statuses(doc)["sa-11"], "not-satisfied", "a failure outranks a missing gate")
    old = {"old.txt": kv("gate-a", 1, STALE), "new.txt": kv("gate-a", 0, FRESH), "b.txt": kv("gate-b", 0, FRESH)}
    _, doc = conv(old)
    t.eq(statuses(doc)["cm-3"], "satisfied", "newest receipt per gate decides")
    t.eq(len(result(doc)["observations"]), 3, "older receipt stays on record")
    _, doc = conv(dict(GOOD, extra=kv("lint", 0, FRESH)))
    t.eq(len(result(doc)["observations"]), 3, "unmapped receipt still becomes an observation")
    t.eq(len(result(doc)["findings"]), 2, "unmapped receipt adds no finding")


def output_properties(t):
    p1, d1 = conv(GOOD)
    p2, _ = conv(GOOD)
    t.eq(p1.stdout, p2.stdout, "same inputs and --now give byte-identical output")
    with tempfile.TemporaryDirectory() as d:
        write(os.path.join(d, "o.json"), p1.stdout)
        v = tool("oscal-validate", os.path.join(d, "o.json"))
        t.eq(v.returncode, 0, "emitted document passes the structural validator")
    t.eq(prop(result(d1), "assessed-at"), NOW, "assessment time is recorded")
    t.eq(prop(result(d1), "max-age-hours"), "168", "max age is recorded")
    with tempfile.TemporaryDirectory() as d:
        rd = os.path.join(d, "r")
        os.mkdir(rd)
        write(os.path.join(rd, "a.txt"), kv("gate-a", 0, FRESH))
        write(os.path.join(d, "m.tsv"), MAP)
        out = os.path.join(d, "o.json")
        p = tool("receipts-to-oscal", rd, os.path.join(d, "m.tsv"), "--now", NOW, "-o", out)
        t.check(p.returncode == 0 and p.stdout == "" and os.path.getsize(out) > 0, "-o writes the file, stdout stays empty")
        t.check("not-assessed" in p.stderr.lower(), "summary names gaps on stderr")


if __name__ == "__main__":
    sys.exit(Selftest("convert").run([happy, missing_receipt, stale, bad_rc_and_future, malformed, empty_inputs,
                                      bad_maps, formats_and_hashes, multi_gate_and_history, output_properties]))
