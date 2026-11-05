"""Tiny assertion harness shared by the selftests.

Prints 'selftest NAME: P/N' and returns nonzero on any failure or on zero checks.
Failures are listed on stderr as 'FAIL: label' (the mutation harness reads them).
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = "2026-11-05T00:00:00Z"
SHA = "0123456789abcdef0123456789abcdef01234567"
FRESH = "2026-11-04T12:00:00Z"
STALE = "2026-10-28T00:00:00Z"      # 8 days before NOW
EDGE = "2026-10-29T00:00:00Z"       # exactly 168 hours before NOW
FUTURE = "2026-11-06T00:00:00Z"


def tool(name, *args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, os.path.join(ROOT, "bin", name)] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, env=e)


def write(path, content):
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content)


def kv(gate, rc, ts, sha=SHA):
    return "gate=%s\nrc=%s\nts=%s\nsha=%s\n" % (gate, rc, ts, sha)


MAP = ("framework\tcontrol_id\tgate\ttitle\n"
       "NIST-800-53r5\tCM-3\tgate-a\tchange control\n"
       "NIST-800-53r5\tSI-7\tgate-b\tintegrity\n")


def conv(files, mapping=MAP, extra=()):
    """Run receipts-to-oscal on a temp dir built from {filename: text|bytes}."""
    with tempfile.TemporaryDirectory() as d:
        rd = os.path.join(d, "r")
        os.mkdir(rd)
        for name, content in files.items():
            write(os.path.join(rd, name), content)
        mp = os.path.join(d, "map.tsv")
        write(mp, mapping)
        proc = tool("receipts-to-oscal", rd, mp, "--now", NOW, *extra)
    doc = None
    if proc.returncode == 0 and proc.stdout.strip():
        doc = json.loads(proc.stdout)
    return proc, doc


def result(doc):
    return doc["assessment-results"]["results"][0]


def prop(obj, name):
    return next(p["value"] for p in obj["props"] if p["name"] == name)


def statuses(doc):
    return {f["target"]["target-id"]: prop(f, "assessment-status") for f in result(doc)["findings"]}


class Selftest:
    def __init__(self, name):
        self.name, self.n, self.bad = name, 0, 0

    def check(self, cond, label):
        self.n += 1
        if not cond:
            self.bad += 1
            print("FAIL: %s" % label, file=sys.stderr)

    def eq(self, got, want, label):
        self.check(got == want, "%s (got %r, want %r)" % (label, got, want))

    def run(self, fns):
        for fn in fns:
            try:
                fn(self)
            except Exception as exc:  # a crashing test is a failed check, never a skipped one
                self.check(False, "%s raised %r" % (fn.__name__, exc))
        print("selftest %s: %d/%d" % (self.name, self.n - self.bad, self.n))
        return 1 if self.bad or self.n == 0 else 0
