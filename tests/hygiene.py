"""Public-safety scan: every repo file is plain ASCII (no em dashes, no emoji) and has no local path.

Zero files scanned is a failure, not a pass. The scan proves itself on a planted bad tree first.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import ROOT, Selftest, write

SKIP = {".git", "__pycache__"}
BAD_PATHS = ("/Us" + "ers/", "/ho" + "me/")


def scan(root):
    """Return (files_scanned, problems)."""
    n, problems = 0, []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in files:
            n += 1
            path = os.path.join(base, name)
            with open(path, "rb") as fh:
                data = fh.read()
            if any(b > 127 for b in data):
                problems.append("%s: non-ASCII byte" % os.path.relpath(path, root))
            if any(p.encode() in data for p in BAD_PATHS):
                problems.append("%s: local path" % os.path.relpath(path, root))
    return n, problems


def planted(t):
    with tempfile.TemporaryDirectory() as d:
        write(os.path.join(d, "clean.md"), "plain text\n")
        t.eq(scan(d), (1, []), "clean tree passes")
        write(os.path.join(d, "dash.md"), "a " + chr(0x2014) + " b\n")
        write(os.path.join(d, "path.txt"), BAD_PATHS[0] + "x\n")
        n, problems = scan(d)
        t.eq((n, len(problems)), (3, 2), "planted em dash and local path are both caught")
    with tempfile.TemporaryDirectory() as d:
        t.eq(scan(d), (0, []), "empty tree scans zero files")


def repo(t):
    n, problems = scan(ROOT)
    t.check(n > 0, "repo scan saw files (%d)" % n)
    t.eq(problems, [], "repo is ASCII-only and path-clean")


if __name__ == "__main__":
    sys.exit(Selftest("hygiene").run([planted, repo]))
