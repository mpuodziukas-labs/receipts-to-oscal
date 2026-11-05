"""Mutation harness: break the code in a throwaway copy and prove a selftest notices.

A mutant is KILLED when its selftest exits nonzero in the mutated copy. Guards against vacuous results:
  - the old text must occur exactly once, otherwise the mutant counts as SURVIVED (VACUOUS)
  - one unmutated control copy per selftest must pass, otherwise every kill is suspect
Prints 'mutants K/K killed' and exits 0 only if every mutant was killed and every control passed.
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = ("bin", "lib", "tests", "examples")
SELFTESTS = ("convert", "verify", "validate")

# (name, selftest, file, old text, new text)
MUTANTS = [
    ("gap-counts-as-satisfied", "convert", "lib/oscal_build.py", 'return "not-assessed", "no-receipt", detail', 'return "satisfied", "ok", detail'),
    ("stale-ignored", "convert", "lib/oscal_build.py", 'if now - rec["when"] > max_age:', "if False:"),
    ("rc-ignored", "convert", "lib/oscal_build.py", 'if rec["rc"] != 0:', "if False:"),
    ("future-allowed", "convert", "lib/oscal_build.py", 'if rec["when"] - now > SKEW:', "if False:"),
    ("failure-no-longer-outranks-gap", "convert", "lib/oscal_build.py", "    if bad:\n", "    if bad and False:\n"),
    ("oldest-receipt-wins", "convert", "lib/oscal_build.py", 'for r in recs}', 'for r in reversed(recs)}'),
    ("empty-receipts-dir-passes", "convert", "lib/receipts.py", "    if not recs:", "    if False:"),
    ("bad-timestamp-accepted", "convert", "lib/receipts.py", "if when is None:", "if False:"),
    ("duplicate-key-accepted", "convert", "lib/receipts.py", "if key.strip() in out:", "if False:"),
    ("duplicate-map-row-accepted", "convert", "lib/receipts.py", "if (fw, cid, gate) in seen:", "if False:"),
    ("empty-map-passes", "convert", "lib/receipts.py", "    if not rows:", "    if False:"),
    ("receipt-hash-covers-one-byte", "convert", "lib/receipts.py", '"sha256": hashlib.sha256(data).hexdigest()}', '"sha256": hashlib.sha256(data[:1]).hexdigest()}'),
    ("require-all-ignored", "convert", "bin/receipts-to-oscal", 'return 1 if a.require_all and counts["satisfied"] != len(verdicts) else 0', "return 0"),
    ("head-ignores-findings", "verify", "lib/chain.py", '    res["observations"] = []\n', '    res["observations"] = []\n    res["findings"] = []\n'),
    ("link-hash-unchecked", "verify", "lib/chain.py", 'if obs_hash(obs, prev) != p.get("chain-hash"):', "if False:"),
    ("head-unchecked", "verify", "lib/chain.py", 'if head_hash(doc, prev) != _props(res).get("chain-head"):', "if False:"),
    ("receipt-sha-unchecked", "verify", "lib/chain.py", 'if actual != p.get("receipt-sha256"):', "if False:"),
    ("verify-exits-zero-on-tamper", "verify", "bin/oscal-verify", "    if problems:\n", "    if False:\n"),
    ("uuid-unchecked", "validate", "lib/oscal_check.py", 'UUID_RE.fullmatch(value), "%s: uuid', 'True, "%s: uuid'),
    ("date-unchecked", "validate", "lib/oscal_check.py", "self.ok(rfc3339.parse(value) is not None,", "self.ok(True,"),
    ("dangling-reference-unchecked", "validate", "lib/oscal_check.py", 'isinstance(ro, dict) and ro.get("observation-uuid") in known', "isinstance(ro, dict)"),
    ("not-assessed-accepted-as-state", "validate", "lib/oscal_check.py", 'in ("satisfied", "not-satisfied"), w +', 'in ("satisfied", "not-satisfied", "not-assessed"), w +'),
    ("skipped-trestle-says-valid", "validate", "lib/oscal_check.py", '"trestle: SKIPPED (not installed)"', '"trestle: valid"'),
    ("validate-exits-zero-on-failure", "validate", "bin/oscal-validate", "return 0 if not errors and trestle_ok else 1", "return 0"),
]


def copy_tree(dst):
    for part in PARTS:
        for base, dirs, files in os.walk(os.path.join(ROOT, part)):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            out = os.path.join(dst, os.path.relpath(base, ROOT))
            os.makedirs(out, exist_ok=True)
            for name in files:
                with open(os.path.join(base, name), "rb") as fh:
                    data = fh.read()
                target = os.path.join(out, name)
                with open(target, "wb") as fh:
                    fh.write(data)
                os.chmod(target, os.stat(os.path.join(base, name)).st_mode)


def start(work, label, selftest, edit=None):
    """Copy the repo into work/label, optionally apply (file, old, new), start the selftest."""
    dst = os.path.join(work, label)
    copy_tree(dst)
    if edit:
        path = os.path.join(dst, edit[0])
        with open(path) as fh:
            text = fh.read()
        if text.count(edit[1]) != 1:
            return None
        with open(path, "w") as fh:
            fh.write(text.replace(edit[1], edit[2]))
    script = os.path.join(dst, "tests", "selftest_%s.py" % selftest)
    return subprocess.Popen([sys.executable, script], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, universal_newlines=True)


def main():
    with tempfile.TemporaryDirectory() as work:
        controls = [(s, start(work, "control-" + s, s)) for s in SELFTESTS]
        bad_controls = []
        for s, p in controls:
            p.communicate()
            if p.returncode != 0:
                bad_controls.append(s)
        killed, survived = 0, []
        for i in range(0, len(MUTANTS), 6):
            running = []
            for name, selftest, rel, old, new in MUTANTS[i:i + 6]:
                running.append((name, start(work, name, selftest, (rel, old, new))))
            for name, proc in running:
                if proc is None:
                    survived.append("%s (VACUOUS: old text not found exactly once)" % name)
                    continue
                proc.communicate()
                if proc.returncode != 0:
                    killed += 1
                else:
                    survived.append("%s (selftest stayed green)" % name)
    for s in survived:
        print("SURVIVED %s" % s)
    for s in bad_controls:
        print("CONTROL FAILED: unmutated %s selftest is not green" % s)
    print("mutants %d/%d killed" % (killed, len(MUTANTS)))
    return 0 if killed == len(MUTANTS) and not bad_controls else 1


if __name__ == "__main__":
    sys.exit(main())
