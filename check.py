#!/usr/bin/env python3
"""Run everything: three selftests, the golden run, the hygiene scan, the mutation harness.

  python3 check.py              run all steps
  python3 check.py convert ...  run only the named steps (convert verify validate golden hygiene mutants)

Selftests run in parallel; output is printed in a fixed order. Exit 0 only if every selected
step passed and at least one step ran. 'trestle' status is printed by the validate step.
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
STEPS = {"convert": "selftest_convert.py", "verify": "selftest_verify.py", "validate": "selftest_validate.py",
         "golden": "golden.py", "hygiene": "hygiene.py", "mutants": "mutants.py"}


def start(script):
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", script)], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def finish(proc):
    out, err = proc.communicate()
    sys.stdout.write(out)
    if proc.returncode != 0:
        sys.stderr.write(err)
    return proc.returncode


def trestle_line():
    sys.path.insert(0, os.path.join(ROOT, "lib"))
    import oscal_check
    return oscal_check.trestle(os.path.join(ROOT, "examples", "out", "assessment-results.json"))[0]


def main(argv):
    unknown = [a for a in argv if a not in STEPS]
    if unknown:
        sys.exit("check.py: unknown step %s" % unknown)
    want = [n for n in STEPS if not argv or n in argv]
    began = time.time()
    quick = [(n, start(STEPS[n])) for n in want if n != "mutants"]
    red = [n for n, proc in quick if finish(proc) != 0]
    if "validate" in want:
        print(trestle_line())
    if "mutants" in want and finish(start(STEPS["mutants"])) != 0:
        red.append("mutants")
    for name in red:
        print("RED: %s" % name, file=sys.stderr)
    print("check wall: %d ms" % int((time.time() - began) * 1000))
    if red or not want:
        print("CHECK: RED", file=sys.stderr)
        return 1
    print("CHECK: GREEN (%d steps)" % len(want))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
