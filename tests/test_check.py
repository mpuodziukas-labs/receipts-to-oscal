"""pytest entry point: the selftests, golden run, hygiene scan and mutation harness must pass, and the runner must not pass on nothing."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "check.py")] + list(args), cwd=ROOT, capture_output=True, text=True)


def test_every_step_passes():
    r = run()
    assert r.returncode == 0, r.stdout + r.stderr


def test_unknown_step_is_not_a_pass():
    assert run("no-such-step").returncode != 0
