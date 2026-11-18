#!/bin/sh
# Thin wrapper so `./check.sh` works from a fresh clone. The logic lives in check.py.
exec python3 "$(dirname "$0")/check.py" "$@"
