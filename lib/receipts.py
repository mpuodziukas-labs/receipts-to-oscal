"""Read gate receipts and the control map. Anything malformed raises InputError (fail closed)."""
import hashlib
import json
import os
import re

import rfc3339


class InputError(Exception):
    pass


GATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SHA_RE = re.compile(r"[0-9a-f]{7,64}")
INT_RE = re.compile(r"-?[0-9]{1,6}")
FIELDS = ("gate", "rc", "ts", "sha")


def _fields(text):
    """One record from JSON (a single object), a TSV header plus one row, or key=value lines."""
    body = text.strip()
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except ValueError:
            raise InputError("not a single JSON object")
        if not isinstance(obj, dict):
            raise InputError("JSON is not an object")
        return obj
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if len(lines) == 2 and "\t" in lines[0]:
        head, row = lines[0].split("\t"), lines[1].split("\t")
        if len(head) != len(row):
            raise InputError("TSV row width differs from header")
        return dict(zip(head, row))
    out = {}
    for ln in lines:
        key, sep, value = ln.partition("=")
        if not sep:
            raise InputError("line is not key=value: %r" % ln[:40])
        if key.strip() in out:
            raise InputError("duplicate key %s" % key.strip())
        out[key.strip()] = value.strip()
    return out


def parse(name, data):
    """Validate one receipt file's bytes and return its record (including sha256 of the bytes)."""
    try:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise InputError("not UTF-8 text")
        f = _fields(text)
        missing = [k for k in FIELDS if k not in f]
        if missing:
            raise InputError("missing field(s) %s" % ",".join(missing))
        gate, rc, ts, sha = (f[k] for k in FIELDS)
        int_ok = (isinstance(rc, int) and not isinstance(rc, bool)) or (isinstance(rc, str) and INT_RE.fullmatch(rc))
        if not int_ok:
            raise InputError("rc is not an integer")
        if not (isinstance(gate, str) and GATE_RE.fullmatch(gate)):
            raise InputError("gate name is not [A-Za-z0-9._-]{1,64}")
        if not (isinstance(sha, str) and SHA_RE.fullmatch(sha)):
            raise InputError("sha is not 7 to 64 lowercase hex characters")
        when = rfc3339.parse(ts)
        if when is None:
            raise InputError("ts is not an RFC 3339 date-time")
    except InputError as exc:
        raise InputError("%s: %s" % (name, exc))
    return {"file": name, "gate": gate, "rc": int(rc), "ts": ts, "when": when, "sha": sha,
            "sha256": hashlib.sha256(data).hexdigest()}


def load_receipts(directory):
    if not os.path.isdir(directory):
        raise InputError("not a directory: %s" % directory)
    recs = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if name.startswith(".") or not os.path.isfile(path):
            continue
        with open(path, "rb") as fh:
            recs.append(parse(name, fh.read()))
    if not recs:
        raise InputError("0 receipts in %s (an empty evidence set is never a pass)" % directory)
    return sorted(recs, key=lambda r: (r["when"], r["file"]))


def _id53(cid):
    return cid.lower().replace("(", ".").replace(")", "")


def _idrmf(cid):
    return cid.lower().replace(" ", "-")


FRAMEWORKS = {
    "NIST-800-53r5": (re.compile(r"[A-Z]{2}-[0-9]{1,2}(\([0-9]{1,2}\))?"), _id53),
    "NIST-AI-RMF": (re.compile(r"(GOVERN|MAP|MEASURE|MANAGE) [1-9]\.[0-9]{1,2}"), _idrmf),
}


def load_map(path):
    """Return (rows, sha256 of the map bytes). Columns: framework, control_id, gate, [title]."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError("control map unreadable: %s" % exc)
    rows, seen, header = [], set(), False
    for num, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if not header:
            if cols[:3] != ["framework", "control_id", "gate"]:
                raise InputError("control map header must start framework<TAB>control_id<TAB>gate")
            header = True
            continue
        if len(cols) not in (3, 4):
            raise InputError("control map line %d: expected 3 or 4 columns" % num)
        fw, cid, gate = cols[:3]
        if fw not in FRAMEWORKS or not FRAMEWORKS[fw][0].fullmatch(cid):
            raise InputError("control map line %d: unknown framework or malformed id %r %r" % (num, fw, cid))
        if not GATE_RE.fullmatch(gate):
            raise InputError("control map line %d: bad gate name" % num)
        if (fw, cid, gate) in seen:
            raise InputError("control map line %d: duplicate row" % num)
        seen.add((fw, cid, gate))
        rows.append({"framework": fw, "control_id": cid, "gate": gate,
                     "title": cols[3] if len(cols) == 4 else "", "oid": FRAMEWORKS[fw][1](cid)})
    if not rows:
        raise InputError("control map has 0 rows")
    return rows, hashlib.sha256(data).hexdigest()
