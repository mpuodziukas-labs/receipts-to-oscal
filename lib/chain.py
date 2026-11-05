"""Hash chain over the observations, sealed by a head hash that also covers everything else.

link_i = sha256(link_(i-1) + LF + canonical(observation_i without its chain-hash prop))
head   = sha256(link_last + LF + canonical(document with observations emptied and chain-head removed))
The first link chains from 64 zeros. Integrity only: nothing here is signed.
"""
import hashlib
import json
import os

NS = "urn:receipts-to-oscal:1"
ZERO = "0" * 64


def prop(name, value):
    return {"name": name, "value": str(value), "ns": NS}


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _props(obj):
    return {p["name"]: p["value"] for p in obj["props"]}


def _drop(props, name):
    return [p for p in props if p["name"] != name]


def obs_hash(obs, prev):
    body = dict(obs)
    body["props"] = _drop(obs["props"], "chain-hash")
    return sha256_hex((prev + "\n" + canon(body)).encode())


def head_hash(doc, last):
    copy = json.loads(canon(doc))
    res = copy["assessment-results"]["results"][0]
    res["observations"] = []
    res["props"] = _drop(res["props"], "chain-head")
    return sha256_hex((last + "\n" + canon(copy)).encode())


def seal(doc):
    """Add chain-prev and chain-hash to each observation and chain-head to the result."""
    res = doc["assessment-results"]["results"][0]
    prev = ZERO
    for obs in res["observations"]:
        obs["props"].append(prop("chain-prev", prev))
        prev = obs_hash(obs, prev)
        obs["props"].append(prop("chain-hash", prev))
    res["props"].append(prop("chain-head", head_hash(doc, prev)))


def verify(doc, receipts_dir=None):
    """Return (links_ok, links_total, problems). Any problem means the document is not intact."""
    problems, ok, total = [], 0, 0
    try:
        results = doc["assessment-results"]["results"]
        if len(results) != 1:
            return 0, 0, ["TAMPER expected exactly one result, found %d" % len(results)]
        res = results[0]
        observations = res["observations"]
        total = len(observations)
        if not observations:
            return 0, 0, ["TAMPER no observations: an empty chain proves nothing"]
        prev = ZERO
        for i, obs in enumerate(observations, 1):
            p = _props(obs)
            good = True
            if p.get("chain-prev") != prev:
                problems.append("TAMPER observation %d: chain-prev does not match the previous link" % i)
                good = False
            if obs_hash(obs, prev) != p.get("chain-hash"):
                problems.append("TAMPER observation %d: content does not match its chain-hash" % i)
                good = False
            if receipts_dir is not None and not _receipt_matches(receipts_dir, p, i, problems):
                good = False
            ok += good
            prev = p.get("chain-hash") or ""
        if head_hash(doc, prev) != _props(res).get("chain-head"):
            problems.append("TAMPER head: chain-head does not match the document")
    except (KeyError, TypeError, AttributeError, IndexError, ValueError) as exc:
        problems.append("TAMPER malformed structure: %r" % (exc,))
    return ok, total, problems


def _receipt_matches(directory, p, i, problems):
    name = p.get("receipt-file", "")
    if not name or os.path.basename(name) != name:
        problems.append("TAMPER observation %d: receipt-file is missing or not a plain name" % i)
        return False
    try:
        with open(os.path.join(directory, name), "rb") as fh:
            actual = sha256_hex(fh.read())
    except OSError:
        problems.append("TAMPER observation %d: receipt %s cannot be read" % (i, name))
        return False
    if actual != p.get("receipt-sha256"):
        problems.append("TAMPER observation %d: receipt %s differs from the recorded sha256" % (i, name))
        return False
    return True
