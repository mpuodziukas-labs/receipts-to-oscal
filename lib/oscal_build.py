"""Turn parsed receipts and control-map rows into an OSCAL assessment-results document."""
import uuid
from datetime import timedelta

import chain
import rfc3339
from chain import NS, prop

OSCAL_VERSION = "1.1.2"
SKEW = timedelta(minutes=5)
BAD = ("future", "rc-nonzero", "stale")
_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, NS)


def uid(*parts):
    return str(uuid.uuid5(_UUID_NS, "|".join(parts)))


def gate_state(rec, now, max_age):
    if rec is None:
        return "missing"
    if rec["when"] - now > SKEW:
        return "future"
    if rec["rc"] != 0:
        return "rc-nonzero"
    if now - rec["when"] > max_age:
        return "stale"
    return "ok"


def observation(rec):
    return {
        "uuid": uid("obs", rec["file"], rec["sha256"]),
        "title": "gate %s" % rec["gate"],
        "description": "Gate %s returned rc=%d at %s against %s." % (rec["gate"], rec["rc"], rec["ts"], rec["sha"]),
        "methods": ["TEST"],
        "collected": rec["ts"],
        "props": [prop("gate", rec["gate"]), prop("rc", rec["rc"]), prop("subject-sha", rec["sha"]),
                  prop("receipt-file", rec["file"]), prop("receipt-sha256", rec["sha256"])],
    }


def group_controls(rows):
    out = {}
    for r in rows:
        key = (r["framework"], r["control_id"])
        out.setdefault(key, {"framework": r["framework"], "id": r["control_id"], "oid": r["oid"], "gates": []})
        out[key]["gates"].append(r["gate"])
    return list(out.values())


def judge(ctl, newest, now, max_age):
    """Return (status, reason, detail). A failure outranks a gap; a gap is never a pass."""
    states = [(g, gate_state(newest.get(g), now, max_age)) for g in ctl["gates"]]
    bad = [s for _, s in states if s in BAD]
    detail = "; ".join("%s: %s" % gs for gs in states)
    if bad:
        return "not-satisfied", bad[0], detail
    if any(s == "missing" for _, s in states):
        return "not-assessed", "no-receipt", detail
    return "satisfied", "ok", detail


def finding(ctl, verdict, newest):
    status, reason, detail = verdict
    return {
        "uuid": uid("finding", ctl["framework"], ctl["id"]),
        "title": "%s %s" % (ctl["framework"], ctl["id"]),
        "description": "%s. Status %s (%s)." % (detail, status, reason),
        "props": [prop("assessment-status", status), prop("finding-reason", reason),
                  prop("framework", ctl["framework"]), prop("control-id", ctl["id"])],
        "target": {"type": "objective-id", "target-id": ctl["oid"],
                   "status": {"state": "satisfied" if status == "satisfied" else "not-satisfied",
                              "reason": {"satisfied": "pass", "not-satisfied": "fail", "not-assessed": "other"}[status]}},
        "related-observations": [{"observation-uuid": uid("obs", newest[g]["file"], newest[g]["sha256"])}
                                 for g in ctl["gates"] if g in newest],
    }


def build(recs, rows, now, max_age, map_sha):
    """Return (document, [(control, status)...]). recs must be sorted oldest first."""
    newest = {r["gate"]: r for r in recs}
    controls = group_controls(rows)
    verdicts = [(c, judge(c, newest, now, max_age)) for c in controls]
    assessed = rfc3339.fmt(now)
    result = {
        "uuid": uid("result", assessed, map_sha),
        "title": "Gate receipts assessed against the control map",
        "description": "Each finding is derived from gate receipts only. A control with no receipt is not-assessed. "
                       "This is a mapping, not an attestation or audit opinion.",
        "start": assessed,
        "end": assessed,
        "props": [prop("assessed-at", assessed), prop("max-age-hours", "%g" % (max_age.total_seconds() / 3600)),
                  prop("control-map-sha256", map_sha), prop("receipt-count", len(recs))],
        "reviewed-controls": {"control-selections": [{"include-controls": [{"control-id": c["oid"]} for c in controls]}]},
        "observations": [observation(r) for r in recs],
        "findings": [finding(c, v, newest) for c, v in verdicts],
    }
    doc = {"assessment-results": {
        "uuid": uid("document", assessed, map_sha),
        "metadata": {"title": "Assessment results from gate receipts", "last-modified": assessed,
                     "version": "1", "oscal-version": OSCAL_VERSION},
        "import-ap": {"href": "urn:receipts-to-oscal:no-assessment-plan",
                      "remarks": "Placeholder. No OSCAL assessment plan exists for this run."},
        "results": [result],
    }}
    chain.seal(doc)
    return doc, [(c, v[0], v[1]) for c, v in verdicts]
