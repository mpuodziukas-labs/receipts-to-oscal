"""Stdlib structural check for the OSCAL assessment-results fields this tool emits.

It checks required keys, uuid shape, RFC 3339 dates, enumerations and reference integrity.
It does not check against the OSCAL JSON schema and is not a substitute for it.
"""
import importlib.util
import re
import subprocess
import sys

import rfc3339

UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}")
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*")
METHODS = {"EXAMINE", "INTERVIEW", "TEST"}


class Checker:
    def __init__(self):
        self.n, self.errors, self.uuids = 0, [], []

    def ok(self, cond, msg):
        self.n += 1
        if not cond:
            self.errors.append(msg)
        return bool(cond)

    def obj(self, value, where):
        return self.ok(isinstance(value, dict), "%s: not an object" % where)

    def need(self, value, keys, where):
        if not self.obj(value, where):
            return False
        return all([self.ok(k in value, "%s: missing %s" % (where, k)) for k in keys])

    def uuid(self, value, where):
        self.uuids.append(value)
        self.ok(isinstance(value, str) and UUID_RE.fullmatch(value), "%s: uuid is not a v4 or v5 uuid" % where)

    def date(self, value, where):
        self.ok(rfc3339.parse(value) is not None, "%s: not an RFC 3339 date-time" % where)

    def props(self, value, where):
        if not self.ok(isinstance(value, list), "%s: props is not a list" % where):
            return
        for i, p in enumerate(value):
            if self.need(p, ("name", "value"), "%s.props[%d]" % (where, i)):
                self.ok(isinstance(p["name"], str) and TOKEN_RE.fullmatch(p["name"]) and isinstance(p["value"], str),
                        "%s.props[%d]: name must be a token and value a string" % (where, i))


def check(doc):
    """Return (checks_run, errors)."""
    c = Checker()
    if not (c.obj(doc, "document") and c.ok(list(doc) == ["assessment-results"], "document: only key must be assessment-results")):
        return c.n, c.errors
    ar = doc["assessment-results"]
    if not c.need(ar, ("uuid", "metadata", "import-ap", "results"), "assessment-results"):
        return c.n, c.errors
    c.uuid(ar["uuid"], "assessment-results")
    if c.need(ar["metadata"], ("title", "last-modified", "version", "oscal-version"), "metadata"):
        c.date(ar["metadata"]["last-modified"], "metadata.last-modified")
    c.need(ar["import-ap"], ("href",), "import-ap")
    if not c.ok(isinstance(ar["results"], list) and len(ar["results"]) >= 1, "results: need at least one result"):
        return c.n, c.errors
    for ri, res in enumerate(ar["results"]):
        where = "results[%d]" % ri
        if not c.need(res, ("uuid", "title", "description", "start", "reviewed-controls", "observations", "findings"), where):
            continue
        c.uuid(res["uuid"], where)
        c.date(res["start"], where + ".start")
        if "end" in res:
            c.date(res["end"], where + ".end")
        c.props(res.get("props", []), where)
        sel = res["reviewed-controls"].get("control-selections") if isinstance(res["reviewed-controls"], dict) else None
        if c.ok(isinstance(sel, list) and sel, where + ".reviewed-controls: need control-selections"):
            for s in sel:
                for ic in (s.get("include-controls", []) if isinstance(s, dict) else []):
                    c.ok(isinstance(ic, dict) and isinstance(ic.get("control-id"), str) and TOKEN_RE.fullmatch(ic["control-id"]),
                         where + ".reviewed-controls: control-id must be a token")
        known = set()
        for oi, ob in enumerate(res["observations"]):
            w = "%s.observations[%d]" % (where, oi)
            if c.need(ob, ("uuid", "description", "methods", "collected"), w):
                c.uuid(ob["uuid"], w)
                known.add(ob["uuid"])
                c.date(ob["collected"], w + ".collected")
                c.ok(isinstance(ob["methods"], list) and ob["methods"] and set(ob["methods"]) <= METHODS, w + ".methods: need 1+ of EXAMINE, INTERVIEW, TEST")
                c.props(ob.get("props", []), w)
        for fi, fd in enumerate(res["findings"]):
            w = "%s.findings[%d]" % (where, fi)
            if not c.need(fd, ("uuid", "title", "description", "target"), w):
                continue
            c.uuid(fd["uuid"], w)
            c.props(fd.get("props", []), w)
            tg = fd["target"]
            if c.need(tg, ("type", "target-id", "status"), w + ".target"):
                c.ok(tg["type"] in ("statement-id", "objective-id"), w + ".target.type: unknown")
                c.ok(isinstance(tg["target-id"], str) and TOKEN_RE.fullmatch(tg["target-id"]), w + ".target.target-id: not a token")
                if c.need(tg["status"], ("state",), w + ".target.status"):
                    c.ok(tg["status"]["state"] in ("satisfied", "not-satisfied"), w + ".target.status.state: must be satisfied or not-satisfied")
                    c.ok(tg["status"].get("reason", "other") in ("pass", "fail", "other"), w + ".target.status.reason: unknown")
            for ro in fd.get("related-observations", []):
                c.ok(isinstance(ro, dict) and ro.get("observation-uuid") in known, w + ".related-observations: dangling reference")
    c.ok(len(c.uuids) == len(set(map(str, c.uuids))), "uuids: not unique across the document")
    return c.n, c.errors


def trestle(path):
    """Return (line, ok). Runs compliance-trestle only if importable; otherwise says SKIPPED."""
    if importlib.util.find_spec("trestle") is None:
        return "trestle: SKIPPED (not installed)", True
    code = ("import sys, pathlib\n"
            "from trestle.oscal.assessment_results import AssessmentResults\n"
            "AssessmentResults.oscal_read(pathlib.Path(sys.argv[1]))\n")
    proc = subprocess.run([sys.executable, "-c", code, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode == 0:
        return "trestle: PASS", True
    return "trestle: FAIL (%s)" % (proc.stderr.strip().splitlines() or ["no detail"])[-1][:120], False
