# receipts-to-oscal

Proves: gate receipts become an OSCAL 1.1.x assessment-results document with a hash chain over the evidence, and the verifier exits 1 on any tamper. Verify in 60s: `bash check.sh`.

Turns the receipts your automated gates already write (gate name, exit code, timestamp, commit sha)
into an OSCAL 1.1.x assessment-results document, with a hash chain over the evidence and a verifier
that exits 1 on any tamper. Python 3 standard library and bash only. Nothing to install.

This is a mapping, not an attestation or audit opinion. It records what gate receipts say and which
controls they are mapped to. It does not say a control is implemented, effective or compliant.

## The problem

Evidence for continuous compliance is usually collected by hand: a screenshot of a green pipeline, a
spreadsheet row, a pasted log. Screenshots rot, nobody can re-derive them, and an auditor cannot tell
a current result from a six-month-old one. The gates already exist and already return an exit code.
What is missing is a small, boring, checkable step between "the gate ran" and "the control has
evidence": the receipt, its age, its hash, and a machine-readable statement of which controls it
supports and which have nothing.

## What it proves

1. Every control in the map gets exactly one finding, derived from receipts only:
   `satisfied`, `not-satisfied` or `not-assessed`.
2. A control with no receipt is `not-assessed`. It is never reported as satisfied.
3. A failing receipt (rc not 0), a receipt older than the stated maximum age, or a receipt dated in
   the future is `not-satisfied`, with the reason in the finding.
4. Malformed receipts, an empty receipts directory and a bad control map stop the run with exit 2 and
   no document. "0 receipts" is never a pass.
5. Each observation carries the sha256 of the receipt bytes. The observations form a hash chain and a
   head hash covers the findings and metadata, so editing any field, reordering or deleting an
   observation changes a hash. `bin/oscal-verify` recomputes it: exit 0 intact, exit 1 otherwise.
6. The output is deterministic. The same receipts, map and `--now` give byte-identical JSON, so an
   auditor can regenerate it and compare.

What it does not prove is in [docs/LIMITS.md](docs/LIMITS.md) and summarised below.

## The one command

```
./check.sh          # needs python3 and a POSIX shell
```

Expected output (the timing line varies):

```
selftest convert: 91/91
selftest verify: 50/50
selftest validate: 48/48
selftest golden: 6/6
selftest hygiene: 5/5
trestle: SKIPPED (not installed)
mutants 24/24 killed
check wall: ... ms
CHECK: GREEN (6 steps)
```

If `compliance-trestle` is importable, the `trestle:` line reads `trestle: PASS` or `trestle: FAIL (...)`.
It is never reported as valid when it did not run. Any red step prints `RED: <step>` and exits nonzero.
The fixtures include the failure cases: missing receipt, stale receipt, rc not 0, future timestamp,
malformed receipts (nine shapes plus binary), empty receipts directory, bad control maps, and a dozen
tampered documents.

## Using it

```
bin/receipts-to-oscal RECEIPTS_DIR CONTROL_MAP [--now RFC3339] [--max-age-hours 168] [--require-all] [-o FILE]
bin/oscal-verify FILE [--receipts RECEIPTS_DIR]
bin/oscal-validate FILE
```

A receipt is one file with four fields, in any one of three shapes (see `examples/receipts/`):
a single JSON object, a TSV header plus one row, or `key=value` lines. Fields: `gate` (name), `rc`
(integer), `ts` (RFC 3339), `sha` (lowercase hex of the commit or artifact the gate ran against).
Dotfiles and subdirectories in the receipts directory are ignored.

`--require-all` makes the tool exit 1 unless every control is satisfied, for use as a CI gate.
Exit codes of `receipts-to-oscal`: 0 report written, 1 `--require-all` and a gap, 2 bad input, 3 the
tool's own output failed its structural check.

Real output on the bundled example (assessed at `2026-11-05T00:00:00Z`, 7 receipts, 8 controls):

```
$ bin/receipts-to-oscal examples/receipts examples/control-map.tsv --now 2026-11-05T00:00:00Z -o out.json
satisfied     NIST-800-53r5  CM-3         ok
satisfied     NIST-800-53r5  SI-7         ok
satisfied     NIST-800-53r5  SA-11        ok
satisfied     NIST-800-53r5  AU-10        ok
not-satisfied NIST-800-53r5  RA-5         rc-nonzero
not-assessed  NIST-AI-RMF    MEASURE 2.1  no-receipt
satisfied     NIST-AI-RMF    MEASURE 2.5  ok
not-satisfied NIST-AI-RMF    MEASURE 2.7  stale
receipts: 7, controls: 8: satisfied 5, not-satisfied 2, not-assessed 1

$ bin/oscal-verify out.json --receipts examples/receipts
chain: 7/7 links verify
head: ok
oscal-verify: intact

$ bin/oscal-validate out.json
structural: 590/590 checks pass
trestle: SKIPPED (not installed)
```

Flip every `not-satisfied` to `satisfied` in a copy and verify it:

```
$ sed 's/"not-satisfied"/"satisfied"/' out.json > forged.json
$ bin/oscal-verify forged.json
chain: 7/7 links verify
TAMPER head: chain-head does not match the document
oscal-verify: FAIL            (exit 1)
```

## How an auditor reproduces it in 2 minutes

1. Read the three inputs: `examples/receipts/`, `examples/control-map.tsv`, and the assessment time in
   the document (`assessed-at` and `max-age-hours` in the result props).
2. Regenerate and compare. A match means the findings follow from the receipts and the map:
   ```
   bin/receipts-to-oscal examples/receipts examples/control-map.tsv --now 2026-11-05T00:00:00Z \
     | cmp - examples/out/assessment-results.json && echo identical
   ```
3. Rehash the evidence: `bin/oscal-verify examples/out/assessment-results.json --receipts examples/receipts`.
   Change one byte in any receipt first and watch it fail.
4. Run `./check.sh` to see the planted failures go red and the mutation harness kill 24 of 24 breakages.

## Control mapping

The example map (`examples/control-map.tsv`) uses these controls. Full rationale and the "does not
show" column are in [docs/CONTROL-MAPPING.md](docs/CONTROL-MAPPING.md). Control ids and titles are
from NIST SP 800-53 Rev 5 and the NIST AI RMF 1.0 core. Which gate supports which control is the
author's judgment, for an assessor to accept or change. A mapping, not an attestation or audit opinion.

| Framework | Control | Example gate |
| --- | --- | --- |
| NIST SP 800-53 Rev 5 | CM-3 Configuration Change Control | config-change-review |
| NIST SP 800-53 Rev 5 | SI-7 Software, Firmware, and Information Integrity | artifact-hash-verify |
| NIST SP 800-53 Rev 5 | SA-11 Developer Testing and Evaluation | unit-tests and eval-regression |
| NIST SP 800-53 Rev 5 | AU-10 Non-repudiation | signed-commit-check |
| NIST SP 800-53 Rev 5 | RA-5 Vulnerability Monitoring and Scanning | dependency-scan |
| NIST AI RMF 1.0 | MEASURE 2.1 | eval-set-manifest |
| NIST AI RMF 1.0 | MEASURE 2.5 | eval-regression |
| NIST AI RMF 1.0 | MEASURE 2.7 | adversarial-eval |

A control with several gates is satisfied only when every one of its gates has a fresh passing
receipt. A failure outranks a gap: one failing gate makes the control `not-satisfied` even if
another gate has no receipt.

## Threat model and limits

In scope: someone edits the OSCAL file after generation, edits or swaps a receipt, drops or reorders
observations, reports a gap as a pass, or leaves a stale or failing result looking current.

Not in scope, and not proven:

- **Authenticity.** The chain is integrity only. Nothing is signed. Someone who can write the file
  and recompute every hash produces a document that verifies. The test suite demonstrates this and
  shows that regeneration from the receipts still exposes it. Publish the `chain-head` somewhere the
  forger cannot write (a signed commit, a CI log, a ticket) to anchor it.
- **That a receipt is true.** A receipt is a text file. Anything that can write the receipts
  directory can write a passing one. The tool checks the receipt's shape, age and exit code.
- **That the gate tests the right thing.** `rc=0` from a gate that always exits 0 proves nothing.
- **Control implementation or effectiveness.** One passing gate does not mean a control is
  implemented. Mapping gates to controls is a judgment that this repo does not make for you.
- **Schema validity.** The stdlib validator checks the fields this tool emits. It is not the OSCAL
  JSON schema. Run the official tooling for that.
- **Not-assessed is encoded conservatively.** OSCAL's objective status has only `satisfied` and
  `not-satisfied`, so `not-assessed` is emitted as `not-satisfied` with reason `other`, plus the
  precise value in the `assessment-status` prop. Consumers that read only `state` see a gap as
  not satisfied, never as a pass.

## Design decisions

- **Fail closed on input, report on gaps.** A malformed receipt or an empty directory stops the run
  (exit 2) because a partial report would look like a clean one. A missing receipt for a mapped
  control is a normal finding (`not-assessed`), because that is the report's job.
- **Findings come from receipts and the map only.** No model, no network, no clock except `--now`.
  The same inputs always give the same bytes, which is what makes regeneration a check.
- **Head hash covers the whole document.** Chaining only the observations would leave the findings
  editable. The head covers the last link plus everything else, so flipping a status is caught.
- **Newest receipt per gate decides.** Older receipts stay in the document as observations, so history
  is visible but cannot rescue a current failure or fail a current pass.
- **uuid5 from content.** Identifiers are stable across runs, so the output diffs cleanly in CI.
- **Optional trestle.** The hook calls `AssessmentResults.oscal_read` from compliance-trestle. It is
  tested here with a stand-in package, not against a real install.
  Unverified against the real package until someone runs it with trestle present.
- **Mutation harness.** `tests/mutants.py` breaks the code 24 ways in a throwaway copy (for example,
  gap counted as satisfied, stale check removed, head ignoring findings, validator exiting 0 on
  failure) and requires a selftest to fail for each. A mutation that changes nothing counts as
  survived, and an unmutated control copy must pass first.

## Layout

```
bin/receipts-to-oscal  bin/oscal-verify  bin/oscal-validate
lib/receipts.py  lib/oscal_build.py  lib/chain.py  lib/oscal_check.py  lib/rfc3339.py
examples/control-map.tsv  examples/receipts/  examples/out/assessment-results.json
tests/selftest_{convert,verify,validate}.py  tests/golden.py  tests/hygiene.py  tests/mutants.py
docs/CONTROL-MAPPING.md  docs/LIMITS.md  check.py  check.sh  .github/workflows/ci.yml
```

CI runs `./check.sh` on every push with read-only permissions and a pinned checkout action.
