# Limits

What this repo does not prove. Each line is also covered, where it can be, by a test.

## Integrity is not authenticity

- The hash chain detects edits to a document that was produced honestly. It does not sign anything.
  An actor who can rewrite the file can recompute all hashes and the document will verify.
  `tests/selftest_verify.py` forges one and asserts that verification passes (the limit) and that
  regeneration from the receipts differs from the forgery (the mitigation).
- Mitigation: record the `chain-head` value outside the writable area (signed commit, CI log,
  ticket), and regenerate from the receipts as in the README.
- `oscal-verify --receipts` rehashes receipt files, so a receipt edited after the fact is caught. It
  cannot tell whether the receipt was true when written.

## Receipts are claims by whatever wrote them

- A receipt is a text file with four fields. Shape, age and exit code are checked. Truth is not.
- The `sha` field is checked for form only. Nothing here confirms it names the commit the gate really
  ran against.
- Timestamps are taken from the receipt. A receipt dated inside the allowed window can be written
  now. A receipt more than 5 minutes ahead of the assessment time is treated as not-satisfied.

## Gate quality

- `rc=0` from a gate that cannot fail proves nothing. The tool cannot see inside the gate.
- A stale window of 168 hours is a default, not a policy. Choose it per control family and state it.
- The newest receipt per gate decides. A flaky gate that passed once after failing ten times reads as
  satisfied.

## Scope of the claims

- One passing gate does not show a control is implemented or effective.
- The gate-to-control map is a judgment. See `docs/CONTROL-MAPPING.md`.
- Not-assessed covers "no receipt", not "not applicable". There is no waiver or exception mechanism.
- No NIST or other standards body has reviewed this. Control titles are paraphrased from the public
  frameworks and are not quoted requirement text.

## OSCAL fidelity

- The structural validator checks the fields this tool emits: required keys, uuid shape (v4 or v5),
  RFC 3339 dates, enumerations, and reference integrity. It is not the OSCAL JSON schema.
- `compliance-trestle` is used only if importable. The call path (`AssessmentResults.oscal_read`) is
  exercised here against a stand-in package, not a real install.
- `import-ap` is a placeholder href because no assessment plan exists. A strict consumer that
  resolves it will find nothing.
- OSCAL objective status has only `satisfied` and `not-satisfied`. `not-assessed` is carried as
  `not-satisfied` plus the `assessment-status` prop. Target ids are not resolved against a catalog.

## Harness

- The mutation harness covers 24 deliberate breakages. A defect outside those shapes is not covered.
- Tests were run with Python 3.11. The code avoids newer syntax, but older versions were not run.
- Symlinks in the receipts directory are followed. The tool does not sandbox the directory.
