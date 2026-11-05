# Control mapping

A mapping, not an attestation or audit opinion.

The example map is `examples/control-map.tsv`. Control ids and titles come from NIST SP 800-53 Rev 5
and the NIST AI RMF 1.0 core. The assignment of an example gate to a control is the author's
judgment (label: INFERRED). It is a starting point for an assessor, who may accept, narrow or reject
each row. The gate names are generic examples, not a product's checks.

Map file format: tab separated, header `framework	control_id	gate	title` (title optional).
Frameworks accepted: `NIST-800-53r5` (ids like `CM-3`, `SI-7(2)`) and `NIST-AI-RMF`
(ids like `MEASURE 2.5`). Anything else is rejected with exit 2. A control may list several gates;
it is satisfied only when all of them have a fresh passing receipt.

OSCAL target ids are the lowercased map ids (`cm-3`, `si-7.2`, `measure-2.5`). They are not resolved
against an OSCAL catalog; `reviewed-controls` lists the same ids.

| Control | Gate in the example | What a passing receipt can support | What it does not show |
| --- | --- | --- | --- |
| SP 800-53 CM-3 Configuration Change Control | config-change-review | A change-review check ran and passed against a stated commit | That every change went through review, or that the reviewers were the right people |
| SP 800-53 SI-7 Software, Firmware, and Information Integrity | artifact-hash-verify | Artifact hashes matched an expected list at the stated time | That the expected list was trustworthy, or that integrity is checked at runtime |
| SP 800-53 SA-11 Developer Testing and Evaluation | unit-tests, eval-regression | Both test gates passed against the stated commit | Test quality or coverage |
| SP 800-53 AU-10 Non-repudiation | signed-commit-check | Commits in range carried valid signatures | Non-repudiation as a property of the whole system; a signed commit is one input |
| SP 800-53 RA-5 Vulnerability Monitoring and Scanning | dependency-scan | A dependency scan ran and exited 0 | Scan coverage, finding triage, or remediation timelines |
| AI RMF MEASURE 2.1 | eval-set-manifest | An evaluation-set manifest check passed (test sets, metrics and tools are recorded) | That the sets are representative |
| AI RMF MEASURE 2.5 | eval-regression | A validity and reliability regression suite passed | That the system is valid or reliable in deployment conditions |
| AI RMF MEASURE 2.7 | adversarial-eval | An adversarial evaluation ran and passed | The breadth of the attack set, or resilience beyond what was tested |

The example data is synthetic. `eval-set-manifest` has no receipt on purpose, so MEASURE 2.1 shows
`not-assessed`. `dependency-scan` returns rc 1 on purpose (RA-5 `not-satisfied`, reason `rc-nonzero`).
`adversarial-eval` is dated 16 days before the assessment time (MEASURE 2.7 `not-satisfied`, reason
`stale`).

## Adding a control

1. Add rows to the map. Use ids you have checked against the framework text.
2. Make the gate write a receipt with the same `gate` name.
3. Run `bin/receipts-to-oscal` and read the finding. A control stays `not-assessed` until a receipt
   exists.
