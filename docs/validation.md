# Validation record

Status for standalone BEC v0.7.0, 2026-11-16:

| Check | Result |
| --- | --- |
| Full suite in the BEC development environment (`work/standalone-envs/BEC`) | Passed: 53 tests, including the 40-test v0.6.0 baseline and 13 saved-case comparison tests. |
| v0.7.0 installed-package smoke test in that development environment | Passed in Python isolated mode outside the checkout: synthetic demo/verification, equivalent-case comparison, one source-linked added sign-in, HTML output, and unchanged source-case hashes. This environment already contains the optional SDK libraries. |
| Fresh v0.7.0 base wheel/environment acceptance | Passed on Windows/Python 3.14.7: the installed smoke exercised the demo, zero-delta and added-evidence comparisons, HTML output and unchanged inputs before optional provider SDKs were installed. |
| Full suite against the fresh installed wheel | Passed: 53 tests using Python isolated mode after installing the wheel's `live` extra. Neither sibling tool was installed; the package resolved from the new environment's `site-packages`. |
| Live Microsoft 365, Defender, and Google tenant access | Not tested in this validation. |

## E2 lab preparation

**Live E2 validation is not executed.** No explicit lab tenant/profile, account list, independently known native event IDs, or completed activity window has been supplied. No provider calls, permission changes, or activity generation were performed for this preparation.

The repository now includes `scripts/validate_lab.py` and the [bounded lab procedure](lab-validation.md). Its preflight previews existing primary-user queries without provider access. A subsequent authorized run uses the installed BEC collector, verifies captured raw evidence and known events, checks query limits, and records pagination and permission-failure evidence only when actually observed. Actual cases, plans, command records, and detailed results stay private; public status uses a fixed field allowlist.

The complete source suite passed **64 offline tests** in the BEC development environment (`work/milestone2-envs/BEC`): the 53-test product baseline plus 11 lab-checker tests. These tests reject exported/demo fixture evidence and missing execution receipts as live qualification, keep absent pagination/restricted-access gates untested, check expected-event mismatches and integrity failures, and verify that public status excludes private identifiers and paths. Synthetic checker tests are not an E2 live run.

The packaged command behavior remains v0.7.0; this addition is repository lab-support tooling. Live provider gates remain unrun until the user supplies the exact target and expected observations.

The publishing coordinator independently built a wheel and installed it in a new BEC-only Windows virtual environment using Python 3.14.7. The base installed smoke passed before optional authentication libraries were installed. After installing that wheel's `live` extra, all **64 tests passed with Python isolated mode**. The lab support script remains in the repository; tested product imports came from the installed wheel. These checks used no provider credentials or live tenant access.

Comparison regressions cover reordered rows and duplicate copies; equivalent whole-row/UAL JSON transport wrappers; sign-in, rule, and OAuth additions with resolvable evidence pointers; same-native-ID variants; window and coverage differences; tenant/native-binding refusals; malformed metadata; missing/tampered/unmanifested evidence; pending and concurrently changing inputs; output placement/overwrite guards; escaped HTML; and processing budgets. Tests verify that comparison leaves source file bytes and modification times unchanged.

The previous v0.6.0 release passed 40 tests in a fresh Windows environment with the `live` extra, and its base wheel demo produced 30 incident events with zero gaps and successful raw verification without optional authentication libraries. Those are historical baseline results, not a replacement for v0.7.0 acceptance.

The full suite uses synthetic fixtures and mocked provider exchanges. Install `.[live]` before running it because provider transport tests import optional SDK types; no live credentials are needed. This prerequisite does not apply to the base demo or export-only investigations.

The installed-wheel smoke test uses Python isolated mode from a temporary working directory, so source-checkout imports cannot supply missing package files. Each GitHub CI job installs and tests only this repository. Offline results do not establish live authentication, permissions, licensing, retention, or provider availability.
