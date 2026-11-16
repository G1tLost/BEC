# Validation record

Status for standalone BEC v0.7.0, 2026-11-16:

| Check | Result |
| --- | --- |
| Full suite in the BEC development environment (`work/standalone-envs/BEC`) | Passed: 53 tests, including the 40-test v0.6.0 baseline and 13 saved-case comparison tests. |
| v0.7.0 installed-package smoke test in that development environment | Passed in Python isolated mode outside the checkout: synthetic demo/verification, equivalent-case comparison, one source-linked added sign-in, HTML output, and unchanged source-case hashes. This environment already contains the optional SDK libraries. |
| Fresh v0.7.0 base wheel/environment acceptance | Passed on Windows/Python 3.14.7: the installed smoke exercised the demo, zero-delta and added-evidence comparisons, HTML output and unchanged inputs before optional provider SDKs were installed. |
| Full suite against the fresh installed wheel | Passed: 53 tests using Python isolated mode after installing the wheel's `live` extra. Neither sibling tool was installed; the package resolved from the new environment's `site-packages`. |
| Live Microsoft 365, Defender, and Google tenant access | Not tested in this validation. |

Comparison regressions cover reordered rows and duplicate copies; equivalent whole-row/UAL JSON transport wrappers; sign-in, rule, and OAuth additions with resolvable evidence pointers; same-native-ID variants; window and coverage differences; tenant/native-binding refusals; malformed metadata; missing/tampered/unmanifested evidence; pending and concurrently changing inputs; output placement/overwrite guards; escaped HTML; and processing budgets. Tests verify that comparison leaves source file bytes and modification times unchanged.

The previous v0.6.0 release passed 40 tests in a fresh Windows environment with the `live` extra, and its base wheel demo produced 30 incident events with zero gaps and successful raw verification without optional authentication libraries. Those are historical baseline results, not a replacement for v0.7.0 acceptance.

The full suite uses synthetic fixtures and mocked provider exchanges. Install `.[live]` before running it because provider transport tests import optional SDK types; no live credentials are needed. This prerequisite does not apply to the base demo or export-only investigations.

The installed-wheel smoke test uses Python isolated mode from a temporary working directory, so source-checkout imports cannot supply missing package files. Each GitHub CI job installs and tests only this repository. Offline results do not establish live authentication, permissions, licensing, retention, or provider availability.
