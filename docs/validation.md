# Validation record

Status for standalone BEC v0.6.0, 2026-11-16:

| Check | Result |
| --- | --- |
| Full suite in the existing development test environment (`work/testenv`) | Passed: 40 tests, including 38 retained email tests and two standalone CLI checks. |
| Base wheel installed into a clean environment, demo run outside the source checkout | Passed: 30 incident events, zero telemetry gaps, and successful raw evidence verification. Optional authentication libraries were not required. |
| Full suite in that clean environment | Passed: 40 tests after installing the documented `live` extra. Python 3.14.7 on Windows; no sibling project was installed. |
| Live Microsoft 365, Defender, and Google tenant access | Not tested in this validation. |

The full suite uses synthetic fixtures and mocked provider exchanges. Install `.[live]` before running it because provider transport tests import optional SDK types; no live credentials are needed. This prerequisite does not apply to the base demo or export-only investigations.

The installed-wheel smoke test uses Python isolated mode from a temporary working directory, so source-checkout imports cannot supply missing package files. Each GitHub CI job installs and tests only this repository. Offline results do not establish live authentication, permissions, licensing, retention, or provider availability.
