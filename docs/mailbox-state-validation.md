# Local mailbox-state draft validation

Base: `07c4593215d11db0e8d2ebc57e2797e000c85e12` (BEC v0.8.0). No remote write or live collection.

Platform: TheBox, macOS, existing Python 3.14 runtime. An isolated temporary virtual environment contains this local package and its declared optional test SDKs. No runtime was replaced.

- Focused tests: 11 passed.
- Complete offline regression suite: 88 passed (77 upstream + 11 new).
- Rebuilt installed package, isolated upstream `scripts/installed_smoke.py`: passed demo, verification, comparisons and exact searches, with unchanged source cases.
- Isolated installed-package mailbox-state suite from outside checkout: 10 passed before the window-filter follow-up; final 11-test source suite and 88-test regression suite passed. The follow-up has not been reinstalled.
- `git diff --check`: passed.
- Original BEC artwork copied byte-for-byte; SHA256 `4c21412db376f33fdc273b2d354e38f4a11baf5f160071957c54c1657732243e` matches supplied asset.

Tests exercise exact bytes/BOM/hash preservation, source/index pointers, unchanged case bytes and modification times, native tenant/mailbox binding, unbound real/synthetic rejection, malformed coverage and duplicate keys, output protection, tampering, opaque delegate wrappers, separate historical/current rule semantics and CLI paths with collection forbidden.

No live provider, GAM, AD, Windows/Linux acceptance or production-case validation was performed. Full regression tests mock provider exchanges. Hashes establish post-import preservation, not source authenticity. Current snapshots remain companion artifacts, not integrated into standard case replay/report/search. Provider or legacy-source code was not copied from another repository.

Follow-up review: snapshot SHA-256 computed once per view and reused for all record pointers. Historical observations now use exact [case start,case end) bounds; a new regression covers start inclusion, end exclusion, baseline exclusion and an explicit unparseable-UAL count.
