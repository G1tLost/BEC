# BEC prerequisites by purpose

BEC requires **Python 3.12 or newer**. Use a dedicated virtual environment; do not modify a system or another tool's environment. These commands assume a shell in this BEC checkout. Check the displayed interpreter version before continuing.

## Windows PowerShell

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m bec --version
.\.venv\Scripts\python.exe -m bec --help
.\.venv\Scripts\python.exe -m bec --root "$env:TEMP\bec-offline-demo" demo
```

`py -3` must select Python 3.12+. If it selects an older installed version, explicitly select an installed supported version, for example `py -3.14`. Python installation itself is outside this guide's commands. No PowerShell activation or execution-policy change is needed.

## macOS or Linux

```sh
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m bec --version
.venv/bin/python -m bec --help
.venv/bin/python -m bec --root /tmp/bec-offline-demo demo
```

`python3` must resolve to Python 3.12+. Select an explicit supported installed interpreter if the system Python is older. Some Linux distributions package venv support separately; use your organization's approved runtime setup rather than bypassing package protections. No activation, root privileges, global pip install or policy changes are needed. Package installation may download build requirements and declared dependencies; the demo itself stays offline.

## Offline snapshots, exports, comparison and search

The base package supports these operations without authentication SDKs or credentials. In this local draft, the snapshot companion accepts the contract documented in [mailbox-state](mailbox-state.md):

```sh
.venv/bin/python -m bec snapshot-import /path/to/bound-case /path/to/export.json --output /path/to/new-companion
.venv/bin/python -m bec snapshot-view /path/to/bound-case /path/to/new-companion
```

On Windows substitute `.\.venv\Scripts\python.exe` and Windows paths. The existing case must bind the exact native Microsoft directory GUID and lowercase mailbox UPN. The default demo is unbound and therefore intentionally cannot receive snapshots. For synthetic QA, create a separate profile containing a synthetic tenant alias, directory GUID and client GUID, then create a case with matching UPN and explicit UTC interval. Case creation is local; do not invoke live `collect`/`investigate` against placeholder identifiers. `snapshot-import` writes only a new companion directory, and `snapshot-view` prints JSON without changing the saved case. Retain both directories.

## Optional live acquisition

Only after authorized live scope and provider access are established, install optional authentication libraries in the same environment:

```powershell
.\.venv\Scripts\python.exe -m pip install ".[live]"
```

```sh
.venv/bin/python -m pip install '.[live]'
```

Installing SDKs does not grant access or authorize collection. Microsoft acquisition requires an explicitly bound tenant/application profile, approved application permissions and certificate or secret-based credentials. Google acquisition uses the native Admin SDK Reports API with approved domain-wide delegation and read-only reporting scope, a service-account credential and an authorized reporting administrator. Provisioning/consent is a separate administrative action, not performed by this guide. Keep credentials and real cases outside the checkout. Follow [security and permissions](security.md), [Workspace setup](workspace.md) and the bounded [lab acceptance procedure](lab-validation.md). Do not reuse arbitrary cached credentials or interpret successful offline tests as live acceptance.

GAM is **not** an implementation dependency: BEC currently calls Google Reports directly. GAM mappings and on-premises AD adapters remain planned, not installed or enabled here. BEC does not require PowerShell, ExchangeOnlineManagement or a sibling toolkit for its native Python workflows.

## Offline tests

The full suite imports optional SDK exception types even though provider exchanges are mocked. Install `.[live]` first, then from the checkout run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_mailbox_state.py -v
```

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s tests -p test_mailbox_state.py -v
```

No credentials, real tenant or GAM/AD installation is required. Tests use temporary synthetic evidence. Validate installed-package behavior separately from checkout imports. Platform-specific installation and live behavior must be tested on their actual platform; this guide's local review does not claim Windows/Linux installation acceptance.
