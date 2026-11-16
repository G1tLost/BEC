# Exact saved-case indicator search

```text
bec search CASE_DIR TYPE VALUE [--format json|html] [--output FILE]
```

Search reads one saved tenant-bound case directory containing `case.json`. JSON goes to stdout by default; HTML is an inert standalone report. Explicit report files must be new and outside the source case. `--root` is not used. Quote shell-sensitive URL values, especially those containing `&` or `#`.

This is a local lookup, separate from `pivot ip|user`, which can collect data and save analyst seeds. Search makes no provider calls, follows no URLs, creates no query jobs, changes no case state, and does not expand to related messages or other accounts. Only directly matching structured values produce hits.

## Types and structured fields

The result's `searched_fields` identifies the exact normalized field paths and match relations. Array matches include their concrete element indexes.

| Type | Searched fields | Exact matching behavior |
| --- | --- | --- |
| `email` | `entities.user[*]`, `entities.mailbox[*]` | Simple email/UPN identity equality using BEC's case-insensitive convention; DNS domain case/IDNA/root-dot normalization. No display-name or quoted-local-part parsing. |
| `domain` | Domain portions of `entities.user[*]` and `entities.mailbox[*]` | `email_domain_equals`: exact domain, not a substring or subdomain. |
| `domain` | Hosts of `entities.url[*]`, `defender.Url`, `defender.RemoteUrl` | `url_host_equals`: exact parsed HTTP(S) host; no network resolution. |
| `domain` | `defender.UrlDomain` | `domain_field_equals`: exact explicitly recorded domain. |
| `ip` | `entities.ip[*]` | Parsed IPv4/IPv6 address equality. Equivalent IPv6 spellings match. CIDR ranges, zone IDs, prefixes, and hostnames are not accepted as query values. |
| `url` | `entities.url[*]`, `defender.Url`, `defender.RemoteUrl` | `url_literal_equals`: complete case-sensitive HTTP(S) URL string equality, retaining path, query, percent encoding, and fragment. |
| `sha256`, `sha1` | `entities.sha256[*]`, `entities.sha1[*]` | Exactly 64 or 40 hexadecimal characters, respectively; hexadecimal case is ignored. These are normalized Defender attachment/evidence hash values. |

Domain values are lowercased, converted through IDNA when needed, and may have one trailing DNS root dot. `example.com` does not match `notexample.com`, `sub.example.com`, or `example.com.attacker.test`. Wildcards are refused. An IP-literal URL host is not treated as a DNS domain; `ip` searches only the listed normalized IP fields.

URL matching is deliberately literal: `https://EXAMPLE.com/a?x=1`, `https://example.com/a?x=1`, and `https://example.com/a?x=10` are different query values. No percent-decoding, default-port/path rewriting, query sorting, Safe Links expansion, or DNS/network access occurs. Use a domain search when exact host identity is the intended question. URLs are displayed as text in HTML; only preserved local evidence receives hyperlinks.

Subjects, message bodies, filenames, arbitrary raw strings, nested URL chains, and binary attachment contents are not searched. A hash query does not scan files or compare the raw evidence manifest's own SHA-256 values. Those artifact hashes are provenance, separate from the searched attachment/evidence hashes. Unsupported types such as MD5 or arbitrary regex are not available.

## Evidence and counting

Search first uses the read-only saved-case verifier: metadata/manifest identity, expected artifact paths, original raw hashes and record counts, raw inventory, and native Microsoft directory/Workspace customer markers must agree. Pending acquisitions are refused without recovery. Raw hashes and watched metadata are checked again after processing; detected changes cause failure. Use quiescent saved cases. The command neither creates case lock files nor calls a recovery/report-rebuilding path.

Existing tenant binding limitations remain explicit. For Microsoft exports with no directory ID in the case, the report identifies reliance on the analyst-supplied tenant alias. Native IDs present in evidence still must match the case's configured native binding. The manifest is the integrity trust anchor; it is not protection against an administrator who rewrites both evidence and hashes.

The search reconstructs normalized fields from verified raw records, not from derived timelines or a text scan. Supported whole-row JSON and UAL transport wrappers are canonicalized in memory. It retains all original bytes and references. All preserved rows are examined, including baseline and evidence outside the incident timeline's reachability scope.

`matched_records` counts distinct canonical raw-record content. Identical duplicates across pages or export wrappers produce one record hit with all source references retained. Different content sharing a native event ID remains separate record variants. `matched_observations` counts matching normalized events; one Google activity can contain several child events. Multiple matching fields in the same event do not inflate that count. `source_references` counts the matched records' original row occurrences, not field matches or Google child repetitions.

Each matched observation includes its event type/time, normalized actor/target, native source event ID, and a list of exact matched field/value/relation pairs. Its evidence references carry the case directory, relative artifact path, local-file URI, artifact SHA-256, zero-based record index, and Google child-event index when applicable. Keep source cases at those paths for HTML evidence links to work. Search reports contain case/account/path information and should be protected as case material.

## Coverage and no-hit interpretation

The report includes original source query statuses/reasons and observed ranges from the case snapshot. Its additional `field_coverage` is per dataset and records:

- Unique raw records examined and normalized observations produced.
- Candidate field values that could be interpreted as the requested type.
- Records containing at least one searchable value.
- Invalid candidate values skipped and normalization issues.

Candidate-value counts can include the same value in several normalized fields; they are coverage diagnostics, not unique hit counts. Empty or unsupported fields, missing datasets, incomplete permissions, parse failures, provider retention, and absent collection windows can all explain no hits. A no-hit report always preserves those limitations and does not establish that the indicator is absent from the tenant. A metadata match does not demonstrate compromise, delivery, interaction, or execution.

The verifier's bounds apply: at most the case's configured `max_events` or 1,000,000 raw rows, whichever is smaller; 128 MiB per input file and 512 MiB raw evidence per case. Excess inputs fail rather than silently truncate results. Reports are built in memory.

Successful searches return `0`, including zero-hit results and visible source-coverage gaps. Invalid indicators, binding/integrity failures, changing inputs, or unsafe output paths return `1`. Argument errors return `2`; interruption returns `130`. An integrity failure is never converted into an empty successful result.
