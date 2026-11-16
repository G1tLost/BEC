# Saved-case comparison

`bec compare BEFORE_DIR AFTER_DIR [--format json|html] [--output FILE]` compares two saved case directories. The first input is the analyst-selected earlier observation; BEC does not infer their chronological order from case creation dates. The default output is JSON on stdout. HTML is a standalone, script-free report with local links to preserved evidence. Explicit output files must not already exist and must be outside both cases. Global `--root` is not used by this command.

## Evidence and identity

Comparison reads original raw artifacts and their manifests. It checks case/manifest identity, expected artifact paths, SHA-256 hashes, record counts, raw inventory, and native tenant/customer markers. A pending acquisition journal is refused rather than recovered. Relevant metadata and raw-file hashes are checked again before the result is returned; detected concurrent changes cause failure. Compare quiescent saved cases: this command does not create case locks, recover transactions, rebuild reports, or write inside either case.

The raw manifest remains the integrity trust anchor. An administrator able to rewrite both evidence and its manifest can defeat that check; retain a protected manifest or original snapshot in the evidence system.

Each record fingerprint covers the dataset and the complete parsed raw row, including fields not currently mapped by the normalizer. Supported transport wrappers are decoded before fingerprinting: a whole-row JSON object string and a JSON object string in UAL `AuditData` or `auditData`. Equivalent objects and these encoded forms compare equally. Object key ordering, record ordering, and page boundaries do not affect fingerprints. Identical rows collapse into one observation with every source pointer retained. Other string fields, nested array order, and record values remain significant; arbitrary semantically similar provider exports are not assumed identical. The original evidence bytes and pointers are never rewritten.

The comparison reads all preserved rows, including historical baselines and unrelated/out-of-window records retained by an export. It does not apply the analysis graph's reachability filter. Each item contains normalized descriptive observations when available, plus parsing issues when a child cannot be normalized. These descriptions do not replace the linked original row. Google activity rows can describe several child events; their descriptions retain the child-event index.

Native identity conflicts are explicit:

- Entra and directory records use their native `id`; Exchange unified audit uses `Id` in its audit body, falling back to the outer `id`.
- Message trace identity also includes the recipient, because one native message ID can belong to several recipients.
- Workspace activity identity uses its native activity `id` object when `uniqueQualifier` is populated.
- Defender rows and records without a usable native identity use their complete content. Defender report/alert IDs can refer to several observations, so the tool does not claim that those IDs alone identify a conflicting row. Different content remains visible in the additions/earlier-only lists.

Different content with one recognized native identity is retained as separate variants, even when both variants exist inside a single case. A conflict is not automatically a provider correction or evidence tampering. The report marks whether the set of variants changed across inputs; an unchanged pre-existing conflict remains visible.

## Coverage and interpretation

The JSON report has `format_version: 1` and contains:

| Field | Meaning |
| --- | --- |
| `before`, `after` | Case identities, paths, bindings, context, record counts, duplicates, and per-dataset coverage. |
| `newly_observed` | Fingerprints present only in the later input. This does not prove when the activity first became available. |
| `only_in_earlier` | Fingerprints absent from the later input. This never establishes deletion, revocation, containment, or remediation. |
| `identity_conflicts` | Native identities with multiple content variants; both sides preserve every variant and source pointer. |
| `context_changes` | Incident windows, primary users, provider settings, investigation options, analyst pivots, and recorded collection mode/summary availability. |
| `coverage_changes` | Observed time ranges, unique/duplicate counts, parsing issues, and recorded query scopes/status/reasons. |

Evidence pointers provide `case_directory`, relative `file`, local-file `uri`, SHA-256, and zero-based `record_index`. Source files must remain available at those locations for HTML links to work. Reports contain potentially sensitive account, query, and filesystem information, so protect them as case material.

Coverage is reconstructed from raw observations, acquisition query metadata, and the saved collection summary. Derived timelines and `telemetry_gaps.json` are not treated as authoritative inputs. Empty source results, missing summaries, permission gaps, differing windows, and late provider ingestion limit interpretation. Matching coverage summaries do not prove either collection is complete. Reordered duplicates may change occurrence counts without any evidence delta.

The tenant alias and native Microsoft directory/Workspace customer bindings must match exactly after GUID normalization. A native binding present in only one input also causes refusal. Microsoft cases with no directory binding on either side rely on the same analyst-supplied alias, and the report states this weaker assurance. Different investigated users in the same tenant are allowed and prominently recorded as a context change.

## Limits and return status

The per-case raw-record budget is the smaller of its configured `max_events` and 1,000,000 rows. Individual input files are limited to 128 MiB and total raw evidence to 512 MiB per case. The comparison rejects excessive inputs instead of truncating the result. It builds the deduplicated inventory in memory. Split larger collections into bounded saved cases.

A generated comparison returns `0`, including comparisons with evidence differences or documented source coverage gaps. Invalid identity, integrity, path, or limit conditions return `1`; argument errors return `2`, and interruption returns `130`. No comparison result implies current tenant state, attacker intent, successful phishing, or malicious execution. There are no live calls or remediation actions in this command.
