# Security and permissions

Google Workspace collection uses a delegated service account with the Admin SDK Reports audit read-only scope. For Workspace-only and mixed-provider cases, follow the [Workspace setup guide](workspace.md).

Create a single-tenant application for the intended directory in Microsoft's public cloud. Assign the following **application** permissions in Microsoft Graph and grant administrator consent. A directory GUID and a client GUID bind the case to that application's tenant-specific authentication endpoint.

| Collector | Application permission | Scope used by BEC |
| --- | --- | --- |
| Entra interactive, non-interactive, service principal and directory audits | `AuditLog.Read.All` | Sign-ins by user, IP or consented service principal. Directory changes by initiating UPN or a discovered target user object ID |
| Purview Unified Audit Log | `AuditLogsQuery-Exchange.Read.All` | Exchange audit search filtered by user or IP, covering mailbox item, aggregated item, admin and search records |
| Exchange message trace | `ExchangeMessageTrace.Read.All` | Separate time-bounded searches for the sender and recipient |
| Defender XDR Advanced Hunting | `ThreatHunting.Read.All` | Account-scoped email, URL, attachment, click, post-delivery and alert evidence |

Microsoft documents the permissions and availability of each workload. Non-interactive and service principal sign-ins use Graph beta, whose contract can change. Session identifiers and optional fields may be absent. [Entra sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) · [Beta sign-in filters](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta) · [Directory audit properties](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0)

The UAL collector creates a search, polls the search ID and retrieves its records. BEC records the search ID locally to resume outstanding searches. Tenant audit settings, licensing, and retention determine which activities are available. [Purview audit search](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0) · [Audit records](https://learn.microsoft.com/en-us/graph/api/security-auditlogquery-list-records?view=graph-rest-1.0)

For Defender, grant administrator consent to the Microsoft Graph **application** permission `ThreatHunting.Read.All`. BEC submits read-only KQL using `POST /v1.0/security/runHuntingQuery`. Defender for Office 365 deployment, Safe Links coverage, incident dates and tenant retention affect which tables have data. Check a known network message ID in Defender Advanced Hunting when validating the first live case. Each query records its table, requested account, time range, status and returned row count. [Graph hunting API](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) · [Defender email URLs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table) · [Safe Links events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table) · [XDR alert evidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)

Message trace requires the Exchange message trace service principal to be provisioned in the tenant. An administrator completes Microsoft's onboarding once. BEC splits long windows into at most nine-day intervals. Microsoft limits historical availability to 90 days. [Exchange onboarding and limits](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace)

## Credentials and case files

The live client uses Azure Identity certificate or client-secret authentication. Set `BEC_CERTIFICATE_PATH` to a PEM or PKCS#12 file containing the private key. Use `BEC_CERTIFICATE_PASSWORD` for an encrypted file, or `BEC_CLIENT_SECRET` for secret-based authentication. Certificates take precedence. The SDK acquires and refreshes access tokens. The CLI never needs the affected user's password. [CertificateCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.certificatecredential?view=azure-python) · [ClientSecretCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.clientsecretcredential?view=azure-python)

Use a restricted evidence directory appropriate to the case. The store inherits the operating system's permissions and encryption. Raw audit records, reports, and acquisition logs can contain sensitive user and mailbox metadata. The HTML report embeds the investigation data for offline use. Its evidence hyperlinks resolve within the case directory. CSV exports quote spreadsheet formula prefixes.

The collector accepts pagination links only on the public Graph HTTPS origin and disables redirects. Logs contain query status, workload, retry counts and pivot entities. They omit authentication headers, credential values and HTTP error bodies.

A SHA-256 manifest detects changes to the collected bytes against the recorded hashes. For independent custody, retain a protected copy of the manifest or case snapshot in your evidence system. An administrator with write access to the entire case can change both an artifact and its manifest.

## Coverage checks for a live case

Compare the case counts and times with a known sign-in, Exchange audit event and message trace in the chosen window. Inspect the raw record referenced by each known event. Check the per-query status for both baseline and incident windows and review any partial results before drawing conclusions. Successful empty queries can occur when retention has expired. BEC reports observed time ranges and cannot establish the tenant's actual retention policy from an empty response.
