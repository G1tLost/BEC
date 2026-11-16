"""Read-only, account-scoped Defender XDR Advanced Hunting queries."""
import json
from dataclasses import dataclass
from datetime import timedelta

TABLES = ("EmailEvents", "EmailUrlInfo", "EmailAttachmentInfo", "UrlClickEvents",
          "EmailPostDeliveryEvents", "AlertEvidence")
ENDPOINT = "/v1.0/security/runHuntingQuery"
ROW_LIMIT = 2000


@dataclass(frozen=True)
class HuntingPage:
    data: bytes
    parameters: dict


def body(table, user, start, end, case_start, case_end, field="account/message scope"):
    """Identifiers come from TABLES. User values are escaped Kusto string literals."""
    if table not in TABLES:
        raise ValueError("Unknown hunting table.")
    account = json.dumps(user, ensure_ascii=False)
    mail_user = f"(RecipientEmailAddress =~ {account} or SenderFromAddress =~ {account})"
    window = f"Timestamp >= datetime({start}) and Timestamp < datetime({end})"
    lookup = table == "EmailUrlInfo" or (table == "AlertEvidence" and field == "NetworkMessageId")
    if lookup:
        mail_range = f"Timestamp >= datetime({case_start}) and Timestamp < datetime({case_end})"
        ids = (f"EmailEvents | where {mail_range} | where {mail_user} "
               "| where isnotempty(NetworkMessageId) | distinct NetworkMessageId")
        match = f"NetworkMessageId in ({ids})"
    elif table == "AlertEvidence":
        match = f"AccountUpn =~ {account}"
    elif table == "UrlClickEvents":
        match = f'Workload =~ "Email" and AccountUpn =~ {account}'
    else:
        match = mail_user
    query = f"{table}\n| where {window}\n| where {match}\n| take {ROW_LIMIT + 1}"
    interval = f"{case_start}/{case_end}" if lookup else f"{start}/{end}"
    return {"Query": query, "Timespan": interval}


def pages(graph, q):
    from .graph import ROOT, SourceError
    from .storage import iso, timestamp

    pending = [(timestamp(q.start), timestamp(q.end))]
    case = graph.case.meta
    while pending:
        low, high = pending.pop()
        params = body(q.dataset, q.value, iso(low), iso(high), case["start"], case["end"], q.field)
        raw = graph.request(ROOT + ENDPOINT, params)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("results"), list):
            raise SourceError("Advanced Hunting response lacks a results array.")
        page = HuntingPage(raw, params)
        if parsed.get("error") or parsed.get("@odata.nextLink") or parsed.get("isTruncated"):
            yield page
            raise SourceError("Advanced Hunting reported incomplete results.")
        if len(parsed["results"]) <= ROW_LIMIT:
            yield page
            continue
        if high - low <= timedelta(microseconds=1):
            yield page
            raise SourceError("Advanced Hunting row limit reached within one timestamp.")
        middle = low + (high - low) // 2
        pending.extend(((middle, high), (low, middle)))
