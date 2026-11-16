"""Customer-bound Google Workspace Admin SDK Reports acquisition."""
import json
import os
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import quote

from .graph import SourceError
from .storage import GOOGLE_APPS, iso

SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
BASE = "https://admin.googleapis.com/admin/reports/v1/activity/users"


@dataclass(frozen=True)
class WorkspaceQuery:
    dataset: str
    kind: str
    value: str
    start: str
    end: str
    customer: str

    @property
    def path(self):
        return f"{BASE}/{quote(self.value, safe='')}/applications/{GOOGLE_APPS[self.dataset]}"

    def metadata(self):
        return dict(dataset=self.dataset, kind=self.kind, value=self.value, start=self.start,
                    end=self.end, customer_id=self.customer, endpoint=self.path, permission=SCOPE)


def queries(case, kind, value, start, end, baseline):
    if kind != "user":
        return
    customer = case.meta["google_workspace"]["customer_id"]
    for dataset in ("google_login",) if baseline else GOOGLE_APPS:
        low = start
        while low < end:
            high = min(low + timedelta(days=30), end)
            yield WorkspaceQuery(dataset, kind, value, iso(low), iso(high), customer)
            low = high


class Workspace:
    def __init__(self, case):
        self.case = case
        config = case.meta["google_workspace"]
        path = os.environ.get("BEC_GOOGLE_SERVICE_ACCOUNT")
        if not path or not config.get("admin_email"):
            raise SourceError("Workspace needs BEC_GOOGLE_SERVICE_ACCOUNT and google_workspace.admin_email.")
        try:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2.service_account import Credentials
        except ImportError as exc:
            raise SourceError("Install BEC's live extra for Workspace authentication.") from exc
        try:
            with open(path, encoding="utf-8-sig") as f:
                info = json.load(f)
            if info["type"] != "service_account" or info["token_uri"] != "https://oauth2.googleapis.com/token":
                raise ValueError("Unexpected credential type or token endpoint.")
            creds = Credentials.from_service_account_info(info, scopes=[SCOPE], subject=config["admin_email"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise SourceError("Cannot load the configured Google service account credential.") from exc
        self.session = AuthorizedSession(creds)

    def request(self, query, params):
        from google.auth.exceptions import GoogleAuthError
        from requests import RequestException

        for attempt in range(5):
            try:
                with self.session.get(query.path, params=params, timeout=45, allow_redirects=False) as resp:
                    status = resp.status_code
                    if status == 200:
                        return resp.content
                    reason = ""
                    if status == 403:
                        try:
                            reason = resp.json()["error"]["errors"][0]["reason"]
                        except (ValueError, KeyError, IndexError, TypeError):
                            pass
                    retryable = status in (429, 500, 502, 503, 504) or reason in (
                        "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded")
                    if not retryable:
                        raise SourceError(f"Workspace HTTP {status} for {query.dataset}. Check reporting privileges, edition and account.")
                    after = resp.headers.get("Retry-After", "")
                    delay = int(after) if after.isdecimal() else 2 ** attempt
            except GoogleAuthError as exc:
                raise SourceError("Workspace authentication failed. Check delegation, scope and reporting administrator.") from exc
            except RequestException:
                delay, status = 2 ** attempt, "network failure"
            if attempt == 4 or delay > 120:
                raise SourceError(f"Workspace retry budget exceeded ({status}).")
            self.case.log("retry", api=query.path, status=status, delay_seconds=delay)
            time.sleep(delay)

    def pages(self, query):
        params = dict(customerId=query.customer, startTime=query.start, endTime=query.end, maxResults=500)
        seen = set()
        while True:
            raw = self.request(query, params)
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("error") or not (
                    "items" in data or data.get("kind") == "admin#reports#activities" or
                    data.get("kind") in ("audit#activities", "reports#activities")):
                raise SourceError("Workspace response lacks an activity collection.")
            yield raw
            token = data.get("nextPageToken")
            if not token:
                return
            if not isinstance(token, str) or token in seen:
                raise SourceError("Workspace returned an invalid or repeated page token.")
            seen.add(token)
            params["pageToken"] = token
