import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

from bec.cli import main
from bec.collection import Collection, acquire, replay
from bec.google_events import normalize_child, correlations
from bec.graph import SourceError, plan
from bec.normalize import records
from bec.reporting import report
from bec.storage import CaseError, DATA, GOOGLE_APPS, create, digest, encode, read, save, timestamp
from bec.workspace import SCOPE, Workspace

USER, CUSTOMER = "compromised@example.com", "C02becdemo"
START, END = "2026-10-30T12:00Z", "2026-10-31T12:00Z"
FIX = DATA / "demo"


class WorkspaceCases(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cfg = {"tenant": "TEST", "google_workspace": {"customer_id": CUSTOMER, "admin_email": "audit@example.com"}}
        self.case = create(self.root, "TEST", USER, START, END, self.cfg)

    def cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            code = main(["--root", str(self.root), *args])
        return code, out.getvalue()

    def rows(self, dataset):
        return read(FIX / (dataset + ".json"))["items"]

    def test_google_and_microsoft_on_one_timeline(self):
        code, out = self.cli("demo")
        self.assertEqual(code, 0, out)
        case_id = out.split()[0]
        path = self.root / "TEST" / case_id
        payload = read(path / "timeline/timeline.json")
        self.assertEqual(len(payload["complete"]), 30)
        self.assertEqual(payload["summary"]["workspace_matches"], 3)
        self.assertTrue(set(GOOGLE_APPS) | {"ual", "interactive", "EmailEvents"} <= set(payload["summary"]["source_counts"]))
        fs = [f for f in payload["findings"] if f["rule"] == "workspace-grant-gmail"]
        self.assertEqual(len(fs), 2)
        f = next(f for f in fs if "message access" in f["observation"])
        self.assertEqual([r["file"].split("/")[1] for r in f["evidence"]], list(GOOGLE_APPS))
        for eid, ref in zip(f["event_ids"], f["evidence"]):
            raw = (path / ref["file"]).read_bytes()
            self.assertEqual(digest(raw), ref["sha256"])
            dataset = ref["file"].split("/")[1]
            row = records(raw, dataset)[ref["record_index"]]
            self.assertEqual(normalize_child("TEST", dataset, row, ref["event_index"], ref)["event_id"], eid)
        self.assertEqual(self.cli("verify", case_id)[0], 0)
        with (path / "timeline/complete.csv").open(encoding="utf-8-sig", newline="") as stream:
            app, = [r for r in csv.DictReader(stream) if r["event_type"] == "google.gmail.app_access"]
            self.assertIn(f["join"]["client_id"], app["workspace"])
        self.assertEqual(self.cli("timeline", "export-timesketch", case_id)[0], 0)
        export = (path / "timeline/timesketch.jsonl").read_text()
        self.assertIn("google_gmail", export)

    def test_live_query_plan_and_dry_run(self):
        before = (self.case.path / "case.json").read_bytes()
        code, out = self.cli("investigate", self.case.id, "--dry-run")
        self.assertEqual(code, 0)
        queries = json.loads(out)["queries"]
        self.assertEqual({q["dataset"] for q in queries}, set(GOOGLE_APPS))
        self.assertTrue(all(q["permission"] == SCOPE and q["customer_id"] == CUSTOMER for q in queries))
        self.assertTrue(all("/users/compromised%40example.com/" in q["endpoint"] for q in queries))
        self.assertEqual(before, (self.case.path / "case.json").read_bytes())
        self.assertFalse((self.case.path / "collection_summary.json").exists())
        long = create(self.root, "TEST", USER, "2026-08-01T00:00Z", END, self.cfg)
        q = [j for j in plan(long, "user", USER) if j.dataset == "google_gmail"]
        self.assertGreater(len(q), 1)
        self.assertTrue(all((timestamp(j.end) - timestamp(j.start)).days <= 30 for j in q))
        self.assertTrue(all(a.end == b.start for a, b in zip(q, q[1:])))

    def test_live_google_only_partial_failure_resume(self):
        def get(client, query, params):
            self.assertEqual(params["customerId"], CUSTOMER)
            if query.dataset == "google_oauth":
                raise SourceError("Workspace HTTP 403 for google_oauth.")
            matched = [row for row in self.rows(query.dataset)
                       if timestamp(query.start) <= timestamp(row["id"]["time"]) < timestamp(query.end)]
            return encode({"kind": "admin#reports#activities", "items": matched})
        with patch.object(Workspace, "__init__", return_value=None), patch.object(Workspace, "request", get), patch("bec.collection.Graph") as graph:
            code, out = self.cli("investigate", self.case.id)
            self.assertEqual(code, 2, out)
            graph.assert_not_called()
        self.assertTrue((self.case.path / "timeline/timeline.html").exists())
        self.assertIn("Workspace HTTP 403", out)
        with patch.object(Workspace, "__init__", return_value=None), patch.object(Workspace, "request", return_value=encode({"items": self.rows("google_oauth")})) as req:
            self.assertEqual(self.cli("investigate", self.case.id)[0], 0)
            self.assertEqual(req.call_count, 1)
        self.assertEqual(read(self.case.path / "analysis_summary.json")["event_count"], 7)

    def test_token_pagination_empty_page_and_retry(self):
        q = plan(self.case, "user", USER)[0]
        g = Workspace.__new__(Workspace)
        g.case, g.session = self.case, MagicMock()
        def response(status, obj):
            res = MagicMock()
            res.status_code, res.content, res.headers = status, encode(obj), {"Retry-After": "2"}
            res.__enter__.return_value = res
            return res
        g.session.get.side_effect = [response(429, {}), response(200, {"items": self.rows("google_login"),
                                      "nextPageToken": "page-2"}), response(200, {"kind": "reports#activities"})]
        with patch("bec.workspace.time.sleep") as wait:
            pages = list(g.pages(q))
            wait.assert_called_once_with(2)
        self.assertEqual(len(pages), 2)
        self.assertEqual(records(pages[1], "google_login"), [])
        self.assertEqual(g.session.get.call_args.kwargs["params"]["pageToken"], "page-2")
        self.assertFalse(g.session.get.call_args.kwargs["allow_redirects"])
        g.session.get.side_effect = [response(200, {"items": [], "nextPageToken": "again"}) for _ in range(2)]
        with self.assertRaisesRegex(SourceError, "repeated"):
            list(g.pages(q))

    def test_import_alfa_ndjson_multievent_dedup_and_pointer(self):
        files = []
        for ds in GOOGLE_APPS:
            rows = self.rows(ds)
            if ds == "google_gmail":
                rows.append(rows[-1])
            filename = GOOGLE_APPS[ds] + ".json"
            (self.root / filename).write_bytes(b"\n".join(encode(r).strip().replace(b"\n", b"") for r in rows))
            files.append(dict(dataset=ds, path=filename))
        bundle = self.root / "bundle.json"
        save(bundle, {"tenant": "TEST", "google_customer_id": CUSTOMER, "files": files})
        code, out = self.cli("investigate", self.case.id, "--bundle", str(bundle))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.case.verify(), 3)
        events, gaps = replay(self.case)
        self.assertFalse(gaps)
        view, = [e for e in events if e["event_type"] == "google.gmail.view"]
        self.assertEqual(view["evidence"]["event_index"], 1)
        self.assertEqual(len(view["additional_evidence"]), 1)
        self.assertEqual(view["additional_evidence"][0]["record_index"], 3)
        manifest_before = self.case.manifest()
        self.assertEqual(self.cli("investigate", self.case.id, "--bundle", str(bundle))[0], 0)
        self.assertEqual(manifest_before, self.case.manifest())

    def test_invalid_child_does_not_hide_siblings(self):
        row = self.rows("google_gmail")[-1]
        row["events"].insert(1, {"name": "delivery", "parameters": [False]})
        acquire(self.case, "google_gmail", encode([row]), "export", {}, 10)
        ev, gaps = replay(self.case)
        self.assertEqual({e["evidence"]["event_index"] for e in ev}, {0, 2})
        self.assertEqual(gaps[0]["evidence"]["event_index"], 1)

    def test_customer_application_and_rebinding_guards(self):
        row = self.rows("google_login")[0]
        for bad in (dict(customerId="C0other"), dict(customerId=None), dict(applicationName="token")):
            with self.assertRaises(CaseError):
                acquire(self.case, "google_login", encode([row | {"id": row["id"] | bad}]), "export", {}, 5)
        self.assertEqual(self.case.verify(), 0)
        profile = self.root / "profile.json"
        save(profile, {"tenant": "TEST", "google_workspace": {"customer_id": "C0different"}})
        self.assertEqual(self.cli("collect", self.case.id, "--workspace-config", str(profile))[0], 1)
        unbound = create(self.root, "TEST", USER, START, END)
        save(profile, self.cfg)
        self.assertIn("google_login", self.cli("collect", unbound.id, "--workspace-config", str(profile), "--dry-run")[1])
        self.assertIsNone(read(unbound.path / "case.json")["google_workspace"])

    def test_missing_credential_is_recoverable_without_network(self):
        with patch.dict("os.environ", {"BEC_GOOGLE_SERVICE_ACCOUNT": ""}):
            code, msg = self.cli("investigate", self.case.id)
        self.assertEqual(code, 2, msg)
        self.assertIn("BEC_GOOGLE_SERVICE_ACCOUNT", msg)
        self.assertEqual(self.case.verify(), 0)
        self.assertTrue((self.case.path / "timeline/timeline.html").exists())

    def test_no_attribution_by_name_only_wrong_user_or_after_revocation(self):
        def ev(ds, row):
            return normalize_child("TEST", ds, row, 0, {})
        grant = self.rows("google_oauth")[0]
        access = self.rows("google_gmail")[1]
        login = self.rows("google_login")[1]
        for change in ({"oauthClientId": "other", "applicationName": "Invoice Reader"},
                       {"applicationName": "Invoice Reader"}, {}):
            wrong = access | {"actor": {"email": USER, "applicationInfo": change}}
            self.assertFalse(correlations([ev("google_oauth", grant), ev("google_gmail", wrong)]))
        for bad in (access | {"actor": access["actor"] | {"email": "other@example.com"}},
                    access | {"id": access["id"] | {"customerId": "C0other"}},
                    access | {"id": access["id"] | {"time": grant["id"]["time"]}}):
            self.assertFalse(correlations([ev("google_oauth", grant), ev("google_gmail", bad)]))
        revoked = deepcopy(grant)
        revoked["events"][0]["name"] = "revoke"
        revoked["id"]["time"] = "2026-10-30T20:33:00Z"
        self.assertFalse(correlations([ev("google_oauth", grant), ev("google_oauth", revoked), ev("google_gmail", access)]))
        revoked["id"]["time"] = access["id"]["time"]
        self.assertFalse(correlations([ev("google_oauth", grant), ev("google_gmail", access), ev("google_oauth", revoked)]))
        wrong_ip = login | {"ipAddress": "203.0.113.200"}
        fs = correlations([ev("google_login", wrong_ip), ev("google_oauth", grant), ev("google_gmail", access)])
        self.assertEqual(len(fs), 1)
        self.assertEqual(len(fs[0]["event_ids"]), 2)

    def test_resource_owner_and_unknown_code(self):
        row = self.rows("google_gmail")[0]
        row["actor"] = {"email": "delegate@example.com"}
        mid = "<resource-id@example.com>"
        row["resourceDetails"] = [{"id": mid, "type": "EMAIL", "ownerDetails": {"ownerIdentity": [
            {"userIdentity": {"userEmail": USER}}]}}]
        row["events"][0]["resourceIds"] = [mid]
        row["events"][0]["parameters"][0]["messageValue"]["parameter"][0]["intValue"] = "999"
        e = normalize_child("TEST", "google_gmail", row, 0, {})
        self.assertEqual(e["actor"]["user"], "delegate@example.com")
        self.assertEqual(e["event_type"], "google.gmail.event")
        self.assertEqual(e["entities"]["mailbox"], [USER])
        self.assertIn(mid, e["entities"]["message"])

    def test_failed_message_access_is_excluded_from_grant_attribution(self):
        grant = normalize_child("TEST", "google_oauth", self.rows("google_oauth")[0], 0, {})
        row = self.rows("google_gmail")[1]
        for status in ({"httpStatusCode": 403}, {"eventStatus": "FAILED"}, {"eventStatus": "SKIPPED"}):
            row["events"][0]["status"] = status
            attempted = normalize_child("TEST", "google_gmail", row, 0, {})
            self.assertEqual(attempted["result"], "failure")
            self.assertFalse(correlations([grant, attempted]))
