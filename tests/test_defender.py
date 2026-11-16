import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from bec import hunting
from bec.cli import main
from bec.collection import Collection, replay
from bec.graph import SourceError, fetch, plan
from bec.messages import correlate_messages
from bec.normalize import normalize, records
from bec.reporting import report
from bec.storage import DATA, Case, create, digest, encode, read, save

USER = "compromised@example.com"
START, END = "2026-10-30T12:00Z", "2026-10-31T12:00Z"
FIX = DATA / "demo"
MID = "<invoice-142@example.net>"
NID = "77869133-e792-41c1-b159-4c7effc15103"


class DefenderCases(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.case = create(self.root, "TEST", USER, START, END)
        self.bundle = FIX / "defender-bundle.json"

    def cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            status = main(["--root", str(self.root), *args])
        return status, out.getvalue()

    def event(self, table, **extra):
        record = read(FIX / f"{table}.json")["results"][0]
        return normalize("TEST", table, record | extra, {"file": table, "record_index": 0})

    def audit(self, mailbox=USER, mid=MID, actor=USER):
        record = {"Operation": "MailItemsAccessed", "MailboxOwnerUPN": mailbox, "UserId": actor,
                  "CreationTime": "2026-10-30T20:36:12Z", "AffectedItems": [{"InternetMessageId": mid}]}
        return normalize("TEST", "ual", record, {"file": "ual", "record_index": 0})

    def test_demo_links_and_resolves_every_record(self):
        code, out = self.cli("investigate", self.case.id, "--bundle", str(self.bundle))
        self.assertEqual(code, 0, out)
        payload = read(self.case.path / "timeline/timeline.json")
        self.assertEqual(payload["summary"]["event_count"], 23)
        m, = payload["messages"]
        self.assertEqual(m["recipient"], USER)
        self.assertEqual(m["internet_message_ids"], [MID])
        self.assertEqual(len(m["mailbox_event_ids"]), 1)
        self.assertEqual(m["attachments"][0]["FileName"], "Invoice-142.pdf")
        self.assertEqual(len(m["attachments"][0]["SHA256"]), 64)
        self.assertEqual(m["urls"][0]["Url"], "https://billing.example.net/invoice/142")
        self.assertEqual({o["source"] for o in m["observations"]}, set(hunting.TABLES) | {"ual", "trace"})
        for o in m["observations"]:
            ref = o["evidence"]
            data = (self.case.path / ref["file"]).read_bytes()
            self.assertEqual(digest(data), ref["sha256"])
            row = records(data)[ref["record_index"]]
            self.assertEqual(normalize("TEST", o["source"], row, ref)["event_id"], o["event_id"])
        mailbox_rows = [r for r in payload["relevant"] if r["event_type"] == "mail.access" and r["message_links"]]
        self.assertEqual(len(mailbox_rows), 1)
        self.assertEqual(mailbox_rows[0]["count"], 1)
        with (self.case.path / "timeline/complete.csv").open(encoding="utf-8-sig", newline="") as handle:
            linked = [r for r in csv.DictReader(handle) if m["id"] in r["message_links"]]
        self.assertEqual(len(linked), 8)
        csv_access, = [r for r in linked if r["event_type"] == "mail.access"]
        self.assertIn("Invoice-142.pdf", csv_access["linked_email_artifacts"])
        self.assertEqual(self.case.verify(), 13)

    def test_mailbox_identity_ambiguity_and_distinct_network_ids(self):
        email, delegated = self.event("EmailEvents"), self.audit(actor="delegate@example.com")
        wrong = self.audit(mailbox="other@example.com")
        docs, finds = correlate_messages([email, delegated, wrong])
        self.assertEqual(len(finds), 1)
        self.assertNotIn("message_links", wrong)
        self.assertEqual(docs[0]["mailbox_event_ids"], [delegated["event_id"]])
        mismatch = self.audit(mid=MID.replace("invoice", "Invoice"))
        docs, finds = correlate_messages([self.event("EmailEvents"), mismatch])
        self.assertFalse(finds)
        audit = self.audit()
        docs, finds = correlate_messages([self.event("EmailEvents"), self.event("EmailEvents", NetworkMessageId="other-network-id"), audit])
        self.assertEqual(len(docs), 2)
        self.assertFalse(finds)
        self.assertIn("Ambiguous", audit["link_notes"][0])

    def test_no_artifact_or_click_inference_by_filename_url_or_time(self):
        email = self.event("EmailEvents")
        misses = [self.event("EmailAttachmentInfo", RecipientEmailAddress="else@example.com"),
                  self.event("UrlClickEvents", Workload="Teams"),
                  self.event("UrlClickEvents", NetworkMessageId="00000000-0000-0000-0000-000000000000"),
                  self.event("EmailUrlInfo", NetworkMessageId="different"),
                  self.event("AlertEvidence", AccountUpn="someone@example.com")]
        docs, _ = correlate_messages([email, *misses])
        self.assertTrue(all("message_links" not in m for m in misses))
        self.assertEqual(len(docs[0]["observations"]), 1)
        a = self.event("EmailUrlInfo", Url="https://example.net/a")
        b = self.event("EmailUrlInfo", Url="https://example.net/b")
        self.assertNotEqual(a["event_id"], b["event_id"])
        self.assertNotEqual(a["event_type"], "email.click")

    def test_all_hunts_use_bounded_queries_and_safe_literals(self):
        account = "o'neil\"sales@example.com"
        qs = [q for q in plan(self.case, "user", account) if q.dataset in hunting.TABLES]
        self.assertEqual({q.dataset for q in qs}, set(hunting.TABLES))
        graph = MagicMock()
        graph.case = self.case
        graph.request.return_value = b'{"results":[]}'
        for q in qs:
            page, = fetch(graph, q, "key")
            self.assertEqual(graph.request.call_args.args[0], "https://graph.microsoft.com" + hunting.ENDPOINT)
            params = graph.request.call_args.args[1]
            self.assertIn(json.dumps(account), params["Query"])
            self.assertIn("Timestamp <", params["Query"])
            self.assertIn("take ", params["Query"])
            self.assertEqual(page.parameters, params)
            self.assertEqual(q.metadata()["permission"], "ThreatHunting.Read.All")
        self.assertFalse(any(q.dataset in hunting.TABLES for q in plan(self.case, "user", USER, baseline=True)))

    def test_hunt_repartitions_keeps_casewide_message_lookup(self):
        graph = MagicMock()
        graph.case = self.case
        q = next(q for q in plan(self.case, "user", USER) if q.dataset == "EmailUrlInfo")
        first, second = b'{"results":[{"Url":"a"}]}', b'{"results":[{"Url":"b"}]}'
        graph.request.side_effect = [b'{"results":[{},{}]}', first, second]
        with patch.object(hunting, "ROW_LIMIT", 1):
            pages = list(fetch(graph, q, "k"))
        self.assertEqual([p.data for p in pages], [first, second])
        self.assertEqual(pages[0].parameters["Timespan"], pages[1].parameters["Timespan"])
        self.assertNotEqual(pages[0].parameters["Query"], pages[1].parameters["Query"])
        self.assertIn("distinct NetworkMessageId", pages[1].parameters["Query"])

    def test_gap_preserves_partial_hunting_evidence_and_retry(self):
        collection = Collection(self.case)
        q = next(q for q in plan(self.case, "user", USER) if q.dataset == "EmailEvents")
        graph = MagicMock()
        graph.case = self.case
        collection.graph = graph
        raw = read(FIX / "EmailEvents.json")
        graph.request.return_value = encode(raw | {"isTruncated": True})
        collection.collect([q])
        self.assertEqual(len(collection.state["gaps"]), 1)
        self.assertEqual(self.case.verify(), 1)
        self.assertIn("Query", self.case.manifest()["artifacts"][0]["queries"][0])
        other = Collection(self.case)
        other.graph = graph
        graph.request.return_value = encode(raw)
        other.collect([q])
        self.assertFalse(other.state["gaps"])
        events, _ = replay(self.case)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(events[0]["additional_evidence"]), 1)

    def test_live_403_and_lower_camel_response(self):
        collection = Collection(self.case)
        collection.graph = MagicMock()
        collection.graph.case = self.case
        query = [q for q in plan(self.case, "user", USER) if q.dataset in ("EmailEvents", "EmailUrlInfo")]
        collection.graph.request.side_effect = [SourceError("Graph HTTP 403"), encode({"results":[{
            "timestamp": "2026-10-30T20:25:22Z", "url": "https://example.net", "networkMessageId": NID}]})]
        collection.collect(query)
        self.assertEqual(len(collection.state["gaps"]), 1)
        es, issues = replay(self.case)
        self.assertFalse(issues)
        self.assertEqual(es[0]["entities"]["url"], ["https://example.net"])

    def test_scope_excludes_unrelated_addressless_rows(self):
        Collection(self.case).import_bundle(self.bundle)
        path = self.root / "more.json"
        samples = read(FIX / "EmailUrlInfo.json")["results"]
        save(path, [samples[0] | {"NetworkMessageId": "unrelated", "Url": "https://unrelated.example.org"}])
        save(self.root / "extra.json", {"tenant": "TEST", "files": [{"dataset": "EmailUrlInfo", "path": "more.json"}]})
        Collection(self.case).import_bundle(self.root / "extra.json")
        stats = report(self.case)
        self.assertEqual(stats["event_count"], 23)
        self.assertNotIn("unrelated.example.org", (self.case.path / "timeline/timeline.json").read_text())

    def test_v01_case_upgrade_only_when_requested(self):
        meta = self.case.meta
        meta["options"].pop("defender")
        meta["version"] = "0.1.0"
        save(self.case.path / "case.json", meta)
        before = (self.case.path / "case.json").read_bytes()
        self.assertNotIn("ThreatHunting", self.cli("investigate", self.case.id, "--dry-run")[1])
        self.assertIn("ThreatHunting", self.cli("investigate", self.case.id, "--defender", "--dry-run")[1])
        self.assertEqual(before, (self.case.path / "case.json").read_bytes())
        self.assertEqual(self.cli("investigate", self.case.id, "--defender", "--bundle", str(self.bundle))[0], 0)
        self.assertTrue(Case(self.case.path).options["defender"])
