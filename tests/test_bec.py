import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from bec.analysis import scope
from bec.cli import main
from bec.collection import Collection, acquire, replay
from bec.graph import Graph, SourceError, fetch, list_url, plan
from bec.normalize import normalize, records
from bec.reporting import report
from bec.storage import DATA, CaseError, create, digest, encode, read, save, timestamp

USER = "compromised@example.com"
START, END = "2026-10-30T12:00Z", "2026-10-31T12:00Z"
DEMO = DATA / "demo" / "bundle.json"


class Cases(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.case = self.new()
        self.collection = Collection(self.case)

    def new(self, user=USER, **options):
        options.setdefault("defender", False)
        return create(self.root, "TEST", user, START, END, dict(tenant="TEST", options=options))

    def imported(self):
        self.collection.import_bundle(DEMO)
        return report(self.case)

    def invoke(self, *args):
        stream = io.StringIO()
        with redirect_stdout(stream), redirect_stderr(stream):
            status = main(["--root", str(self.root), *args])
        return status, stream.getvalue()

    def test_case_and_end_to_end_reconstruction(self):
        code, output = self.invoke("investigate", self.case.id, "--bundle", str(DEMO))
        self.assertEqual(code, 0, output)
        tl = read(self.case.path / "timeline/timeline.json")
        events = tl["complete"]
        self.assertEqual(len(events), 16)
        self.assertEqual([e["timestamp_utc"] for e in events], sorted(e["timestamp_utc"] for e in events))
        types = [e["event_type"] for e in events]
        seq = ["mail.delivery", "authentication.failure", "authentication.success", "mail.access", "mail.rule.create"]
        cursor = -1
        for typ in seq:
            cursor = types.index(typ, cursor + 1)
        self.assertEqual(self.case.verify(), 6)
        for f in tl["findings"]:
            for ref in f["evidence"]:
                raw = (self.case.path / ref["file"]).read_bytes()
                self.assertEqual(digest(raw), ref["sha256"])
                self.assertEqual(records(raw)[ref["record_index"]]["id"], ref["source_event_id"])
        cluster = next(e for e in tl["relevant"] if e["count"] > 1)
        self.assertEqual(cluster["count"], 4)
        self.assertEqual(len(cluster["evidence_reference"]), 4)
        self.assertEqual(len(cluster["messages"]), 4)
        self.assertIn("colleague@example.com", {e["actor"] for e in events})
        self.assertNotIn("traveler@example.com", {e["actor"] for e in events})
        self.assertEqual(self.invoke("timeline", "export-timesketch", self.case.id)[0], 0)
        first = json.loads((self.case.path / "timeline/timesketch.jsonl").read_text().splitlines()[0])
        self.assertTrue({"datetime", "message", "timestamp_desc"} <= first.keys())

    def test_traveler_without_compromise_claim(self):
        c = self.new("traveler@example.com")
        Collection(c).import_bundle(DEMO)
        report(c)
        ev = [json.loads(line) for line in (c.path / "normalized/events.jsonl").read_text().splitlines()]
        self.assertIn("new_country", ev[0]["anomalies"])
        self.assertTrue(all(e["assessment"] in ("Unknown", "Contextual") for e in ev))
        self.assertEqual([f["rule"] for f in read(c.path / "findings.json")], ["auth-mail"])

    def test_session_geography_and_consent(self):
        self.imported()
        fs = read(self.case.path / "findings.json")
        self.assertTrue({"session-geography", "oauth-use", "fail-success", "auth-rule"} <= {f["rule"] for f in fs})
        geo = next(f for f in fs if f["rule"] == "session-geography")
        self.assertEqual(geo["join"]["session"], "sess-001")
        self.assertEqual(len(geo["evidence"]), 3)
        principal = next(f for f in fs if f["rule"] == "oauth-use")["join"]["principal"]
        edges = read(self.case.path / "entities/graph.json")["edges"]
        self.assertEqual(len([e for e in edges if e["target"] == ["principal", principal]]), 2)

    def test_scope_shared_and_trusted(self):
        self.collection.import_bundle(DEMO)
        events, _ = replay(self.case)
        manual = [("ip", "192.0.2.10")]
        selected, _, history, _, _ = scope(self.case, events, manual)
        self.assertFalse(any(str(e["actor"]["user"]).startswith("staff") for e in selected))
        self.assertIn("shared IP", {q["status"] for q in history})
        case = self.new(trusted_networks=["198.51.100.0/24"])
        selected, _, history, _, _ = scope(case, events)
        self.assertIn("trusted network", {q["status"] for q in history})
        self.assertNotIn("colleague@example.com", [e["actor"]["user"] for e in selected])

    def test_tamper_and_original_bytes(self):
        self.imported()
        entry = self.case.manifest()["artifacts"][0]
        artifact = self.case.raw_path(entry)
        self.assertEqual(artifact.read_bytes(), (DEMO.parent / "interactive.json").read_bytes())
        artifact.write_bytes(b"[]")
        with self.assertRaisesRegex(CaseError, "verification failed"):
            self.case.verify()
        self.assertEqual(self.invoke("analyze", self.case.id)[0], 1)

    def test_replay_is_idempotent(self):
        self.imported()
        before = (self.case.path / "evidence_manifest.json").read_bytes()
        findings = read(self.case.path / "findings.json")
        self.imported()
        self.assertEqual(before, (self.case.path / "evidence_manifest.json").read_bytes())
        self.assertEqual(findings, read(self.case.path / "findings.json"))

    def test_recover_interrupted_manifest(self):
        self.imported()
        manifest = self.case.manifest()
        record = manifest["artifacts"].pop()
        save(self.case.path / ".pending-artifact.json", record)
        save(self.case.path / "evidence_manifest.json", manifest)
        self.assertEqual(self.case.verify(), 6)
        self.assertFalse((self.case.path / ".pending-artifact.json").exists())

    def test_bundle_and_native_tenant_checks(self):
        other = create(self.root, "OTHER", USER, START, END)
        with self.assertRaisesRegex(CaseError, "tenant binding"):
            Collection(other).import_bundle(DEMO)
        with self.assertRaisesRegex(CaseError, "directory ID"):
            acquire(self.case, "ual", encode([{"organizationId": "another-tenant"}]), "export", {}, 50)
        self.assertEqual(other.verify(), 0)
        self.assertEqual(self.case.verify(), 0)

    def test_malformed_record_remains_traceable(self):
        row = {"id": "no-tz", "createdDateTime": "2026-10-30T20:00:00"}
        save(self.root / "bad.json", [row])
        bundle = self.root / "bundle.json"
        save(bundle, {"tenant": "TEST", "files": [{"dataset": "interactive", "path": "bad.json"}]})
        code, out = self.invoke("investigate", self.case.id, "--bundle", str(bundle))
        self.assertEqual(code, 2, out)
        gaps = read(self.case.path / "telemetry_gaps.json")
        ref = next(g["evidence"] for g in gaps if "evidence" in g)
        self.assertEqual(records((self.case.path / ref["file"]).read_bytes())[ref["record_index"]], row)

    def test_timezone_and_unknown_result(self):
        self.assertEqual(timestamp("2026-10-30T16:30:00-04:00"), timestamp("2026-10-30T20:30Z"))
        with self.assertRaises(CaseError):
            timestamp("2026-10-30T16:30:00")
        e = normalize("TEST", "interactive", {"createdDateTime": START}, {})
        self.assertEqual(e["event_type"], "authentication.unknown")
        e = normalize("TEST", "ual", {"CreationTime": "2026-10-30T16:30:00", "Operation": "MailItemsAccessed"}, {})
        self.assertEqual(e["timestamp_utc"], "2026-10-30T16:30:00.000000Z")

    def test_dry_run_has_no_acquisition(self):
        before = set(self.case.path.rglob("*"))
        code, out = self.invoke("investigate", self.case.id, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("AuditLogsQuery-Exchange.Read.All", out)
        self.assertEqual(before, set(self.case.path.rglob("*")))

    def test_partial_live_failure_and_resume(self):
        def simulate(_, q, key):
            if q.dataset == "ual":
                raise SourceError("Graph HTTP 403: access denied.")
            yield encode({"value": []})
        with patch("bec.collection.Graph"), patch("bec.collection.fetch", side_effect=simulate):
            code, out = self.invoke("investigate", self.case.id)
            self.assertEqual(code, 2, out)
        gaps = read(self.case.path / "telemetry_gaps.json")
        self.assertTrue(any("403" in g["reason"] for g in gaps))
        with patch("bec.collection.Graph"), patch("bec.collection.fetch", return_value=[b'{"value":[]}']) as fetcher:
            self.assertEqual(self.invoke("collect", self.case.id)[0], 0)
            self.assertEqual(fetcher.call_count, 1)
            self.assertEqual(fetcher.call_args.args[1].dataset, "ual")

    def test_live_investigation_follows_evidence_with_scoped_queries(self):
        seen = []

        def simulate(_, q, key):
            seen.append((q.kind, q.value, q.dataset))
            matched = []
            for row in read(DEMO.parent / (q.dataset + ".json"))["value"]:
                event = normalize("TEST", q.dataset, row, {})
                inside = q.start <= event["timestamp_utc"] <= q.end
                if q.dataset == "trace":
                    eligible = row[q.field] == q.value
                elif q.kind == "user_id":
                    eligible = q.value in event["entities"].get("user_id", [])
                else:
                    eligible = q.value in event["entities"].get(q.kind, [])
                if inside and eligible:
                    matched.append(row)
            yield encode({"value": matched})

        with patch("bec.collection.Graph"), patch("bec.collection.fetch", side_effect=simulate):
            code, out = self.invoke("investigate", self.case.id)
            self.assertEqual(code, 0, out)
        self.assertIn(("ip", "198.51.100.74", "ual"), seen)
        self.assertIn(("user", "colleague@example.com", "trace"), seen)
        self.assertTrue(any(kind == "principal" for kind, _, _ in seen))
        self.assertEqual(read(self.case.path / "analysis_summary.json")["event_count"], 16)

    def test_live_shared_ip_stops_before_next_page(self):
        query = plan(self.case, "ip", "192.0.2.10")
        shared = [row for row in read(DEMO.parent / "interactive.json")["value"]
                  if row["id"].startswith("shared-")]
        def pages(_, q, key):
            yield encode({"value": shared})
            self.fail("Fetched an additional page after detecting shared infrastructure.")
        with patch("bec.collection.Graph"), patch("bec.collection.fetch", side_effect=pages) as get:
            self.collection.collect(query)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(all(g["shared_ip"] for g in self.collection.state["gaps"]))
        self.assertEqual(self.case.verify(), 1)

    def test_ual_create_poll_page_and_resume(self):
        graph = MagicMock()
        graph.case = self.case
        q = next(q for q in plan(self.case, "user", USER) if q.dataset == "ual")
        job = "91144a7b-fa98-4575-950a-a136bc393488"
        graph.request.side_effect = [encode({"id": job}), encode({"status": "running"}), encode({"status": "succeeded"})]
        graph.pages.return_value = [b'{"value":[]}']
        with patch("bec.graph.time.sleep"):
            self.assertEqual(list(fetch(graph, q, "stable-key")), [b'{"value":[]}'])
        self.assertEqual(graph.request.call_args_list[0].args[1]["userPrincipalNameFilters"], [USER])
        self.assertTrue(graph.pages.call_args.args[0].endswith(job + "/records"))
        save(self.case.path / "collection/audit_jobs.json", {"stable-key": job})
        graph.request.side_effect = [encode({"status": "succeeded", "isRecordCountLimitExceeded": True})]
        pages = fetch(graph, q, "stable-key")
        self.assertEqual(next(pages), b'{"value":[]}')
        with self.assertRaisesRegex(SourceError, "record limit"):
            next(pages)

    def test_transport_pagination_foreign_origin_and_retry(self):
        g = Graph.__new__(Graph)
        g.case, g.credential, g.opener = self.case, MagicMock(), MagicMock()
        g.credential.get_token.return_value.token = "dummy"
        url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        next_page = url + "?p=2"
        err = HTTPError(url, 429, "rate limit", {"Retry-After": "3"}, None)
        g.opener.open.side_effect = [err, io.BytesIO(encode({"value": [1], "@odata.nextLink": next_page})),
                                    io.BytesIO(encode({"value": [2]}))]
        with patch("bec.graph.time.sleep") as sleep:
            self.assertEqual([records(raw) for raw in g.pages(url)], [[1], [2]])
            sleep.assert_called_once_with(3)
        calls = g.opener.open.call_count
        with self.assertRaises(SourceError):
            g.request("https://example.net/v1.0/steal")
        self.assertEqual(calls, g.opener.open.call_count)
        g.opener.open.side_effect = URLError("timeout")
        with self.assertRaisesRegex(SourceError, "outcome unknown"):
            g.request("https://graph.microsoft.com/v1.0/security/auditLog/queries", {})
        self.assertEqual(g.opener.open.call_count, calls + 1)

    def test_odata_literals_and_trace_window(self):
        case = create(self.root, "TEST", "o'neil@example.com", "2026-09-01T00:00Z", END,
                      dict(tenant="TEST", options={"defender": False}))
        jobs = plan(case, "user", case.meta["user"])
        for q in jobs:
            if q.dataset == "ual":
                continue
            filt = parse_qs(urlsplit(list_url(q)).query)["$filter"][0]
            self.assertIn("o''neil", filt)
            if q.dataset == "trace":
                self.assertLessEqual((timestamp(q.end) - timestamp(q.start)).days, 10)

    def test_lock_and_path_validation(self):
        with self.case.lock(), self.assertRaises(CaseError):
            with self.case.lock():
                pass
        for bad in ("../x", "CON", "test/tenant"):
            with self.assertRaises(CaseError):
                create(self.root, bad, USER, START, END)
        self.assertEqual(self.invoke("verify", "../case")[0], 1)


if __name__ == "__main__":
    unittest.main()
