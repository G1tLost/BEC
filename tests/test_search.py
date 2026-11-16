"""Typed saved-case search acceptance: precision, provenance, integrity and no writes."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bec.cli import main
from bec.collection import acquire
from bec.normalize import records
from bec.search import canonical, search, write_report
from bec.storage import CaseError, DATA, create, digest, encode, read, save


class SearchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = create(self.root / "cases", "TEST", "compromised@example.com",
            "2026-10-30T12:00Z", "2026-10-31T12:00Z",
            dict(tenant="TEST", microsoft=True, google_workspace=dict(customer_id="C02becdemo")))

    def fixture(self, dataset):
        return records((DATA / "demo" / (dataset + ".json")).read_bytes(), dataset)

    def add(self, dataset, rows):
        acquire(self.case, dataset, encode(rows), "export", dict(dataset=dataset), 100000)

    def tree(self):
        return {str(path.relative_to(self.case.path)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.case.path.rglob("*") if path.is_file()}

    def cli(self, *arguments):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = main([str(argument) for argument in arguments])
        return status, output.getvalue(), error.getvalue()

    def defender(self, **fields):
        return dict(Timestamp="2026-10-30T20:00:00Z", NetworkMessageId="native-message-1", **fields)

    def test_supported_types_match_known_structured_fields_and_preserve_sources(self):
        self.add("EmailEvents", [self.defender(SenderFromAddress="sender@example.org", RecipientEmailAddress="victim@example.com")])
        self.add("EmailUrlInfo", [self.defender(Url="https://login.example.com/a?x=1", UrlDomain="login.example.com")])
        self.add("EmailAttachmentInfo", [self.defender(SHA256="a" * 64, SHA1="b" * 40, RecipientEmailAddress="victim@example.com")])
        row = self.fixture("interactive")[0]
        row["ipAddress"] = "198.51.100.10"
        self.add("interactive", [row])
        before = self.tree()
        for kind, value in (("email", "VICTIM@EXAMPLE.COM"), ("domain", "LOGIN.EXAMPLE.COM."),
                            ("ip", "198.51.100.10"), ("url", "https://login.example.com/a?x=1"),
                            ("sha256", "A" * 64), ("sha1", "B" * 40)):
            with self.subTest(kind=kind), patch("bec.graph.Graph", side_effect=AssertionError("No live calls")), \
                    patch("bec.workspace.Workspace", side_effect=AssertionError("No live calls")):
                result = search(self.case.path, kind, value)
                self.assertGreater(result["summary"]["matched_records"], 0)
                for hit in result["matches"]:
                    for observation in hit["observations"]:
                        self.assertTrue(observation["matches"])
                        for match in observation["matches"]:
                            self.assertEqual(match["canonical_value"], result["query"]["canonical_value"])
                            self.assertIn("equals", match["relation"])
                        for reference in observation["evidence"]:
                            raw = (self.case.path / reference["file"]).read_bytes()
                            self.assertEqual(digest(raw), reference["sha256"])
                            self.assertIsInstance(records(raw, hit["dataset"])[reference["record_index"]], dict)
        self.assertEqual(self.tree(), before)

    def test_domain_relations_are_exact_and_do_not_match_subdomains_or_suffixes(self):
        self.add("EmailEvents", [self.defender(SenderFromAddress="user@notexample.com", RecipientEmailAddress="user@sub.example.com")])
        self.add("EmailUrlInfo", [self.defender(Url="https://notexample.com/example.com", UrlDomain="sub.example.com")])
        self.assertEqual(search(self.case.path, "domain", "example.com")["summary"]["matched_records"], 0)
        self.add("EmailEvents", [self.defender(SenderFromAddress="user@example.com")])
        self.add("EmailUrlInfo", [self.defender(Url="https://EXAMPLE.com/a", UrlDomain="example.com")])
        result = search(self.case.path, "domain", "example.com")
        self.assertEqual(result["summary"]["matched_records"], 2)
        relations = {match["relation"] for hit in result["matches"] for event in hit["observations"] for match in event["matches"]}
        self.assertEqual(relations, {"email_domain_equals", "url_host_equals", "domain_field_equals"})

    def test_email_and_ip_prefixes_do_not_match(self):
        row = self.fixture("interactive")[0]
        row.update(userPrincipalName="notvictim@example.com", ipAddress="198.51.100.10")
        self.add("interactive", [row])
        self.assertEqual(search(self.case.path, "email", "victim@example.com")["summary"]["matched_records"], 0)
        self.assertEqual(search(self.case.path, "ip", "198.51.100.1")["summary"]["matched_records"], 0)

    def test_url_equality_retains_case_path_query_encoding_and_fragment(self):
        wanted = "https://example.com/a%2Fb?x=1#top"
        variants = [wanted, "https://EXAMPLE.com/a%2Fb?x=1#top", "https://example.com/a/b?x=1#top",
                    "https://example.com/a%2Fb?x=10#top", "https://example.com/a%2Fb?x=1#other",
                    "https://example.com/prefix/a%2Fb?x=1#top"]
        self.add("EmailUrlInfo", [self.defender(Url=url) for url in variants])
        result = search(self.case.path, "url", wanted)
        self.assertEqual(result["summary"]["matched_records"], 1)
        self.assertTrue(all(match["observed"] == wanted for match in result["matches"][0]["observations"][0]["matches"]))
        self.assertEqual(search(self.case.path, "domain", "example.com")["summary"]["matched_records"], len(variants))

    def test_ip_and_hash_normalization_do_not_guess_other_types(self):
        row = self.fixture("interactive")[0]
        row["ipAddress"] = "2001:db8::1"
        self.add("interactive", [row])
        self.assertEqual(search(self.case.path, "ip", "2001:0db8:0:0:0:0:0:1")["summary"]["matched_records"], 1)
        for kind, value in (("ip", "198.51.100.0/24"), ("ip", "fe80::1%eth0"), ("sha256", "a" * 40),
                            ("sha1", "g" * 40), ("domain", "*.example.com"), ("domain", "198.51.100.1"),
                            ("url", "javascript:alert(1)"), ("email", "Display Name <user@example.com>")):
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(CaseError):
                    search(self.case.path, kind, value)
        self.assertEqual(canonical("domain", "bücher.example"), "xn--bcher-kva.example")

    def test_duplicates_keep_all_references_without_inflating_unique_hits(self):
        row = self.defender(SenderFromAddress="victim@example.com", RecipientEmailAddress="victim@example.com")
        self.add("EmailEvents", [row, deepcopy(row)])
        self.add("EmailEvents", {"value": [dict(reversed(list(row.items())))]})
        self.add("EmailEvents", {"value": [json.dumps(row, indent=4)]})
        result = search(self.case.path, "email", "victim@example.com")
        self.assertEqual(result["summary"]["matched_records"], 1)
        self.assertEqual(result["summary"]["matched_observations"], 1)
        self.assertEqual(result["summary"]["source_references"], 4)
        self.assertEqual(len(result["matches"][0]["observations"][0]["evidence"]), 4)
        self.assertGreater(len(result["matches"][0]["observations"][0]["matches"]), 1)

    def test_conflicting_native_id_variants_remain_separate(self):
        row = self.fixture("interactive")[0]
        row["userPrincipalName"] = "victim@example.com"
        self.add("interactive", [row, {**row, "ipAddress": "203.0.113.99"}])
        result = search(self.case.path, "email", "victim@example.com")
        self.assertEqual(result["summary"]["matched_records"], 2)
        self.assertEqual(len({hit["record_fingerprint"] for hit in result["matches"]}), 2)
        self.assertEqual(len({event["event_id"] for hit in result["matches"] for event in hit["observations"]}), 1)

    def test_workspace_child_references_resolve_to_original_events(self):
        row = self.fixture("google_oauth")[0]
        row["events"].append(deepcopy(row["events"][0]))
        self.add("google_oauth", [row])
        result = search(self.case.path, "email", row["actor"]["email"])
        self.assertEqual(result["summary"]["matched_records"], 1)
        self.assertEqual(result["summary"]["matched_observations"], 2)
        self.assertEqual(result["summary"]["source_references"], 1)
        indexes = {ref["event_index"] for observation in result["matches"][0]["observations"] for ref in observation["evidence"]}
        self.assertEqual(indexes, {0, 1})
        for observation in result["matches"][0]["observations"]:
            for reference in observation["evidence"]:
                raw = (self.case.path / reference["file"]).read_bytes()
                self.assertEqual(digest(raw), reference["sha256"])
                original = records(raw, "google_oauth")[reference["record_index"]]
                self.assertEqual(original["events"][reference["event_index"]]["name"], "authorize")

    def test_integrity_and_native_binding_failures_are_not_no_match_results(self):
        self.add("interactive", self.fixture("interactive")[:1])
        raw = self.case.raw_path(self.case.manifest()["artifacts"][0])
        raw.write_bytes(b"[]")
        output = self.root / "invalid.json"
        status, _, error = self.cli("search", self.case.path, "email", "absent@example.com", "--output", output)
        self.assertEqual(status, 1)
        self.assertIn("verification failed", error)
        self.assertFalse(output.exists())
        other = create(self.root / "bound", "BOUND", "user@example.com", "2026-10-30T12:00Z", "2026-10-31T12:00Z",
            dict(tenant="BOUND", directory_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222"))
        row = self.fixture("interactive")[0]
        row.pop("tenant_id", None)
        row["organizationId"] = other.meta["directory_id"]
        acquire(other, "interactive", encode([row]), "export", dict(dataset="interactive"), 100000)
        other.meta["directory_id"] = "33333333-3333-3333-3333-333333333333"
        save(other.path / "case.json", other.meta)
        with self.assertRaises(CaseError):
            search(other.path, "email", "absent@example.com")

    def test_no_hit_keeps_coverage_gaps_and_unsupported_fields_visible(self):
        self.add("EmailEvents", [self.defender(Subject="victim@example.com", SenderFromAddress="sender@example.org")])
        self.add("interactive", [dict(id="bad-time", userPrincipalName="victim@example.com")])
        save(self.case.path / "collection_summary.json", dict(tenant=self.case.tenant, case_id=self.case.id,
            mode="export", queries={"missing": dict(dataset="ual", status="gap", reason="No usable export supplied.")}, gaps=[]))
        result = search(self.case.path, "email", "victim@example.com")
        self.assertEqual(result["summary"]["matched_records"], 0)
        self.assertEqual(result["field_coverage"]["interactive"]["normalization_issues"], 1)
        self.assertEqual(result["case"]["coverage"]["ual"]["queries"][0]["status"], "gap")
        self.assertTrue(any("does not establish absence" in note for note in result["limitations"]))
        self.assertTrue(any("Subjects" in note for note in result["limitations"]))

    def test_invalid_structured_values_are_counted_without_string_search_fallback(self):
        self.add("EmailUrlInfo", [self.defender(Url="javascript:example.com", UrlDomain="https://example.com")])
        self.add("EmailAttachmentInfo", [self.defender(SHA256="not-a-hash " + "a" * 64)])
        for kind, value, dataset in (("url", "https://example.com", "EmailUrlInfo"),
                                     ("domain", "example.com", "EmailUrlInfo"),
                                     ("sha256", "a" * 64, "EmailAttachmentInfo")):
            with self.subTest(kind=kind):
                result = search(self.case.path, kind, value)
                self.assertEqual(result["summary"]["matched_records"], 0)
                self.assertGreater(result["field_coverage"][dataset]["ignored_invalid_values"], 0)
                self.assertEqual(result["field_coverage"][dataset]["searchable_values"], 0)

    def test_outputs_are_private_safe_and_html_never_links_indicator_urls(self):
        row = self.defender(SenderFromAddress="victim@example.com", Subject='<script>alert("unsafe")</script>')
        self.add("EmailEvents", [row])
        before = self.tree()
        result = search(self.case.path, "email", "victim@example.com")
        for path in (self.case.path / "hit.json", self.case.path / "timeline" / "hit.html"):
            with self.assertRaisesRegex(CaseError, "outside the input case"):
                write_report(result, path, "json")
        existing = self.root / "existing.json"
        existing.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            write_report(result, existing, "json")
        output = self.root / "search.html"
        status, _, error = self.cli("search", self.case.path, "email", "victim@example.com", "--format", "html", "--output", output)
        self.assertEqual(status, 0, error)
        document = output.read_text(encoding="utf-8")
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn('href="file:', document)
        self.assertNotIn('href="http', document)
        self.assertEqual(self.tree(), before)

    def test_pending_or_changing_inputs_are_refused(self):
        self.add("interactive", self.fixture("interactive")[:1])
        journal = self.case.path / ".pending-artifact.json"
        save(journal, {"leave": "untouched"})
        before = self.tree()
        with self.assertRaisesRegex(CaseError, "pending acquisition"):
            search(self.case.path, "email", "compromised@example.com")
        self.assertEqual(self.tree(), before)
        journal.unlink()
        from bec.search import normalize

        def mutate(*arguments):
            save(self.case.path / "pivots" / "analyst.json", [["user", "new@example.com"]])
            return normalize(*arguments)

        with patch("bec.search.normalize", side_effect=mutate):
            with self.assertRaisesRegex(CaseError, "changed during comparison"):
                search(self.case.path, "email", "compromised@example.com")


if __name__ == "__main__":
    unittest.main()
