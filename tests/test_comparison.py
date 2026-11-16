"""Offline comparison acceptance: provenance, identity, coverage, integrity and no writes."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from bec.cli import main
from bec.collection import acquire
from bec.comparison import _canonical_record, compare, write_report
from bec.normalize import records
from bec.storage import CaseError, DATA, create, digest, encode, read, save


USER = "compromised@example.com"
START, END = "2026-10-30T12:00Z", "2026-10-31T12:00Z"


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def case(self, tenant="TEST", **profile):
        return create(self.root / "cases", tenant, USER, START, END,
                      dict(tenant=tenant, options=dict(defender=False), **profile))

    def add(self, case, dataset, rows):
        acquire(case, dataset, encode(rows), "export", dict(dataset=dataset, start=START, end=END), 100000)

    def fixture(self, dataset):
        return records((DATA / "demo" / (dataset + ".json")).read_bytes(), dataset)

    def tree(self, case):
        return {str(path.relative_to(case.path)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in case.path.rglob("*") if path.is_file()}

    def cli(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([str(argument) for argument in arguments])
        return code, out.getvalue(), err.getvalue()

    def test_identical_reordered_and_duplicate_rows_have_no_evidence_delta(self):
        before, after = self.case(), self.case()
        rows = self.fixture("interactive")[:3]
        self.add(before, "interactive", rows)
        # Dictionary key order, row order and duplicate copies are not new observations.
        reordered = [dict(reversed(list(row.items()))) for row in reversed(rows)]
        self.add(after, "interactive", reordered + [reordered[0]])
        previous = (self.tree(before), self.tree(after))
        result = compare(before.path, after.path)
        self.assertEqual(result["summary"]["newly_observed"], 0)
        self.assertEqual(result["summary"]["only_in_earlier"], 0)
        self.assertEqual(result["summary"]["unchanged"], 3)
        self.assertEqual(result["summary"]["identity_conflicts"], 0)
        self.assertEqual(result["after"]["duplicate_occurrences"], 1)
        self.assertEqual((self.tree(before), self.tree(after)), previous)
        same = compare(before.path, before.path)
        self.assertEqual(same["summary"]["coverage_changes"], 0)

    def test_added_signin_rule_and_oauth_have_resolvable_source_references(self):
        profile = dict(microsoft=True, google_workspace=dict(customer_id="C02becdemo"))
        before, after = self.case(**profile), self.case(**profile)
        for dataset in ("interactive", "ual", "google_oauth"):
            row = next((row for row in self.fixture(dataset)
                        if dataset != "ual" or "New-InboxRule" in json.dumps(row)), self.fixture(dataset)[0])
            self.add(after, dataset, [row, deepcopy(row)])
        previous = (self.tree(before), self.tree(after))
        with patch("bec.graph.Graph", side_effect=AssertionError("No live provider")), \
                patch("bec.workspace.Workspace", side_effect=AssertionError("No live provider")):
            result = compare(before.path, after.path)
        self.assertEqual(result["summary"]["newly_observed"], 3)
        self.assertEqual(result["after"]["duplicate_occurrences"], 3)
        types = {observation["event_type"] for item in result["newly_observed"] for observation in item["observations"]}
        self.assertTrue({"authentication.success", "mail.rule.create", "google.oauth.grant"} <= types)
        for item in result["newly_observed"]:
            self.assertEqual(len(item["evidence"]), 2)
            for ref in item["evidence"]:
                data = (Path(ref["case_directory"]) / ref["file"]).read_bytes()
                self.assertEqual(digest(data), ref["sha256"])
                row = records(data, item["dataset"])[ref["record_index"]]
                self.assertEqual(digest(encode(dict(dataset=item["dataset"],
                    record=_canonical_record(item["dataset"], row)))), item["fingerprint"])
                self.assertTrue(ref["uri"].startswith("file:"))
        self.assertEqual((self.tree(before), self.tree(after)), previous)

    def test_same_native_id_different_content_is_visible_even_within_one_case(self):
        before, after = self.case(), self.case()
        original = self.fixture("interactive")[0]
        changed = {**original, "ipAddress": "203.0.113.99", "newVendorField": "retained"}
        self.add(before, "interactive", [original])
        self.add(after, "interactive", [original, changed, changed])
        result = compare(before.path, after.path)
        self.assertEqual(result["summary"]["newly_observed"], 1)
        self.assertEqual(result["summary"]["identity_conflicts"], 1)
        conflict, = result["identity_conflicts"]
        self.assertTrue(conflict["changed"])
        self.assertEqual(len(conflict["before"]), 1)
        self.assertEqual(len(conflict["after"]), 2)
        unchanged_conflict = compare(after.path, after.path)
        self.assertEqual(unchanged_conflict["summary"]["newly_observed"], 0)
        self.assertEqual(unchanged_conflict["summary"]["changed_identity_conflicts"], 0)
        self.assertEqual(unchanged_conflict["summary"]["identity_conflicts"], 1)

    def test_supported_json_string_wrappers_have_equivalent_fingerprints(self):
        for dataset in ("interactive", "ual"):
            with self.subTest(dataset=dataset):
                before, after = self.case(), self.case()
                row = self.fixture(dataset)[0]
                if dataset == "ual":
                    from bec.normalize import ual_body
                    row = dict(AuditData=ual_body(row))
                self.add(before, dataset, [row])
                reordered = dict(reversed(list(row.items())))
                if dataset == "ual":
                    reordered["AuditData"] = json.dumps(dict(reversed(list(row["AuditData"].items()))), indent=4)
                self.add(after, dataset, [json.dumps(reordered, indent=2), reordered])
                result = compare(before.path, after.path)
                self.assertEqual(result["summary"]["newly_observed"], 0)
                self.assertEqual(result["summary"]["only_in_earlier"], 0)
                self.assertEqual(result["summary"]["identity_conflicts"], 0)
                self.assertEqual(result["after"]["duplicate_occurrences"], 1)

    def test_malformed_case_metadata_is_a_clear_cli_error(self):
        for mutation in ([], dict(options=[]), dict(google_workspace="not an object"),
                         dict(directory_id=42), dict(microsoft="yes"), dict(user=None)):
            with self.subTest(mutation=mutation):
                before, after = self.case(), self.case()
                metadata = {**after.meta, **mutation} if isinstance(mutation, dict) else mutation
                save(after.path / "case.json", metadata)
                previous = self.tree(after)
                code, out, error = self.cli("compare", before.path, after.path)
                self.assertEqual(code, 1, out)
                self.assertTrue(error.startswith("BEC: "), error)
                self.assertNotIn("Traceback", error)
                self.assertEqual(self.tree(after), previous)

    def test_window_scope_coverage_and_absence_are_explicit(self):
        before, after = self.case(), self.case()
        self.add(before, "ual", self.fixture("ual")[:1])
        after.meta["start"] = "2026-10-31T00:00:00Z"
        after.meta["options"]["defender"] = True
        save(after.path / "case.json", after.meta)
        save(after.path / "collection_summary.json", dict(tenant=after.tenant, case_id=after.id,
            mode="live", queries={"missing": dict(dataset="ual", status="gap", reason="Permission denied.")}, gaps=[]))
        result = compare(before.path, after.path)
        self.assertEqual(result["summary"]["only_in_earlier"], 1)
        self.assertTrue({"incident_window", "options", "collection_mode"} <=
                        {change["field"] for change in result["context_changes"]})
        self.assertEqual(result["after"]["coverage"]["ual"]["queries"][0]["status"], "gap")
        self.assertTrue(any("never establishes deletion" in note for note in result["interpretation"]))
        self.assertNotIn("deleted", result)

    def test_tenant_directory_and_workspace_bindings_must_match(self):
        base = self.case()
        variants = [self.case(tenant="OTHER"),
            self.case(directory_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222"),
            self.case(google_workspace=dict(customer_id="C02example"))]
        for other in variants:
            with self.subTest(binding=other.meta):
                with self.assertRaisesRegex(CaseError, "matching tenant aliases"):
                    compare(base.path, other.path)
        first = self.case(google_workspace=dict(customer_id="C01example"))
        second = self.case(google_workspace=dict(customer_id="C02example"))
        with self.assertRaises(CaseError):
            compare(first.path, second.path)

    def test_tampered_missing_and_unmanifested_evidence_reject_without_writes(self):
        for kind in ("tampered", "missing", "unmanifested", "bad_count", "bad_identity"):
            with self.subTest(kind=kind):
                before, after = self.case(), self.case()
                self.add(after, "interactive", self.fixture("interactive")[:1])
                manifest = read(after.path / "evidence_manifest.json")
                artifact = after.path / manifest["artifacts"][0]["artifact"]
                if kind == "tampered":
                    artifact.write_bytes(b"[]")
                elif kind == "missing":
                    artifact.unlink()
                elif kind == "unmanifested":
                    (artifact.parent / ("0" * 64 + ".json")).write_bytes(b"[]")
                elif kind == "bad_count":
                    manifest["artifacts"][0]["records"] += 1
                    save(after.path / "evidence_manifest.json", manifest)
                else:
                    manifest["tenant"] = "OTHER"
                    save(after.path / "evidence_manifest.json", manifest)
                previous = (self.tree(before), self.tree(after))
                output = self.root / (kind + ".json")
                code, out, err = self.cli("compare", before.path, after.path, "--output", output)
                self.assertEqual(code, 1, out + err)
                self.assertFalse(output.exists())
                self.assertEqual((self.tree(before), self.tree(after)), previous)

    def test_pending_transaction_is_not_recovered_by_comparison(self):
        before, after = self.case(), self.case()
        save(after.path / ".pending-artifact.json", {"pending": "leave untouched"})
        previous = self.tree(after)
        with self.assertRaisesRegex(CaseError, "pending acquisition"):
            compare(before.path, after.path)
        self.assertEqual(self.tree(after), previous)

    def test_changed_input_during_read_is_rejected(self):
        before, after = self.case(), self.case()
        self.add(after, "interactive", self.fixture("interactive")[:1])
        from bec.comparison import _describe

        def changed(*arguments):
            save(after.path / "collection_summary.json", dict(tenant=after.tenant, case_id=after.id, queries={}))
            return _describe(*arguments)

        with patch("bec.comparison._describe", side_effect=changed):
            with self.assertRaisesRegex(CaseError, "changed during comparison"):
                compare(before.path, after.path)

    def test_output_cannot_overwrite_existing_files_or_enter_input_cases(self):
        before, after = self.case(), self.case()
        result = compare(before.path, after.path)
        for path in (before.path / "new.json", after.path / "timeline" / "delta.html"):
            with self.assertRaisesRegex(CaseError, "outside both input cases"):
                write_report(result, path, "json")
            self.assertFalse(path.exists())
        existing = self.root / "existing.json"
        existing.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            write_report(result, existing, "json")
        self.assertEqual(existing.read_bytes(), b"preserve")

    def test_cli_json_and_html_reports_link_evidence_and_escape_vendor_text(self):
        before, after = self.case(), self.case()
        row = self.fixture("directory")[0]
        row["activityDisplayName"] = '<script>alert("unsafe")</script>'
        self.add(after, "directory", [row])
        previous = (self.tree(before), self.tree(after))
        code, output, error = self.cli("compare", before.path, after.path)
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual(result["summary"]["newly_observed"], 1)
        html_file = self.root / "reports" / "delta.html"
        code, output, error = self.cli("compare", before.path, after.path, "--format", "html", "--output", html_file)
        self.assertEqual(code, 0, error)
        document = html_file.read_text(encoding="utf-8")
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn('href="file:', document)
        self.assertEqual((self.tree(before), self.tree(after)), previous)

    def test_raw_record_and_byte_budgets_are_enforced(self):
        before, after = self.case(), self.case()
        self.add(after, "interactive", self.fixture("interactive")[:2])
        after.meta["options"]["max_events"] = 1
        save(after.path / "case.json", after.meta)
        with self.assertRaisesRegex(CaseError, "raw-record budget"):
            compare(before.path, after.path)
        after.meta["options"]["max_events"] = 100000
        save(after.path / "case.json", after.meta)
        with patch("bec.comparison.MAX_CASE_BYTES", 1):
            with self.assertRaisesRegex(CaseError, "raw-evidence limit"):
                compare(before.path, after.path)


if __name__ == "__main__":
    unittest.main()
