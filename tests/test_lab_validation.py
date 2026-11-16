"""Offline lab-checker tests are not live tenant qualification."""
import io
import importlib.util
import json
import os
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bec.collection import acquire
from bec.storage import CaseError, DATA, create, digest, encode, iso, read, save
script = Path(__file__).resolve().parents[1] / "scripts" / "validate_lab.py"
spec = importlib.util.spec_from_file_location("bec_lab_validation", script)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.user = "lab-user@lab-owned-domain.org"
        self.profile = dict(tenant="LAB-OWNED", directory_id="e0166570-4b52-4d1a-a32c-70db62a96716",
            client_id="12345678-9abc-4def-8123-456789abcdef", options=dict(defender=False))
        self.profile_path = self.root / "profile.json"
        save(self.profile_path, self.profile)
        self.plan = dict(schema_version=1, authorization_reference="Offline unit test only; no live authorization.",
            profile=str(self.profile_path), tenant=self.profile["tenant"], users=[self.user],
            start="2026-10-30T12:00:00Z", end="2026-10-31T12:00:00Z",
            credential_source=dict(microsoft="client_secret"), required_sources=["interactive"],
            expected_events=[dict(user=self.user, dataset="interactive", source_event_id="lab-observation",
                                 event_type="authentication.success", actor=self.user)])
        self.plan_path = self.root / "plan.json"
        save(self.plan_path, self.plan)

    def target(self):
        save(self.plan_path, self.plan)
        return lab.prepare(self.plan_path)

    def observed(self, fixture=False, mode="live", collector="graph"):
        target = self.target()
        case = create(self.root / "cases", target["tenant"], self.user, target["start"], target["end"], target["profile"])
        rows = read(DATA / "demo" / "interactive.json")
        rows = rows.get("value") if isinstance(rows, dict) else rows
        row = dict(rows[0])
        if not fixture:
            row.update(id="lab-observation", userPrincipalName=self.user, createdDateTime="2026-10-30T20:00:00Z")
            row.pop("tenant_id", None)
        else:
            # Use the exact known fixture row and alias while retaining the explicit test-native binding.
            target["tenant"] = "TEST"
            target["profile"]["tenant"] = "TEST"
            case = create(self.root / "fixture-cases", "TEST", self.user, target["start"], target["end"], target["profile"])
            row = rows[0]
        queries = target["query_preview"][self.user]
        primary = next(query for query in queries if query["dataset"] == "interactive")
        started = iso(datetime.now(UTC) - timedelta(seconds=1))
        acquire(case, "interactive", encode([row]), collector, primary, 5000)
        state = dict(case_id=case.id, tenant=case.tenant, mode=mode,
            queries={digest(encode(query)): {**query, "status": "collected", "records": 1 if query == primary else 0}
                     for query in queries}, gaps=[])
        save(case.path / "collection_summary.json", state)
        receipt = dict(collector_invoked=True, case_id=case.id, collect_exit=0, started=started, finished=iso(datetime.now(UTC)))
        return case, target, receipt

    def test_preflight_is_offline_and_bounded(self):
        with patch.object(lab.subprocess, "run", side_effect=AssertionError("No processes or providers during preflight")):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(lab.main(["preflight", "--plan", str(self.plan_path)]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "not_executed")
        self.assertFalse(result["provider_calls"])
        options = result["plan"]["profile"]["options"]
        self.assertEqual(options["baseline_days"], 0)
        self.assertEqual(options["max_depth"], 0)
        self.assertLessEqual(options["max_events"], 5000)
        self.assertTrue(all(query["kind"] == "user" and query["value"] == self.user
                            for query in result["plan"]["query_preview"][self.user]))

    def test_missing_expectations_and_example_targets_are_refused(self):
        for change in (dict(expected_events=[]), dict(users=["analyst@example.com"]),
                       dict(end="2026-11-03T12:00:00Z"), dict(credential_source={})):
            with self.subTest(change=change):
                save(self.plan_path, {**self.plan, **change})
                with self.assertRaises(CaseError):
                    lab.prepare(self.plan_path)
        save(self.profile_path, {**self.profile, "directory_id": "11111111-1111-1111-1111-111111111111"})
        save(self.plan_path, self.plan)
        with self.assertRaises(CaseError):
            lab.prepare(self.plan_path)

    def test_export_and_demo_fixture_cannot_qualify_as_live(self):
        for fixture, mode, collector in ((False, "export", "export"), (True, "live", "graph")):
            with self.subTest(fixture=fixture):
                case, target, receipt = self.observed(fixture, mode, collector)
                result = lab.assess(case.path, target, self.user, receipt)
                self.assertEqual(result["gates"]["live_origin"], "failed")
                self.assertEqual(result["status"], "failed")
                if fixture:
                    self.assertFalse(result["origin_evidence"]["fixture_free"])

    def test_missing_execution_receipt_cannot_qualify(self):
        case, target, receipt = self.observed()
        receipt["collector_invoked"] = False
        result = lab.assess(case.path, target, self.user, receipt)
        self.assertEqual(result["gates"]["live_origin"], "failed")

    def test_absent_pagination_or_restricted_access_remains_untested(self):
        case, target, receipt = self.observed()
        result = lab.assess(case.path, target, self.user, receipt)
        self.assertEqual(result["gates"]["expected_events"], "passed")
        self.assertEqual(result["gates"]["pagination"], "not_exercised")
        self.assertEqual(result["gates"]["permission_failures"], "not_exercised")
        self.assertEqual(result["status"], "incomplete")
        target["pagination_sources"] = ["interactive"]
        target["permission_denied_sources"] = ["ual"]
        result = lab.assess(case.path, target, self.user, receipt)
        self.assertEqual(result["gates"]["pagination"], "not_observed")
        self.assertEqual(result["gates"]["permission_failures"], "not_observed")
        self.assertNotEqual(result["status"], "passed_for_declared_scope")

    def test_expected_event_mismatch_and_unexpected_gap_fail(self):
        case, target, receipt = self.observed()
        target["expected_events"][0]["source_event_id"] = "missing"
        state = read(case.path / "collection_summary.json")
        key = next(key for key, query in state["queries"].items() if query["dataset"] == "ual")
        state["queries"][key].update(status="gap", reason="Graph HTTP 500: request failed.")
        save(case.path / "collection_summary.json", state)
        target["permission_denied_sources"] = ["ual"]
        result = lab.assess(case.path, target, self.user, receipt)
        self.assertEqual(result["gates"]["expected_events"], "failed")
        self.assertEqual(result["gates"]["unexpected_gaps"], "failed")

    def test_tampered_evidence_rejected(self):
        case, target, receipt = self.observed()
        entry = case.manifest()["artifacts"][0]
        case.raw_path(entry).write_bytes(b"[]")
        with self.assertRaises(CaseError):
            lab.assess(case.path, target, self.user, receipt)

    def test_observed_pagination_and_permission_checks_do_not_replace_live_origin(self):
        case, target, receipt = self.observed()
        target["pagination_sources"] = ["interactive"]
        target["permission_denied_sources"] = ["ual"]
        state = read(case.path / "collection_summary.json")
        query = next(query for query in target["query_preview"][self.user] if query["dataset"] == "interactive")
        acquire(case, "interactive", encode({"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?page=2"}),
                "graph", query, 5000)
        acquire(case, "interactive", encode({"value": []}), "graph", query, 5000)
        key = next(key for key, query in state["queries"].items() if query["dataset"] == "ual")
        state["queries"][key].update(status="gap", reason="Graph HTTP 403: check application consent.")
        save(case.path / "collection_summary.json", state)
        receipt.update(collector_invoked=False, finished=iso(datetime.now(UTC)))
        result = lab.assess(case.path, target, self.user, receipt)
        self.assertEqual(result["gates"]["pagination"], "passed")
        self.assertEqual(result["gates"]["permission_failures"], "passed")
        self.assertEqual(result["gates"]["live_origin"], "failed")
        self.assertEqual(result["status"], "failed")

    def test_run_requires_selected_credentials_before_any_process(self):
        target = self.target()
        output = self.root / "unstarted-run"
        with patch.dict(os.environ, {}, clear=True), patch.object(lab.subprocess, "run") as process:
            with self.assertRaises(CaseError):
                lab.run(target, output)
        process.assert_not_called()
        self.assertFalse(output.exists())

    def test_public_summary_omits_identifiers_paths_and_private_errors(self):
        case, target, receipt = self.observed()
        assessed = lab.assess(case.path, target, self.user, receipt)
        result = dict(tool=dict(version="0.7.0", module="C:/private/user-identifiers"), cases=[assessed],
                      live_execution=True, status="incomplete", private_error="private IP 10.0.0.1 and secret profile")
        public = json.dumps(lab.public_summary(result))
        for private in (self.user, target["tenant"], self.profile["directory_id"], str(case.path), "10.0.0.1", "secret profile"):
            self.assertNotIn(private, public)
        self.assertIn("not_exercised", public)

    def test_only_selected_credential_mechanism_is_inherited(self):
        target = self.target()
        with patch.dict(os.environ, dict(BEC_CLIENT_SECRET="unit-test", BEC_CERTIFICATE_PATH="unselected",
                                        BEC_GOOGLE_SERVICE_ACCOUNT="unselected"), clear=True):
            environment = lab.credential_environment(target)
        self.assertEqual(environment["BEC_CLIENT_SECRET"], "unit-test")
        self.assertNotIn("BEC_CERTIFICATE_PATH", environment)
        self.assertNotIn("BEC_GOOGLE_SERVICE_ACCOUNT", environment)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CaseError):
                lab.credential_environment(target)


if __name__ == "__main__":
    unittest.main()
