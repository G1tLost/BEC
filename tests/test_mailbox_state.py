import copy
import json
import tempfile
import unittest
from pathlib import Path
from bec.storage import create, CaseError, digest
from bec.mailbox_state import import_snapshot, view_snapshot


class MailboxStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tenant = '11111111-1111-1111-1111-111111111111'
        self.case = create(self.root / 'cases', 'TEST', 'user@example.com', '2026-01-01T00:00Z',
                           '2026-01-02T00:00Z', dict(tenant='TEST', directory_id=self.tenant, client_id=self.tenant))
        self.source = self.root / 'input.json'
        self.output = self.root / 'import'
        self.obj = dict(schema='response-menu.mailbox-snapshot.v1', tenant_id=self.tenant,
                        mailbox_upn='user@example.com', acquired_at='2026-01-03T00:00:00Z', synthetic=True,
                        evidence_class='reserialized-source-objects', sources={
                            'inbox_rules': dict(status='partial', records=[{'Name': 'test', 'Enabled': False}]),
                            'forwarding': dict(status='collected', records=[]),
                            'delegates': dict(status='unavailable', records=[])})

    def write(self):
        self.source.write_bytes(b'\xef\xbb\xbf' + json.dumps(self.obj, indent=3).encode())

    def test_roundtrip_exact_bytes_and_unchanged_case(self):
        self.write()
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.case.path.rglob('*') if p.is_file()}
        receipt = import_snapshot(self.case.path, self.source, self.output)
        self.assertEqual(receipt['sha256'], digest(self.source.read_bytes()))
        self.assertEqual(self.source.read_bytes(), (self.output / 'snapshot.json').read_bytes())
        result = view_snapshot(self.case.path, self.output)
        row = result['current_snapshot']['inbox_rules']['records'][0]
        self.assertEqual(row['record'], self.obj['sources']['inbox_rules']['records'][0])
        self.assertEqual(row['evidence']['json_pointer'], '/sources/inbox_rules/records/0')
        self.assertEqual(result['historical_rule_activity'], [])
        self.assertIsNone(result['historical_coverage'])
        after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.case.path.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_binding_and_contract_refusals(self):
        original = copy.deepcopy(self.obj)
        for key, value in [('tenant_id', '22222222-2222-2222-2222-222222222222'),
                           ('mailbox_upn', 'other@example.com'), ('mailbox_upn', 'USER@example.com'),
                           ('acquired_at', '2026-01-01T00:00:00'), ('acquired_at', '2026-01-01T00:00:00+02:00'),
                           ('synthetic', 'true'), ('evidence_class', 'original-provider-bytes')]:
            with self.subTest(key=key, value=value):
                self.obj = {**original, key: value}; self.write()
                with self.assertRaises((CaseError, ValueError)):
                    import_snapshot(self.case.path, self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_unbound_real_and_synthetic_refused(self):
        case = create(self.root / 'unbound', 'TEST', 'user@example.com', '2026-01-01T00:00Z', '2026-01-02T00:00Z')
        for synthetic in (False, True):
            self.obj['synthetic'] = synthetic; self.write()
            with self.assertRaises(CaseError):
                import_snapshot(case.path, self.source, self.output)

    def test_coverage_invalid_and_missing(self):
        for change in ('status', 'records', 'missing'):
            obj = copy.deepcopy(self.obj)
            if change == 'status': obj['sources']['inbox_rules']['status'] = 'clean'
            if change == 'records': obj['sources']['delegates']['records'] = [{}]
            if change == 'missing': del obj['sources']['forwarding']
            self.source.write_text(json.dumps(obj))
            with self.assertRaises(CaseError): import_snapshot(self.case.path, self.source, self.output)

    def test_tampered_and_overwrite_refused(self):
        self.write(); import_snapshot(self.case.path, self.source, self.output)
        with self.assertRaises(CaseError): import_snapshot(self.case.path, self.source, self.output)
        (self.output / 'snapshot.json').write_text('{}')
        with self.assertRaises(CaseError): view_snapshot(self.case.path, self.output)

    def test_protected_output_and_symlink(self):
        self.write()
        with self.assertRaises(CaseError): import_snapshot(self.case.path, self.source, self.case.path / 'extra')
        link = self.root / 'link.json'; link.symlink_to(self.source)
        with self.assertRaises(CaseError): import_snapshot(self.case.path, link, self.output)

    def test_duplicate_keys_refused(self):
        self.write(); data = self.source.read_text(encoding='utf-8-sig')
        self.source.write_text(data.replace('"synthetic": true', '"synthetic": true, "synthetic": false'))
        with self.assertRaises(CaseError): import_snapshot(self.case.path, self.source, self.output)

    def test_opaque_delegate_wrapper_preserved(self):
        wrapped = {'source': 'Exchange.Mailbox.SendOnBehalf', 'record': {'Value': ['a@example.com']}}
        self.obj['sources']['delegates'] = dict(status='collected', records=[wrapped])
        self.write(); import_snapshot(self.case.path, self.source, self.output)
        result = view_snapshot(self.case.path, self.output)
        self.assertEqual(result['current_snapshot']['delegates']['records'][0]['record'], wrapped)

    def test_historical_rules_separate_from_current_state(self):
        from bec.collection import acquire
        from bec.storage import encode
        row = dict(Id='rule1', CreationTime='2026-01-01T12:00:00Z', Operation='New-InboxRule',
                   UserId='user@example.com', ObjectId='user@example.com', ResultStatus='Succeeded')
        acquire(self.case, 'ual', encode([row]), 'export', dict(dataset='ual'), 100000)
        self.write(); import_snapshot(self.case.path, self.source, self.output)
        result = view_snapshot(self.case.path, self.output)
        self.assertEqual(len(result['historical_rule_activity']), 1)
        self.assertEqual(result['historical_rule_activity'][0]['observation']['event_type'], 'mail.rule.create')
        self.assertFalse(result['current_snapshot']['inbox_rules']['records'][0]['record']['Enabled'])

    def test_cli_json_and_no_collection(self):
        from bec.cli import main
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        self.write()
        with patch('bec.collection.Collection.collect', side_effect=AssertionError('network collection forbidden')):
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(['snapshot-import', str(self.case.path), str(self.source), '--output', str(self.output)]), 0)
            json.loads(output.getvalue())
            with redirect_stdout(StringIO()) as result:
                self.assertEqual(main(['snapshot-view', str(self.case.path), str(self.output)]), 0)
            self.assertTrue(json.loads(result.getvalue())['synthetic'])

    def test_historical_half_open_window_and_undated_gap(self):
        from bec.collection import acquire
        from bec.storage import encode
        times = ['2025-12-31T23:59:59Z', '2026-01-01T00:00:00Z',
                 '2026-01-01T23:59:59Z', '2026-01-02T00:00:00Z', None]
        rows = [dict(Id=str(i), CreationTime=t, Operation='New-InboxRule', UserId='user@example.com',
                     ObjectId='user@example.com', ResultStatus='Succeeded') for i, t in enumerate(times)]
        acquire(self.case, 'ual', encode(rows), 'export', dict(dataset='ual'), 100000)
        self.write(); import_snapshot(self.case.path, self.source, self.output)
        result = view_snapshot(self.case.path, self.output)
        self.assertEqual([r['observation']['source_event_id'] for r in result['historical_rule_activity']], ['1', '2'])
        self.assertEqual(result['historical_unparseable_ual_observations'], 1)
        self.assertEqual(result['historical_window']['bounds'], '[start,end)')
        self.assertEqual(result['tenant_id'], self.tenant)
