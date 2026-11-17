"""Exercise the installed wheel outside this checkout, using only synthetic data."""
import json
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def run(directory, *args):
    result = subprocess.run([sys.executable, '-I', '-m', 'bec', *args], cwd=directory,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def snapshot(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob('*') if path.is_file()}


def vendor_rows(data):
    value = json.loads(data)
    return value.get('value', value.get('results', value.get('Results', value.get('items')))) if isinstance(value, dict) else value


with tempfile.TemporaryDirectory(prefix='bec-installed-') as folder:
    root = Path(folder) / 'cases'
    run(folder, '--root', str(root), 'demo')
    cases = list(root.glob('TEST/INC-*/case.json'))
    assert len(cases) == 1
    case = cases[0].parent
    payload = json.loads((case / 'timeline/timeline.json').read_text(encoding='utf-8'))
    assert payload['summary']['event_count'] == 30
    assert payload['summary']['gaps'] == 0
    assert (case / 'timeline/timeline.html').is_file()
    assert not (case / 'acquisitions.json').exists()
    run(folder, '--root', str(root), 'verify', case.name)
    run(folder, '--root', str(root), 'demo')
    later, = [path.parent for path in root.glob('TEST/INC-*/case.json') if path.parent != case]
    identical = json.loads(run(folder, 'compare', str(case), str(later)))
    assert identical['summary']['newly_observed'] == 0
    assert identical['summary']['only_in_earlier'] == 0

    manifest = json.loads((later / 'evidence_manifest.json').read_text(encoding='utf-8'))
    entry = next(item for item in manifest['artifacts'] if item['dataset'] == 'interactive')
    original = json.loads((later / entry['artifact']).read_text(encoding='utf-8'))
    rows = original['value'] if isinstance(original, dict) else original
    added = dict(next(row for row in rows if row.get('userPrincipalName') == 'compromised@example.com'))
    added.update(id='installed-comparison-added-signin', createdDateTime='2026-10-30T23:45:00Z')
    exports = Path(folder) / 'exports'
    exports.mkdir()
    (exports / 'added.json').write_text(json.dumps([added]), encoding='utf-8')
    bundle = exports / 'bundle.json'
    bundle.write_text(json.dumps(dict(tenant='TEST', files=[dict(dataset='interactive', path='added.json')])), encoding='utf-8')
    run(folder, '--root', str(root), 'investigate', later.name, '--bundle', str(bundle))
    before_bytes = snapshot(case), snapshot(later)
    delta = json.loads(run(folder, 'compare', str(case), str(later)))
    assert delta['summary']['newly_observed'] == 1
    assert delta['summary']['only_in_earlier'] == 0
    observation, = delta['newly_observed']
    assert observation['identity']['native_id'] == added['id']
    reference, = observation['evidence']
    source = (Path(reference['case_directory']) / reference['file']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == reference['sha256']
    assert json.loads(source)[reference['record_index']]['id'] == added['id']
    report = Path(folder) / 'comparison.html'
    run(folder, 'compare', str(case), str(later), '--format', 'html', '--output', str(report))
    assert 'href="file:' in report.read_text(encoding='utf-8')

    email = json.loads(run(folder, 'search', str(case), 'email', 'COMPROMISED@EXAMPLE.COM'))
    assert email['summary']['matched_records'] > 0
    evidence = email['matches'][0]['observations'][0]['evidence'][0]
    raw = (case / evidence['file']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == evidence['sha256']
    assert isinstance(vendor_rows(raw)[evidence['record_index']], dict)
    url_entry = next(item for item in manifest['artifacts'] if item['dataset'] == 'EmailUrlInfo')
    url_row = vendor_rows((later / url_entry['artifact']).read_bytes())[0]
    url = url_row.get('Url', url_row.get('url'))
    assert json.loads(run(folder, 'search', str(case), 'url', url))['summary']['matched_records'] > 0
    missing = json.loads(run(folder, 'search', str(case), 'url', url + '__not_observed__'))
    assert missing['summary']['matched_records'] == 0
    assert missing['limitations'] and missing['field_coverage']
    attachment_entry = next(item for item in manifest['artifacts'] if item['dataset'] == 'EmailAttachmentInfo')
    attachment = vendor_rows((later / attachment_entry['artifact']).read_bytes())[0]
    attachment_hash = attachment.get('SHA256', attachment.get('sha256'))
    assert json.loads(run(folder, 'search', str(case), 'sha256', attachment_hash.upper()))['summary']['matched_records'] > 0
    search_report = Path(folder) / 'indicator-search.html'
    run(folder, 'search', str(case), 'email', 'compromised@example.com', '--format', 'html', '--output', str(search_report))
    assert 'href="file:' in search_report.read_text(encoding='utf-8')
    assert 'href="https:' not in search_report.read_text(encoding='utf-8')
    assert (snapshot(case), snapshot(later)) == before_bytes

    # Independently authored v1 fixture; no producer runtime or live credentials.
    native_tenant = '33333333-3333-4333-8333-333333333333'
    profile = Path(folder) / 'synthetic-profile.json'
    profile.write_text(json.dumps(dict(tenant='SNAPSHOT', directory_id=native_tenant,
                                      client_id=native_tenant)), encoding='utf-8')
    case_id = run(folder, '--root', str(root), 'case', 'create', '--tenant', 'SNAPSHOT',
                  '--user', 'mailbox@example.com', '--start', '2026-01-01T00:00:00Z',
                  '--end', '2026-01-02T00:00:00Z', '--config', str(profile)).strip()
    bound_case = root / 'SNAPSHOT' / case_id
    bound_before = {str(path.relative_to(bound_case)): (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in bound_case.rglob('*') if path.is_file()}
    current = dict(schema='response-menu.mailbox-snapshot.v1', tenant_id=native_tenant,
                   mailbox_upn='mailbox@example.com', acquired_at='2026-01-03T00:00:00.1234567Z',
                   synthetic=True, evidence_class='reserialized-source-objects', sources={
                       'inbox_rules': dict(status='partial', records=[dict(Name='Synthetic current rule', Enabled=False)]),
                       'forwarding': dict(status='denied', records=[]),
                       'delegates': dict(status='collected', records=[dict(source='Exchange.Mailbox.SendOnBehalf',
                           record=dict(UserPrincipalName='mailbox@example.com', GrantSendOnBehalfTo=['assistant@example.com']))])})
    current_file = Path(folder) / 'synthetic-snapshot.json'
    current_bytes = b'\xef\xbb\xbf' + json.dumps(current, indent=3).encode('utf-8')
    current_file.write_bytes(current_bytes)
    source_mtime = current_file.stat().st_mtime_ns
    companion = Path(folder) / 'mailbox-companion'
    receipt = json.loads(run(folder, 'snapshot-import', str(bound_case), str(current_file), '--output', str(companion)))
    assert receipt['sha256'] == hashlib.sha256(current_bytes).hexdigest()
    assert (companion / 'snapshot.json').read_bytes() == current_bytes
    state = json.loads(run(folder, 'snapshot-view', str(bound_case), str(companion)))
    assert state['synthetic'] is True and state['tenant_id'] == native_tenant
    assert state['mailbox_upn'] == 'mailbox@example.com'
    assert state['evidence_class'] == 'reserialized-source-objects'
    assert state['acquired_at'] == current['acquired_at']
    assert state['current_snapshot']['inbox_rules']['status'] == 'partial'
    assert state['current_snapshot']['forwarding']['status'] == 'denied'
    delegate = state['current_snapshot']['delegates']['records'][0]
    assert delegate['record'] == current['sources']['delegates']['records'][0]
    assert delegate['evidence']['json_pointer'] == '/sources/delegates/records/0'
    assert delegate['evidence']['sha256'] == receipt['sha256']
    assert not state['historical_rule_activity'] and state['historical_coverage'] is None
    assert {str(path.relative_to(bound_case)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in bound_case.rglob('*') if path.is_file()} == bound_before
    assert current_file.read_bytes() == current_bytes and current_file.stat().st_mtime_ns == source_mtime
    print('Installed BEC: demo, verification, comparison, exact searches and mailbox snapshot import/view passed; source evidence and cases were unchanged.')
