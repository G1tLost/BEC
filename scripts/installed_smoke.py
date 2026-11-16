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
    print('Installed BEC: demo, verification, comparison and exact email/URL/hash searches passed; no-hit coverage remained visible and both cases were unchanged.')
