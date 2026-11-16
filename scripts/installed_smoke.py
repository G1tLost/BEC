"""Exercise the installed wheel outside this checkout, using only synthetic data."""
import json
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
    print('Installed BEC: 30 email/cloud events, no gaps, raw evidence verified outside checkout.')
