"""Offline companion snapshots, kept separate from historical provider evidence."""
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from .comparison import Snapshot, _read
from .storage import CaseError, digest, encode, now, user_address, timestamp

SCHEMA = 'response-menu.mailbox-snapshot.v1'
SOURCES = {'inbox_rules', 'forwarding', 'delegates'}
LIMIT = 16 * 1024 * 1024


def _bytes(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise CaseError('Snapshot must be a regular, non-symlink file of at most 16 MiB.')
    data = _read(path)
    if len(data) > LIMIT:
        raise CaseError('Snapshot exceeds 16 MiB.')
    return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaseError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def validate(data, case):
    obj = json.loads(data.decode('utf-8-sig'), object_pairs_hook=_unique,
                     parse_constant=lambda x: (_ for _ in ()).throw(CaseError('Non-finite JSON number.')))
    fields = {'schema', 'tenant_id', 'mailbox_upn', 'acquired_at', 'synthetic', 'evidence_class', 'sources'}
    if not isinstance(obj, dict) or set(obj) != fields or obj['schema'] != SCHEMA:
        raise CaseError('Unsupported mailbox snapshot contract.')
    if obj['evidence_class'] != 'reserialized-source-objects' or type(obj['synthetic']) is not bool:
        raise CaseError('Snapshot evidence class or synthetic marker is invalid.')
    if not isinstance(obj['tenant_id'], str):
        raise CaseError('Snapshot tenant ID must be a GUID string.')
    tenant = str(uuid.UUID(obj['tenant_id']))
    if not case.binding['directory_id'] or tenant != case.binding['directory_id']:
        raise CaseError('Snapshot requires an exact native Microsoft tenant binding; unbound cases are refused.')
    if user_address(obj['mailbox_upn']) != obj['mailbox_upn'] or obj['mailbox_upn'] != case.case.meta['user']:
        raise CaseError('Snapshot requires the exact lowercase case mailbox UPN.')
    if not isinstance(obj['acquired_at'], str) or 'T' not in obj['acquired_at']:
        raise CaseError('Snapshot acquisition time must be ISO UTC.')
    acquired = datetime.fromisoformat(obj['acquired_at'].replace('Z', '+00:00'))
    if acquired.tzinfo is None or acquired.utcoffset() != timedelta(0):
        raise CaseError('Snapshot acquisition time must be ISO UTC.')
    if not isinstance(obj['sources'], dict) or set(obj['sources']) != SOURCES:
        raise CaseError('Snapshot requires inbox_rules, forwarding and delegates coverage.')
    count = 0
    for source in obj['sources'].values():
        if not isinstance(source, dict) or set(source) != {'status', 'records'}:
            raise CaseError('Each snapshot source requires status and records.')
        if source['status'] not in {'collected', 'partial', 'denied', 'unavailable'}:
            raise CaseError('Unknown source coverage status.')
        rows = source['records']
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise CaseError('Snapshot records must be objects.')
        if source['status'] in {'denied', 'unavailable'} and rows:
            raise CaseError('Denied/unavailable sources cannot contain records.')
        count += len(rows)
    if count > 10000:
        raise CaseError('Snapshot exceeds 10,000 records.')
    return obj


def import_snapshot(case_directory, source, output):
    case = Snapshot(case_directory)
    source = Path(source).absolute()
    data = _bytes(source)
    obj = validate(data, case)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(case.case.path):
        raise CaseError('Import output must be a new directory outside the case.')
    manifest = dict(schema='bec.mailbox-snapshot-import.v1', sha256=digest(data),
                    file='snapshot.json', imported_at=now(), source_file=source.name,
                    tenant_id=obj['tenant_id'], mailbox_upn=obj['mailbox_upn'],
                    synthetic=obj['synthetic'], evidence_class=obj['evidence_class'])
    case.check_unchanged()
    if _bytes(source) != data:
        raise CaseError('Snapshot changed during import.')
    output.mkdir(parents=True, exist_ok=False)
    # A failed write leaves an incomplete directory which view refuses, never a recovered case mutation.
    with (output / 'snapshot.json').open('xb') as stream:
        stream.write(data)
    with (output / 'manifest.json').open('xb') as stream:
        stream.write(encode(manifest))
    return manifest


def view_snapshot(case_directory, directory):
    case = Snapshot(case_directory)
    directory = Path(directory)
    if directory.is_symlink():
        raise CaseError('Snapshot directory cannot be a symlink.')
    directory = directory.resolve()
    manifest_bytes = _bytes(directory / 'manifest.json')
    manifest = json.loads(manifest_bytes, object_pairs_hook=_unique)
    data = _bytes(directory / 'snapshot.json')
    if not isinstance(manifest, dict):
        raise CaseError('Invalid snapshot manifest.')
    snapshot_hash = digest(data)
    if manifest.get('schema') != 'bec.mailbox-snapshot-import.v1' or manifest.get('file') != 'snapshot.json' or manifest.get('sha256') != snapshot_hash:
        raise CaseError('Snapshot integrity verification failed.')
    obj = validate(data, case)
    if any(manifest.get(k) != obj[k] for k in ('tenant_id', 'mailbox_upn', 'synthetic', 'evidence_class')):
        raise CaseError('Snapshot manifest binding mismatch.')
    sources = {}
    for name, source in obj['sources'].items():
        sources[name] = dict(status=source['status'], records=[dict(record=row, evidence=dict(
            file='snapshot.json', sha256=snapshot_hash, source=name, record_index=i,
            json_pointer=f'/sources/{name}/records/{i}')) for i, row in enumerate(source['records'])])
    history = []
    start, end = (timestamp(case.case.meta[key]) for key in ('start', 'end'))
    undated = 0
    for item in case.inventory.values():
        if item['dataset'] != 'ual':
            continue
        undated += len(item['normalization_issues'])
        for observation in item['observations']:
            try:
                when = timestamp(observation['timestamp_utc'])
            except (ValueError, TypeError, KeyError):
                undated += 1
                continue
            if not start <= when < end:
                continue
            if observation['event_type'].startswith('mail.rule.') and obj['mailbox_upn'] in {
                    str(observation.get('actor', {}).get('user', '')).casefold(),
                    str(observation.get('target', {}).get('resource', '')).casefold()}:
                history.append(dict(observation=observation, evidence=item['evidence']))
    case.check_unchanged()
    if data != _bytes(directory / 'snapshot.json') or manifest_bytes != _bytes(directory / 'manifest.json'):
        raise CaseError('Snapshot changed during view.')
    return dict(schema='bec.mailbox-state-view.v1', tenant_id=obj['tenant_id'], mailbox_upn=obj['mailbox_upn'],
                synthetic=obj['synthetic'], evidence_class=obj['evidence_class'], acquired_at=obj['acquired_at'],
                current_snapshot=sources, historical_rule_activity=history, historical_coverage=case.coverage.get('ual'),
                historical_window=dict(start=case.case.meta['start'], end=case.case.meta['end'], bounds='[start,end)'),
                historical_unparseable_ual_observations=undated,
                limitations=['Snapshot is state at acquisition, not incident-time state.',
                    'Reserialized objects are not original provider response bytes; hashes prove preservation after import only.',
                    'Undated or unparseable UAL observations are excluded from dated history and counted; they may hide rule changes.',
                    'Historical actor/target matches are not proof of rule ownership; absent records do not prove absence or remediation.',
                    'No provider calls, GAM/AD acquisition, changes or remediation are performed.'])
