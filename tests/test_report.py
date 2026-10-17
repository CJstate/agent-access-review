import csv
import json
from datetime import datetime, timezone

from agent_access_review.__main__ import main
from agent_access_review.checks import run_all
from agent_access_review.parsers import discover
from agent_access_review.report import sha256, write_all
from conftest import AS_OF, EXAMPLES

COLLECTED = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)


def review(tmp_path):
    results = [(a, run_all(a, AS_OF)) for a in discover([EXAMPLES])]
    return results, write_all(results, tmp_path, AS_OF, COLLECTED)


def test_evidence_hash_detects_tampering(tmp_path):
    _, paths = review(tmp_path)
    record = json.loads(paths['evidence:finance-ops-agent'].read_text(encoding='utf-8'))
    hashed = {'inventory': record['inventory'], 'source_record': record['source_record']}
    assert sha256(hashed) == record['sha256']
    hashed['inventory']['owner'] = 'someone-else@example.com'
    assert sha256(hashed) != record['sha256']


def test_evidence_lists_every_check(tmp_path):
    _, paths = review(tmp_path)
    record = json.loads(paths['evidence:support-copilot'].read_text(encoding='utf-8'))
    assert [r['status'] for r in record['results']] == ['PASS'] * 12


def test_no_secret_in_any_output(tmp_path):
    review(tmp_path)
    blob = ''.join(p.read_text(encoding='utf-8') for p in tmp_path.rglob('*') if p.is_file())
    for secret in ['example-not-a-real-token-0001', 'example-password', 'example-crm-key']:
        assert secret not in blob


def test_decision_sheet(tmp_path):
    _, paths = review(tmp_path)
    rows = list(csv.DictReader(paths['sheet'].open(encoding='utf-8')))
    decision = {(r['agent_id'], r['tool']): r['recommended_decision'] for r in rows}
    assert decision[('support-copilot', 'zendesk')] == 'Keep'
    assert decision[('finance-ops-agent', 'expense-ocr')] == 'Revoke'
    assert decision[('finance-ops-agent', 'netsuite')] == 'Modify'
    assert decision[('claude-desktop-config', 'internal-crm')] == 'Investigate'
    assert all(r['reviewer_decision'] == '' for r in rows)


def test_oscal_findings(tmp_path):
    _, paths = review(tmp_path)
    doc = json.loads(paths['oscal'].read_text(encoding='utf-8'))['assessment-results']
    assert doc['metadata']['oscal-version'] == '1.1.2'
    result = doc['results'][0]
    assert len(result['observations']) == 5
    states = {f['target']['target-id']: f['target']['status']['state'] for f in result['findings']}
    assert states['ac-2.3'] == 'not-satisfied'
    assert set(states) == {'ac-2', 'ac-2.3', 'ac-4', 'ac-6', 'cm-7', 'cm-8', 'ia-5', 'sc-8', 'sr-3'}
    obs_ids = {o['uuid'] for o in result['observations']}
    assert all(r['observation-uuid'] in obs_ids for f in result['findings'] for r in f['related-observations'])


def test_cli_gate(tmp_path, capsys):
    out = tmp_path / 'out'
    assert main(['scan', str(EXAMPLES / 'agents.yaml'), '--out', str(out), '--as-of', '2026-10-12']) == 0
    assert main(['scan', str(EXAMPLES / 'agents.yaml'), '--out', str(out), '--as-of', '2026-10-12',
                 '--fail-on', 'high']) == 1
    assert (out / 'access-review.md').exists()
    assert 'finance-ops-agent' in capsys.readouterr().out


def test_cli_nothing_found(tmp_path):
    assert main(['scan', str(tmp_path), '--out', str(tmp_path / 'out')]) == 2


def test_demo_runs_on_bundled_examples(tmp_path, capsys):
    assert main(['demo', '--out', str(tmp_path / 'demo')]) == 0
    out = capsys.readouterr().out
    assert 'finance-ops-agent' in out and 'Next:' in out
    # sources are recorded relative to the scanned folder, not this machine's install path
    assert '`examples/agents.yaml`' in (tmp_path / 'demo' / 'access-review.md').read_text(encoding='utf-8')
