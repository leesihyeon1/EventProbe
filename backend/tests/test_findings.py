"""Findings are derived locally from verification evidence. No live target or LLM.

Covers dedup/merge, the evidence-validity rule shared with the conclusion, stable
IDs across a restart, append-only triage history, and a zero-egress HTML report.
"""
import httpx

from core.agent import AgentManager
from core.agent_findings import (STATUSES, SEVERITIES, build_findings, build_report_html,
                                 finding_id, valid_patch)
from core.agent_store import Store

SEED = {'url': 'https://app.test/items?id=1', 'method': 'GET'}


def _events(*specs):
    """Build event dicts (id/kind/step_id/created/data) from terse tuples."""
    out, clock = [], [100.0]
    for kind, step_id, data in specs:
        clock[0] += 1
        eid = data.pop('_id', f'{kind[:3]}{len(out)}')
        out.append({'id': eid, 'kind': kind, 'step_id': step_id, 'created': clock[0], 'data': data})
    return out


def _run_data(**endpoints):
    return {'spec': {'goal': '테스트 목표'}, 'endpoints': {'seed': SEED, **endpoints},
            'needs_credentials': False}


def test_findings_merge_by_endpoint_actor_and_escalate_verdict():
    events = _events(
        ('action', 's1', {'kind': 'probe', 'category': 'xss', 'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('observation', 's1', {'_id': 'o1'}),
        ('verification', 's1', {'status': 'suspicious', 'evidence_ids': ['o1']}),
        ('action', 's2', {'kind': 'probe', 'category': 'xss', 'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('observation', 's2', {'_id': 'o2'}),
        ('verification', 's2', {'status': 'confirmed', 'evidence_ids': ['o2']}),
    )
    findings = build_findings('run1', _run_data(), events)
    assert len(findings) == 1
    f = findings[0]
    # Two verifications on the same (category, endpoint, actor) are one finding.
    assert f['verdict'] == 'confirmed'               # escalates suspicious -> confirmed
    assert set(f['evidence_ids']) == {'o1', 'o2'}    # evidence accumulates
    assert len(f['verification_ids']) == 2
    assert f['method'] == 'GET' and f['path'] == '/items' and f['query_keys'] == ['id']
    assert f['severity'] == 'high'                   # default for confirmed


def test_label_without_linked_evidence_is_inconclusive():
    events = _events(
        ('action', 's1', {'kind': 'probe', 'category': 'sqli', 'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('verification', 's1', {'status': 'confirmed', 'evidence_ids': ['ghost']}),
    )
    f = build_findings('run1', _run_data(), events)[0]
    assert f['verdict'] == 'inconclusive'            # cited evidence is not a real observation
    assert f['evidence_ids'] == []
    assert f['incomplete_evidence'] is True
    assert f['severity'] == 'info'


def test_finding_id_is_stable_across_runs_and_order():
    a = finding_id('runX', 'xss', 'seed', 'owner')
    b = finding_id('runX', 'xss', 'seed', 'owner')
    assert a == b and len(a) == 16
    assert finding_id('runX', 'xss', 'seed', 'guest') != a    # actor distinguishes findings


def test_triage_updates_apply_append_only_with_history():
    base = _events(
        ('action', 's1', {'kind': 'probe', 'category': 'xss', 'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('observation', 's1', {'_id': 'o1'}),
        ('verification', 's1', {'status': 'confirmed', 'evidence_ids': ['o1']}),
    )
    fid = build_findings('run1', _run_data(), base)[0]['id']
    events = base + _events(
        ('finding_update', '', {'finding_id': fid, 'severity': 'critical'}),
        ('finding_update', '', {'finding_id': fid, 'status': 'resolved', 'note': '패치 적용'}),
    )
    f = build_findings('run1', _run_data(), events)[0]
    assert f['severity'] == 'critical' and f['status'] == 'resolved' and f['note'] == '패치 적용'
    assert len(f['history']) == 2                     # every change kept, originals untouched
    assert [e for e in events if e['kind'] == 'verification'][0]['data']['status'] == 'confirmed'


def test_invalid_patch_values_are_rejected():
    assert valid_patch({'status': 'bogus', 'severity': 'nope'}) is None
    assert valid_patch({'status': 'triaged'}) == {'status': 'triaged'}
    assert set(STATUSES) and set(SEVERITIES)
    # A patch with an unknown status does not change a finding.
    events = _events(
        ('action', 's1', {'kind': 'probe', 'category': 'xss', 'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('observation', 's1', {'_id': 'o1'}),
        ('verification', 's1', {'status': 'confirmed', 'evidence_ids': ['o1']}),
    )
    fid = build_findings('run1', _run_data(), events)[0]['id']
    events += _events(('finding_update', '', {'finding_id': fid, 'status': 'bogus'}))
    assert build_findings('run1', _run_data(), events)[0]['status'] == 'open'


def test_finding_ids_and_triage_survive_a_restart(tmp_path):
    path = tmp_path / 'agent.db'
    manager = AgentManager(Store(path))
    run_id = manager.store.create(_run_data())
    manager.store.event(run_id, 'action', {'kind': 'probe', 'category': 'idor',
                                           'endpoint_id': 'seed', 'actor_id': 'guest'}, 's1')
    manager.store.event(run_id, 'observation', {}, 's1', 'obs1')
    manager.store.event(run_id, 'verification', {'status': 'confirmed', 'evidence_ids': ['obs1']}, 's1')
    first = manager.snapshot(run_id)['findings']
    assert len(first) == 1
    fid = first[0]['id']
    manager.update_finding(run_id, fid, {'status': 'triaged'})

    # New Store + manager over the same file == a server restart.
    reopened = AgentManager(Store(path)).snapshot(run_id)['findings']
    assert reopened[0]['id'] == fid                   # deterministic id persists
    assert reopened[0]['status'] == 'triaged'         # append-only update persists


def test_update_finding_rejects_unknown_id(tmp_path):
    manager = AgentManager(Store(tmp_path / 'agent.db'))
    run_id = manager.store.create(_run_data())
    try:
        manager.update_finding(run_id, 'deadbeefdeadbeef', {'status': 'resolved'})
        assert False, 'expected ValueError'
    except ValueError:
        pass


def test_report_html_escapes_values_and_makes_no_requests():
    # A hostile category/path must not break out of the HTML.
    events = _events(
        ('action', 's1', {'kind': 'probe', 'category': '<script>x</script>',
                          'endpoint_id': 'seed', 'actor_id': 'owner'}),
        ('observation', 's1', {'_id': 'o1'}),
        ('verification', 's1', {'status': 'confirmed', 'evidence_ids': ['o1']}),
    )
    run = {'id': 'run1', 'state': 'completed', 'data': _run_data(),
           'events': events, 'conclusion': {'verdict': 'confirmed', 'counts': {'confirmed': 1},
                                            'text': '확증됨', 'next_steps': ['검토'], 'scope_note': '범위 주의'},
           'findings': build_findings('run1', _run_data(), events)}
    html = build_report_html(run)
    assert '<!doctype html>' in html
    assert '<script>x</script>' not in html and '&lt;script&gt;' in html   # escaped, not executed
    assert 'http://' not in html and 'https://' not in html                 # no external resources/urls
    assert 'src=' not in html and '</script>' not in html                   # no scripts at all
    assert '확증됨' in html and '범위 주의' in html


def test_report_from_real_run(tmp_path):
    async def execute():
        import asyncio
        from core.agent_models import RunSpec, Action

        def planner(*actions):
            pending = iter(actions)
            async def choose(ctx):
                value = next(pending, {'kind': 'finish', 'hypothesis': '종료'})
                value.setdefault('basis', [ctx['observations'][-1]['id']])
                return Action.model_validate(value)
            return choose

        manager = AgentManager(Store(tmp_path / 'agent.db'), planner(
            {'kind': 'probe', 'hypothesis': '반사', 'category': 'xss', 'param': 'id',
             'payload': '<svg onload=alert(1)>'}), httpx.MockTransport(lambda r: httpx.Response(200, text='normal')))
        run_id = manager.create(RunSpec.model_validate({'goal': '테스트', 'request': {'url': 'https://app.test/?id=1'}}))
        await manager.tasks[run_id]
        return manager.snapshot(run_id)

    import asyncio
    run = asyncio.run(execute())
    assert isinstance(run['findings'], list)
    html = build_report_html(run)
    assert '자율 검증 작업 보고서' in html
