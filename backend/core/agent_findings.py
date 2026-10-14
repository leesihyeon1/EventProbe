"""Deterministic, local findings over a run's verification evidence.

Findings never call an LLM and never read response bodies. A finding ID is a pure
function of (run_id, dedup key), so IDs survive a restart without materializing
rows or migrating the store. Findings are derived from existing `verification`
events — the originals are never modified. User triage (status/severity/note) is
recorded as append-only `finding_update` events and folded in on read, keeping a
full audit history. Report rendering is pure string building: zero egress.
"""
import hashlib
import html
from urllib.parse import parse_qsl, urlsplit

# Finding lifecycle (user-editable) is distinct from the derived evidence verdict.
STATUSES = ('open', 'triaged', 'resolved', 'false_positive', 'ignored')
SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
_VERDICTS = ('inconclusive', 'suspicious', 'confirmed')
_VERDICT_RANK = {v: i for i, v in enumerate(_VERDICTS)}
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Conservative default; a label without linked evidence can only be inconclusive.
_DEFAULT_SEVERITY = {'confirmed': 'high', 'suspicious': 'medium', 'inconclusive': 'info'}

_STATUS_KO = {'open': '미처리', 'triaged': '분류됨', 'resolved': '해결',
              'false_positive': '오탐', 'ignored': '무시'}
_SEVERITY_KO = {'info': '정보', 'low': '낮음', 'medium': '보통', 'high': '높음', 'critical': '심각'}
_VERDICT_KO = {'confirmed': '확증', 'suspicious': '의심', 'inconclusive': '미확정'}


def finding_id(run_id, category, endpoint_id, actor_id):
    """Stable across restarts: a finding keeps its ID as long as its dedup key does."""
    raw = '\x00'.join([run_id or '', category or '', endpoint_id or '', actor_id or ''])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _address(request):
    """Origin + path + query keys only. Query values and bodies are never copied."""
    try:
        p = urlsplit((request or {}).get('url', '') or '')
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
            return {'origin': '', 'path': (request or {}).get('url', '') or '', 'query_keys': []}
        port = f':{p.port}' if p.port else ''
        keys = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}
                      | set((request or {}).get('params', {}) or {}))
        return {'origin': f'{p.scheme}://{p.hostname.lower()}{port}', 'path': p.path or '/', 'query_keys': keys}
    except (ValueError, TypeError):
        return {'origin': '', 'path': '', 'query_keys': []}


def build_findings(run_id, data, events):
    """Derive the current findings for a run. Pure and local."""
    observations = {e['id'] for e in events if e['kind'] == 'observation'}
    actions = {e['step_id']: e['data'] for e in events if e['kind'] == 'action' and e['step_id']}
    endpoints = (data or {}).get('endpoints', {}) or {}
    findings = {}
    for e in events:
        if e['kind'] != 'verification':
            continue
        verdict_data = e['data'] or {}
        cited = [r for r in (verdict_data.get('evidence_ids') or [])]
        refs = [r for r in cited if r in observations]
        label = verdict_data.get('status', 'inconclusive')
        # Mirror build_conclusion: a label without linked evidence is only inconclusive.
        verdict = label if refs and label in ('confirmed', 'suspicious') else 'inconclusive'
        action = actions.get(e['step_id'], {})
        category = action.get('category') or action.get('kind') or 'verification'
        endpoint_id = action.get('endpoint_id') or ''
        actor_id = action.get('actor_id') or ''
        key = (category, endpoint_id, actor_id)
        finding = findings.get(key)
        if finding is None:
            finding = findings[key] = {
                'id': finding_id(run_id, category, endpoint_id, actor_id),
                'category': category, 'endpoint_id': endpoint_id, 'actor_id': actor_id,
                'verdict': 'inconclusive', 'evidence_ids': [], 'verification_ids': [],
                'step_ids': [], 'created': e['created'], 'updated': e['created'],
                'incomplete_evidence': False,
            }
        finding['verification_ids'].append(e['id'])
        if e['step_id'] and e['step_id'] not in finding['step_ids']:
            finding['step_ids'].append(e['step_id'])
        for ref in refs:
            if ref not in finding['evidence_ids']:
                finding['evidence_ids'].append(ref)
        if _VERDICT_RANK[verdict] > _VERDICT_RANK[finding['verdict']]:
            finding['verdict'] = verdict
        if len(set(cited)) != len(set(refs)):
            finding['incomplete_evidence'] = True
        finding['created'] = min(finding['created'], e['created'])
        finding['updated'] = max(finding['updated'], e['created'])
    for finding in findings.values():
        request = endpoints.get(finding['endpoint_id']) or endpoints.get('seed') or {}
        address = _address(request)
        finding.update(address)
        finding['method'] = (request.get('method') or 'GET').upper()
        default_severity = _DEFAULT_SEVERITY[finding['verdict']]
        finding['default_severity'] = default_severity
        finding['severity'] = default_severity
        finding['status'] = 'open'
        finding['note'] = ''
        finding['history'] = []
    by_id = {f['id']: f for f in findings.values()}
    for e in events:
        if e['kind'] != 'finding_update':
            continue
        patch = e['data'] or {}
        finding = by_id.get(patch.get('finding_id'))
        if finding is None:
            continue
        entry = {'event_id': e['id'], 'created': e['created']}
        if patch.get('status') in STATUSES:
            finding['status'] = entry['status'] = patch['status']
        if patch.get('severity') in SEVERITIES:
            finding['severity'] = entry['severity'] = patch['severity']
        if isinstance(patch.get('note'), str):
            finding['note'] = entry['note'] = patch['note']
        if len(entry) > 2:  # status/severity/note beyond event_id+created
            finding['history'].append(entry)
            finding['updated'] = max(finding['updated'], e['created'])
    return sorted(findings.values(), key=lambda f: (
        -_SEVERITY_RANK[f['severity']], -_VERDICT_RANK[f['verdict']],
        f['category'], f['path'], f['id']))


def valid_patch(patch):
    """Return a sanitized finding_update payload, or None if it changes nothing."""
    out = {}
    if patch.get('status') in STATUSES:
        out['status'] = patch['status']
    if patch.get('severity') in SEVERITIES:
        out['severity'] = patch['severity']
    if isinstance(patch.get('note'), str):
        out['note'] = patch['note'][:2000]
    return out or None


def _h(value):
    return html.escape(str(value), quote=True)


def build_report_html(run):
    """A standalone, print-friendly local report. No scripts, no external resources,
    no response bodies — pure string building, so generation makes zero requests."""
    data = run.get('data', {}) or {}
    spec = data.get('spec', {}) or {}
    conclusion = run.get('conclusion', {}) or {}
    findings = run.get('findings')
    if findings is None:
        findings = build_findings(run.get('id', ''), data, run.get('events', []) or [])
    goal = spec.get('goal', '') or '(목표 미기재)'
    counts = conclusion.get('counts', {}) or {}
    rows = []
    for f in findings:
        query = ', '.join(f.get('query_keys') or []) or '-'
        evidence = len(f.get('evidence_ids') or [])
        incomplete = ' · 증거 일부 누락' if f.get('incomplete_evidence') else ''
        rows.append(
            '<tr>'
            f'<td><span class="sev sev-{_h(f["severity"])}">{_h(_SEVERITY_KO.get(f["severity"], f["severity"]))}</span></td>'
            f'<td>{_h(_VERDICT_KO.get(f["verdict"], f["verdict"]))}</td>'
            f'<td>{_h(_STATUS_KO.get(f["status"], f["status"]))}</td>'
            f'<td>{_h(f["category"])}</td>'
            f'<td class="mono">{_h(f["method"])} {_h(f["path"])}</td>'
            f'<td class="mono">{_h(query)}</td>'
            f'<td>{_h(f.get("actor_id") or "-")}</td>'
            f'<td>{evidence}{incomplete}</td>'
            '</tr>')
    table = ('<p class="empty">연결된 증거로 확인된 발견이 없습니다.</p>' if not rows else
             '<table><thead><tr>'
             '<th>심각도</th><th>판정</th><th>상태</th><th>유형</th><th>엔드포인트</th>'
             '<th>쿼리 키</th><th>행위자</th><th>증거</th>'
             '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')
    next_steps = ''.join(f'<li>{_h(s)}</li>' for s in (conclusion.get('next_steps') or []))
    unfinished = len(conclusion.get('unfinished_steps') or [])
    return f'''<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EventProbe 작업 보고서</title>
<style>
  :root {{ color-scheme: light; --fg:#1b1f24; --muted:#5a6572; --line:#d7dde4; --bg:#fff; }}
  body {{ font: 14px/1.6 system-ui, "Segoe UI", sans-serif; color:var(--fg); background:var(--bg);
    max-width: 960px; margin: 0 auto; padding: 32px 20px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  h2 {{ font-size: 16px; margin: 28px 0 10px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }}
  .muted {{ color: var(--muted); }}
  .verdict {{ font-weight: 700; }}
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 8px 0; }}
  dt {{ color: var(--muted); }} dd {{ margin: 0; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ font-size: 12px; color: var(--muted); }}
  .mono {{ font-family: ui-monospace, "Cascadia Code", monospace; font-size: 12px; word-break: break-all; }}
  .sev {{ padding: 1px 8px; border-radius: 999px; font-size: 12px; }}
  .sev-critical {{ background:#fde2e1; color:#8a1c13; }} .sev-high {{ background:#fdeadf; color:#8a3d12; }}
  .sev-medium {{ background:#fcf4d6; color:#7a5a06; }} .sev-low {{ background:#e3eefc; color:#1f4e8a; }}
  .sev-info {{ background:#edf0f3; color:#444; }}
  .empty {{ color: var(--muted); }}
  footer {{ margin-top: 32px; font-size: 12px; color: var(--muted); border-top: 1px solid var(--line); padding-top: 10px; }}
  @media print {{ body {{ padding: 0; }} h2 {{ page-break-after: avoid; }} tr {{ page-break-inside: avoid; }} }}
</style></head>
<body>
  <h1>자율 검증 작업 보고서</h1>
  <p class="muted">작업 ID {_h(run.get('id', ''))} · 상태 {_h(run.get('state', ''))}</p>
  <h2>개요</h2>
  <dl>
    <dt>목표</dt><dd>{_h(goal)}</dd>
    <dt>결론</dt><dd class="verdict">{_h(_VERDICT_KO.get(conclusion.get('verdict', ''), conclusion.get('verdict', '')))}
      ({_h(conclusion.get('completion', ''))})</dd>
    <dt>판정 집계</dt><dd>확증 {counts.get('confirmed', 0)} · 의심 {counts.get('suspicious', 0)} · 미확정 {counts.get('inconclusive', 0)}</dd>
    <dt>관측 수</dt><dd>{conclusion.get('observation_count', 0)}</dd>
    <dt>미완료 검사</dt><dd>{unfinished}</dd>
  </dl>
  <p>{_h(conclusion.get('text', ''))}</p>
  <h2>발견 ({len(findings)})</h2>
  {table}
  <h2>다음 조치</h2>
  <ul>{next_steps or '<li class="empty">추가 조치 없음</li>'}</ul>
  <footer>
    {_h(conclusion.get('scope_note', '작업 종료는 전체 대상의 안전을 의미하지 않습니다.'))}<br>
    로컬 생성 보고서입니다. 외부 AI 및 대상 요청을 수행하지 않았습니다. 원본 증거는 작업 상세의 로컬 타임라인에서 확인하세요.
  </footer>
</body></html>'''
