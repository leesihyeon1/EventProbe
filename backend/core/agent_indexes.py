"""Local, value-free lookup indexes over durable agent events."""

import json

from core.agent_assets import asset_shape
from core.agent_findings import build_findings
from core.agent_view import map_request


TRAFFIC_KINDS = {'observation', 'browser_request', 'browser_response'}
FINDING_KINDS = {'verification', 'finding_update'}


def index_traffic_event(db, event_id, run_id, created, kind, data):
    if kind not in TRAFFIC_KINDS:
        return
    if kind == 'browser_response':
        if isinstance(data.get('status'), int) and data.get('request_id'):
            db.execute('UPDATE traffic_index SET status=? WHERE run_id=? AND request_id=? '
                       "AND source='browser'",
                       (data['status'], run_id, str(data['request_id'])))
        return
    request = data.get('request') or {}
    projected = map_request(request)
    shape = asset_shape(request)
    if not shape:
        return
    response = data.get('response') or {}
    status = response.get('status') if kind == 'observation' else data.get('status')
    db.execute(
        'INSERT OR REPLACE INTO traffic_index '
        '(id,run_id,created,source,method,origin,path,status,asset_id,request_id) '
        'VALUES (?,?,?,?,?,?,?,?,?,?)',
        (event_id, run_id, created, 'browser' if kind == 'browser_request' else 'agent',
         shape[2], shape[1], shape[3], status if isinstance(status, int) else None,
         shape[0], str(data.get('request_id') or (event_id if kind == 'browser_request' else ''))),
    )


def reindex_findings(db, run_id):
    """Rebuild one run inside its event transaction; originals remain authoritative."""
    row = db.execute('SELECT data FROM runs WHERE id=?', (run_id,)).fetchone()
    if row is None:
        return
    data = json.loads(row['data'])
    rows = db.execute(
        "SELECT id,kind,step_id,created,"
        "json_extract(data,'$.kind') AS action_kind,"
        "json_extract(data,'$.category') AS category,"
        "json_extract(data,'$.endpoint_id') AS endpoint_id,"
        "json_extract(data,'$.actor_id') AS actor_id,"
        "json_extract(data,'$.status') AS status,"
        "json_extract(data,'$.evidence_ids') AS evidence_ids,"
        "json_extract(data,'$.finding_id') AS finding_id,"
        "json_extract(data,'$.severity') AS severity,"
        "json_extract(data,'$.note') AS note "
        "FROM events WHERE run_id=? AND kind IN "
        "('action','observation','verification','finding_update') ORDER BY created,rowid",
        (run_id,),
    ).fetchall()
    events = []
    for event in rows:
        kind = event['kind']
        if kind == 'action':
            payload = {'kind': event['action_kind'], 'category': event['category'],
                       'endpoint_id': event['endpoint_id'], 'actor_id': event['actor_id']}
        elif kind == 'verification':
            payload = {'status': event['status'],
                       'evidence_ids': json.loads(event['evidence_ids']) if event['evidence_ids'] else []}
        elif kind == 'finding_update':
            payload = {'finding_id': event['finding_id'], 'status': event['status'],
                       'severity': event['severity']}
            if event['note'] is not None:
                payload['note'] = event['note']
        else:
            payload = {}
        events.append({'id': event['id'], 'kind': kind, 'step_id': event['step_id'],
                       'created': event['created'], 'data': payload})
    db.execute('DELETE FROM finding_index WHERE run_id=?', (run_id,))
    for finding in build_findings(run_id, data, events):
        endpoint = (data.get('endpoints') or {}).get(finding['endpoint_id']) or \
                   (data.get('endpoints') or {}).get('seed') or {}
        shape = asset_shape(endpoint)
        db.execute(
            'INSERT INTO finding_index '
            '(id,run_id,created,updated,category,verdict,status,severity,method,origin,path,'
            'asset_id,evidence_count,incomplete_evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (finding['id'], run_id, finding['created'], finding['updated'], finding['category'],
             finding['verdict'], finding['status'], finding['severity'], finding['method'],
             finding['origin'], finding['path'], shape[0] if shape else finding.get('asset_id') or '',
             len(finding['evidence_ids']), int(finding['incomplete_evidence'])),
        )


def reindex_run(db, run_id):
    db.execute('DELETE FROM traffic_index WHERE run_id=?', (run_id,))
    for event in db.execute("SELECT id,created,kind,data FROM events WHERE run_id=? "
                            "AND kind IN ('observation','browser_request','browser_response') "
                            "ORDER BY created,rowid", (run_id,)).fetchall():
        index_traffic_event(db, event['id'], run_id, event['created'], event['kind'],
                            json.loads(event['data']))
    reindex_findings(db, run_id)
