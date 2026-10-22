"""Value-free asset index derived from locally stored run endpoints."""

import hashlib
import json
from urllib.parse import parse_qsl, urlsplit

from core.agent_view import map_request, request_field_keys


def asset_shape(request):
    projected = map_request(request)
    if not projected.get('url'):
        return None
    url = urlsplit(projected['url'])
    origin = f'{url.scheme}://{url.netloc}'
    query = sorted({key for key, _ in parse_qsl(url.query, keep_blank_values=True)} |
                   set(projected.get('params') or {}))
    method = projected['method'].upper()
    path = url.path or '/'
    identity = json.dumps([origin, method, path, query], ensure_ascii=False)
    return (hashlib.sha256(identity.encode()).hexdigest(), origin, method, path,
            json.dumps(query, ensure_ascii=False))


def reindex_run(db, run_id, data):
    db.execute('DELETE FROM asset_refs WHERE run_id=?', (run_id,))
    for endpoint_id, request in (data.get('endpoints') or {}).items():
        shape = asset_shape(request)
        if shape is None:
            continue
        db.execute('INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?)', shape)
        db.execute('INSERT OR REPLACE INTO asset_refs VALUES (?,?,?,?)',
                   (run_id, str(endpoint_id), shape[0],
                    json.dumps(request_field_keys(request), ensure_ascii=False)))
    db.execute('DELETE FROM assets WHERE NOT EXISTS '
               '(SELECT 1 FROM asset_refs WHERE asset_refs.asset_id=assets.id) '
               'AND NOT EXISTS (SELECT 1 FROM manual_traffic WHERE manual_traffic.asset_id=assets.id)')
