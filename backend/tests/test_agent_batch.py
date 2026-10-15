"""Bulk management reports each permission and state result without target requests."""
import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_store import Store


def test_batch_archive_partial_results_and_owner_scope(tmp_path, monkeypatch):
    store = Store(tmp_path / 'batch.db')
    mine = store.create({'spec': {'goal': 'mine'}, 'owner': 'alice'})
    theirs = store.create({'spec': {'goal': 'theirs'}, 'owner': 'bob'})
    busy = store.create({'spec': {'goal': 'busy'}, 'owner': 'alice'})
    store.update(busy, store.get(busy)['data'], 'running')
    manager = AgentManager(store, transport=httpx.MockTransport(lambda _: pytest.fail('target request')))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)

    response = client.post('/api/agent/runs/batch',
                           json={'ids': [mine, theirs, busy, 'missing', mine], 'action': 'archive'},
                           headers={'x-eventprobe-user': 'alice'})
    assert response.status_code == 200
    result = response.json()
    assert (result['succeeded'], result['failed']) == (1, 3)
    assert [row['status'] for row in result['results'][1:]] == [403, 409, 404]
    assert store.get(mine)['data']['archived'] is True
    assert store.get(theirs)['data'].get('archived') is None
    assert store.get(busy)['data'].get('archived') is None
    assert manager.tasks == {}

    restored = client.post('/api/agent/runs/batch',
                           json={'ids': [mine], 'action': 'unarchive'},
                           headers={'x-eventprobe-user': 'alice'})
    assert restored.json()['succeeded'] == 1
    assert store.get(mine)['data']['archived'] is False
    assert client.post('/api/agent/runs/batch', json={'ids': [], 'action': 'stop'}).status_code == 422
    assert client.post('/api/agent/runs/batch', json={'ids': [mine], 'action': 'stop'},
                       headers={'x-eventprobe-user': 'alice'}).json()['results'][0]['status'] == 409

    metadata = f'/api/agent/runs/{mine}/metadata'
    assert client.patch(metadata, json={'name': '  Reviewed  ', 'category': 'access'},
                        headers={'x-eventprobe-user': 'bob'}).status_code == 403
    saved = client.patch(metadata, json={'name': '  Reviewed  ', 'category': 'access'},
                         headers={'x-eventprobe-user': 'alice'})
    assert saved.status_code == 200 and saved.json()['name'] == 'Reviewed'
    assert store.get(mine)['data']['spec']['goal'] == 'mine'
    assert store.get(mine)['data']['category'] == 'access'
    assert client.patch(f'/api/agent/runs/{busy}/metadata', json={'name': 'Busy'},
                        headers={'x-eventprobe-user': 'alice'}).status_code == 409
