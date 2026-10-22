"""Value-free manual and bulk traffic projections share the global lookup."""

import tempfile
import unittest
from pathlib import Path

from core.agent_store import Store


class ManualTrafficStoreTest(unittest.TestCase):
    def test_merged_lookup_scope_filters_restart_and_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runs.sqlite3'
            store = Store(path)
            run_id = store.create({'owner': 'alice', 'spec': {'goal': 'test'}, 'endpoints': {}})
            store.event(run_id, 'observation', {
                'request': {'method': 'GET', 'url': 'https://example.test/agent'},
                'response': {'status': 200}}, 'step')
            request = {'method': 'POST',
                       'url': 'https://example.test/login?token=SECRET_QUERY',
                       'params': {'name': 'SECRET_PARAM'},
                       'headers': {'Authorization': 'SECRET_HEADER'},
                       'body': 'password=SECRET_BODY'}
            store.record_manual_traffic(request, 302, owner='alice')
            store.record_manual_traffic(request, 0, source='bulk', owner='bob')
            stored = store.record_manual_traffic_batch([
                (request, 201, 'raw'), (request, 500, 'multi')], owner='alice')
            self.assertEqual(len(stored), 2)
            store = Store(path)
            alice = store.lookup_page('traffic', owner='alice')
            self.assertEqual(alice['total'], 4)
            self.assertEqual({row['source'] for row in alice['items']},
                             {'manual', 'agent', 'raw', 'multi'})
            manual = store.lookup_page('traffic', owner='alice', source='manual')
            self.assertEqual(manual['total'], 1)
            self.assertEqual(manual['items'][0]['status'], 302)
            self.assertEqual(manual['items'][0]['path'], '/login')
            self.assertEqual(store.lookup_page('traffic', owner='alice', run_id=run_id)['total'], 1)
            self.assertEqual(store.lookup_page('traffic', owner='alice', archived=True)['total'], 0)
            self.assertEqual(store.lookup_page('traffic', owner='bob', source='bulk')['items'][0]['status'], None)
            self.assertEqual(store.lookup_page('traffic', owner='alice', source='multi')['items'][0]['status'], 500)
            self.assertTrue(store.lookup_page('traffic', owner='alice', limit=1)['has_more'])
            alice_assets = store.asset_page(search='login', owner='alice')
            self.assertEqual(alice_assets['total'], 1)
            self.assertEqual(alice_assets['assets'][0]['run_count'], 0)
            self.assertEqual(alice_assets['assets'][0]['manual_count'], 3)
            self.assertEqual(alice_assets['assets'][0]['query'], ['name', 'token'])
            self.assertTrue(alice_assets['assets'][0]['query_known'])
            self.assertEqual(store.asset_page(search='login', owner='bob')['assets'][0]['manual_count'], 1)
            self.assertEqual(store.asset_page(owner='charlie')['total'], 0)
            self.assertEqual(store.asset_page(owner='alice', archived=True)['total'], 0)
            for secret in ('SECRET_QUERY', 'SECRET_PARAM', 'SECRET_HEADER', 'SECRET_BODY'):
                self.assertNotIn(secret, str(store.lookup_page('traffic')))
                self.assertNotIn(secret, path.read_bytes().decode('utf-8', errors='ignore'))

    def test_old_manual_traffic_rebuilds_asset_without_guessing_query_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runs.sqlite3'
            store = Store(path)
            request = {'method': 'GET', 'url': 'https://example.test/old?token=PRIVATE'}
            store.record_manual_traffic(request, 200, owner='alice')
            with store.connect() as db:
                db.execute('DELETE FROM assets')
                db.execute("DELETE FROM store_migrations WHERE name='manual_asset_v1'")
            restored = Store(path)
            asset = restored.asset_page(owner='alice')['assets'][0]
            self.assertEqual(asset['manual_count'], 1)
            self.assertFalse(asset['query_known'])
            self.assertEqual(asset['query'], [])
            self.assertNotIn('PRIVATE', str(asset))
            restored.record_manual_traffic(request, 200, owner='alice')
            asset = restored.asset_page(owner='alice')['assets'][0]
            self.assertTrue(asset['query_known'])
            self.assertEqual(asset['query'], ['token'])

    def test_deleting_run_preserves_shared_manual_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'runs.sqlite3')
            request = {'method': 'GET', 'url': 'https://example.test/shared'}
            run_id = store.create({'owner': 'alice', 'spec': {'goal': 'test'},
                                   'endpoints': {'seed': request}})
            store.record_manual_traffic(request, 200, owner='alice')
            self.assertEqual(store.asset_page(owner='alice')['assets'][0]['run_count'], 1)
            store.delete(run_id)
            asset = store.asset_page(owner='alice')['assets'][0]
            self.assertEqual(asset['run_count'], 0)
            self.assertEqual(asset['manual_count'], 1)


if __name__ == '__main__':
    unittest.main()
