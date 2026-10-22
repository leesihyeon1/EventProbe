"""Passive comparison of a finding with its linked retest runs."""

import tempfile
import unittest
from pathlib import Path

from core.agent_store import Store


class RetestComparisonsTest(unittest.TestCase):
    def test_missing_verdict_is_unknown_and_owner_is_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'runs.sqlite3')
            endpoint = {'method': 'GET', 'url': 'https://example.test/item?id=SECRET_VALUE'}
            original = store.create({'owner': 'alice', 'spec': {'goal': 'original'},
                                     'endpoints': {'seed': endpoint}})
            store.event(original, 'action', {'kind': 'probe', 'category': 'sqli',
                                            'endpoint_id': 'seed', 'actor_id': 'current'}, 's1')
            evidence = store.event(original, 'observation', {'request': endpoint,
                                     'response': {'status': 200, 'body': 'SECRET_BODY'}}, 's1')
            store.event(original, 'verification',
                        {'status': 'confirmed', 'evidence_ids': [evidence]}, 's1')
            finding_id = store.lookup_page('finding', owner='alice')['items'][0]['id']
            link = {'run_id': original, 'finding_id': finding_id, 'category': 'sqli'}
            same = store.create({'owner': 'alice', 'spec': {'request': endpoint},
                                 'endpoints': {'seed': endpoint}, 'retest_of': link})
            changed_endpoint = {'method': 'POST', 'url': 'https://example.test/other'}
            changed = store.create({'owner': 'alice', 'spec': {'request': changed_endpoint},
                                    'endpoints': {'seed': changed_endpoint}, 'retest_of': link})
            other = store.create({'owner': 'bob', 'spec': {'request': endpoint},
                                  'endpoints': {'seed': endpoint}, 'retest_of': link})
            result = store.retest_comparisons(original, finding_id, owner='alice')
            self.assertEqual(result['original']['verdict'], 'confirmed')
            self.assertEqual(len(result['items']), 2)
            by_run = {item['run_id']: item for item in result['items']}
            self.assertTrue(by_run[same]['same_request_shape'])
            self.assertFalse(by_run[changed]['same_request_shape'])
            self.assertEqual(by_run[changed]['request_shape']['path'], '/other')
            self.assertIsNone(by_run[same]['finding'])
            self.assertNotIn(other, str(result))
            self.assertNotIn('SECRET_VALUE', str(result))
            self.assertNotIn('SECRET_BODY', str(result))
            store.event(same, 'action', {'kind': 'confirm', 'category': 'sqli',
                                        'endpoint_id': 'seed', 'actor_id': 'current'}, 's2')
            store.event(same, 'verification', {'status': 'confirmed', 'evidence_ids': []}, 's2')
            updated = store.retest_comparisons(original, finding_id, owner='alice')
            self.assertEqual({item['run_id']: item for item in updated['items']}[same]['finding']['verdict'],
                             'inconclusive')
            with self.assertRaises(KeyError):
                store.retest_comparisons(original, 'missing', owner='alice')


if __name__ == '__main__':
    unittest.main()
