"""Read-only operational diagnostics across workspace and archive boundaries."""

import tempfile
import unittest
from pathlib import Path

from core.agent_store import Store


class DiagnosticPageTests(unittest.TestCase):
    def test_latest_browser_status_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'runs.sqlite3')
            own = store.create({'owner': 'alice', 'spec': {'goal': 'private'},
                                'procedure_sha256': {'agent': 'a' * 64},
                                'planner_attempts': [{'model': 'local-test',
                                                      'prompt_sha256': 'b' * 64,
                                                      'status': 'rejected', 'elapsed_ms': 30}],
                                'endpoints': {}})
            other = store.create({'owner': 'bob', 'spec': {'goal': 'other'},
                                  'endpoints': {}})
            store.event(own, 'browser_recon', {'code': 'old', 'status': 'failed'})
            store.event(own, 'browser_recon', {'code': '', 'status': 'ready',
                                               'response_body': 'PRIVATE_RESPONSE'})
            store.event(own, 'request_error', {'reason': 'PRIVATE_RESPONSE'})
            store.event(other, 'browser_recon', {'code': 'other_workspace'})

            page = store.diagnostic_page(owner='alice', limit=1)
            self.assertEqual(page['total'], 1)
            self.assertFalse(page['has_more'])
            self.assertEqual(page['items'][0]['id'], own)
            self.assertEqual(page['items'][0]['browser_status'], 'ready')
            self.assertEqual(page['items'][0]['request_errors'], 1)
            self.assertEqual(page['items'][0]['procedure_sha256'], 'a' * 64)
            self.assertEqual(page['items'][0]['prompt_sha256'], 'b' * 64)
            self.assertEqual(page['items'][0]['model'], 'local-test')
            self.assertIsNone(page['items'][0]['token_count'])
            self.assertNotIn('PRIVATE_RESPONSE', str(page))
            self.assertNotIn(other, str(page))

            store.set_archived(own, True)
            self.assertEqual(store.diagnostic_page(owner='alice')['total'], 0)

    def test_attempt_without_terminal_event_remains_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'runs.sqlite3')
            run_id = store.create({'owner': 'alice', 'browser_recon_attempted': True,
                                   'spec': {'goal': 'diagnostic'}, 'endpoints': {}})
            page = store.diagnostic_page(owner='alice')
            self.assertEqual(page['items'][0]['id'], run_id)
            self.assertEqual(page['items'][0]['browser_status'], 'unknown')
            store.event(run_id, 'browser_recon', {'status': 'completed'})
            self.assertEqual(store.diagnostic_page(owner='alice')['items'][0]['browser_status'],
                             'completed')


if __name__ == '__main__':
    unittest.main()
