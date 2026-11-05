"""Exercise publication ordering and recovery with a stateful management peer."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('trustee_admin', ROOT / 'deployment/trustee/admin_client.py')
admin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admin)
A = 'resource/default/bootstrap/' + 'a' * 64
B = 'resource/default/bootstrap/' + 'b' * 64


class Peer:
    endpoint = 'https://trustee.example:8443'
    as_policy_id = 'openshell-tdx'

    def __init__(self):
        self.resources = {'resource/unrelated/project/key': b'untouched'}
        self.calls = []
        self.lose_post_response = False
        self.fail_policy = False
        self.fail_delete = False

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if method == 'DELETE':
            if self.fail_delete:
                raise TimeoutError('unreachable')
            self.resources.pop(path, None)
        elif method == 'POST':
            self.resources[path] = body
            if self.lose_post_response:
                raise TimeoutError('POST committed, response lost')
        else:
            raise AssertionError(method)

    def policy(self, value, *, attestation=False):
        self.calls.append(('AS' if attestation else 'KBS', value))
        if self.fail_policy:
            raise TimeoutError('policy request failed')


class Publication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = Path(self.temp.name) / 'publication.json'
        self.peer = Peer()

    def sync(self, resources, policy=b'approved bindings'):
        admin.synchronize(self.peer, resources, policy, b'approved measurements', self.journal)

    def test_initial_deny_then_resources_then_policy_and_idempotent_retry(self):
        self.sync({A: b'secret'})
        self.assertEqual(self.peer.calls, [('KBS', admin.DENY), ('POST', A),
                                         ('AS', b'approved measurements'), ('KBS', b'approved bindings')])
        self.peer.calls.clear()
        self.sync({A: b'secret'})
        self.assertEqual(self.peer.calls, [])

    def test_named_policy_is_published_when_migrating_an_existing_journal(self):
        self.sync({A: b'secret'})
        state = json.loads(self.journal.read_text())
        state.pop('as_policy_id')
        self.journal.write_text(json.dumps(state))
        self.peer.calls.clear()
        self.sync({A: b'secret'})
        self.assertEqual(self.peer.calls, [('AS', b'approved measurements')])

    def test_lost_post_response_survives_restart_and_is_deleted_on_rollback(self):
        self.peer.lose_post_response = True
        with self.assertRaises(TimeoutError):
            self.sync({A: b'secret'})
        self.assertIn(A, self.peer.resources)
        self.assertIn(A, json.loads(self.journal.read_text())['resources'])
        self.peer.lose_post_response = False
        self.sync({}, b'revoked bindings')
        self.assertNotIn(A, self.peer.resources)
        self.assertEqual(self.peer.resources['resource/unrelated/project/key'], b'untouched')

    def test_failed_delete_remains_pending_and_retry_finishes(self):
        self.sync({A: b'secret', B: b'other sandbox'})
        self.peer.fail_delete = True
        with self.assertRaises(TimeoutError):
            self.sync({B: b'other sandbox'}, b'only B')
        self.assertIn(A, json.loads(self.journal.read_text())['resources'])
        self.peer.fail_delete = False
        self.sync({B: b'other sandbox'}, b'only B')
        self.assertNotIn(A, self.peer.resources)
        self.assertEqual(self.peer.resources[B], b'other sandbox')

    def test_failed_policy_is_not_marked_committed(self):
        self.sync({A: b'secret'})
        old = json.loads(self.journal.read_text())['policy']
        self.peer.fail_policy = True
        with self.assertRaises(TimeoutError):
            self.sync({A: b'secret', B: b'new'}, b'new policy')
        self.assertEqual(json.loads(self.journal.read_text())['policy'], old)
        self.peer.fail_policy = False
        self.sync({A: b'secret', B: b'new'}, b'new policy')
        self.assertNotEqual(json.loads(self.journal.read_text())['policy'], old)

    def test_replacement_publisher_waits_for_inflight_publication(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.peer.request
        errors = []
        def delayed(method, path, body=None):
            original(method, path, body)
            if method == 'POST' and path == A:
                entered.set()
                if not release.wait(5):
                    raise AssertionError('test did not release first publisher')
        self.peer.request = delayed
        def first():
            try:
                self.sync({A: b'secret'})
            except Exception as error:
                errors.append(error)
        def replacement():
            try:
                self.sync({}, b'revoked')
            except Exception as error:
                errors.append(error)
            finally:
                finished.set()
        one = threading.Thread(target=first)
        two = threading.Thread(target=replacement)
        one.start()
        try:
            self.assertTrue(entered.wait(5))
            two.start()
            self.assertFalse(finished.wait(.1))
        finally:
            release.set()
            one.join(5)
            if two.ident:
                two.join(5)
        self.assertFalse(errors, errors)
        self.assertTrue(finished.is_set())
        self.assertNotIn(A, self.peer.resources)
        self.assertNotIn(A, json.loads(self.journal.read_text())['resources'])

    def test_foreign_resource_and_endpoint_change_are_rejected_before_http(self):
        with self.assertRaises(ValueError):
            self.sync({'resource/foreign/key/value': b'no'})
        self.assertEqual(self.peer.calls, [])
        self.sync({A: b'secret'})
        self.peer.calls.clear()
        self.peer.endpoint = 'https://other.example'
        with self.assertRaises(ValueError):
            self.sync({A: b'secret'})
        self.assertEqual(self.peer.calls, [])
