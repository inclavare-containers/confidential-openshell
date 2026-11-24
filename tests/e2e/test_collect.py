"""Task acceptance rejects fabricated results and never executes guest source."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('collect', Path(__file__).with_name('collect.py'))
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)


class WorkAcceptance(unittest.TestCase):
    source = 'def clamp(x, lower, upper):\n    return max(lower, min(x, upper))\n'
    result = {'public_cases': [0, 4, 9, 0]}

    def check(self, source=None, result=None, test=b'unchanged'):
        return collect.verify_work(source or self.source,
                                   self.result if result is None else result,
                                   test, b'unchanged')

    def test_repaired_source_passes_independent_cases(self):
        self.assertEqual(self.check()['oracle_cases'], 140)

    def test_original_bug_fabricated_result_and_test_edit_rejected(self):
        for source, result, test in [
            ('def clamp(x, lower, upper):\n    return min(lower, max(x, upper))\n', self.result, b'unchanged'),
            (self.source, {'public_cases': [True, 4, 9, 0]}, b'unchanged'),
            (self.source, self.result, b'changed'),
        ]:
            with self.subTest(source=source, result=result, test=test), self.assertRaises(ValueError):
                self.check(source, result, test)

    def test_guest_code_imports_calls_and_decorators_never_execute(self):
        for source in [
            'import os\n' + self.source,
            'def clamp(x, lower, upper):\n    return __import__("os").system("false")\n',
            '@dangerous()\n' + self.source,
            'def clamp(x, lower, upper):\n    open("/tmp/forged", "w")\n    return x\n',
        ]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.check(source)


class EventAcceptance(unittest.TestCase):
    def events(self):
        def event(kind, **part):
            return {'type': kind, 'sessionID': 'session',
                    'part': {'sessionID': 'session', **part}}
        return [
            event('tool_use', callID='read', tool='read', state={'status': 'completed'}),
            event('tool_use', callID='edit', tool='edit', state={'status': 'completed'}),
            event('tool_use', callID='test', tool='bash', state={
                'status': 'completed', 'input': {'command': 'python3 test_clamp.py'},
                'metadata': {'exit': 0}}),
            event('text', text='Fixed clamp and ran the tests.'),
            event('step_finish', tokens={'output': 12}, reason='stop'),
        ]

    def test_completed_tool_task_passes(self):
        self.assertEqual(collect.verify_events(self.events())['tool_calls'], 3)

    def test_public_test_in_successful_and_list(self):
        for command in ('python3 test_clamp.py && cat result.json',
                        'cd /sandbox/project && python3 test_clamp.py'):
            with self.subTest(command=command):
                events = self.events()
                events[2]['part']['state']['input']['command'] = command
                self.assertTrue(collect.verify_events(events)['test_command_completed'])

    def test_mention_or_masked_failure_is_not_a_successful_test(self):
        for command in ("echo 'python3 test_clamp.py'",
                        "echo '&&' python3 test_clamp.py '&&'",
                        'python3 test_clamp.py || true',
                        'exit 0 && python3 test_clamp.py'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                events = self.events()
                events[2]['part']['state']['input']['command'] = command
                collect.verify_events(events)

    def test_fake_tool_success_missing_edit_and_mixed_session_rejected(self):
        cases = []
        failed = self.events()
        failed[2]['part']['state']['metadata']['exit'] = 1
        cases.append(failed)
        cases.append([e for e in self.events() if e['part'].get('tool') != 'edit'])
        mixed = self.events()
        mixed[-1]['sessionID'] = mixed[-1]['part']['sessionID'] = 'different'
        cases.append(mixed)
        duplicated = self.events()
        duplicated[1]['part']['callID'] = 'read'
        cases.append(duplicated)
        for events in cases:
            with self.subTest(events=events), self.assertRaises(ValueError):
                collect.verify_events(copy.deepcopy(events))


if __name__ == '__main__':
    unittest.main()
