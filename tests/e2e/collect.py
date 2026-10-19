#!/usr/bin/env python3
"""Check OpenCode task events or repaired workspace without executing guest code."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_clamp(source, x, lower, upper):
    """Interpret a deliberately tiny expression grammar; NEVER exec/eval guest code."""
    require(len(source) <= 4096, 'source too large')
    tree = ast.parse(source)
    require(len(list(ast.walk(tree))) <= 64, 'expression too complex')
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef), 'one function required')
    fn = tree.body[0]
    require(fn.name == 'clamp' and not fn.decorator_list and fn.returns is None, 'function identity')
    a = fn.args
    require([p.arg for p in a.args] == ['x', 'lower', 'upper'] and
            not a.posonlyargs and not a.kwonlyargs and not a.defaults and
            not a.kw_defaults and a.vararg is None and a.kwarg is None and
            all(p.annotation is None for p in a.args), 'function arguments')
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    require(len(body) == 1 and isinstance(body[0], ast.Return), 'only a return expression allowed')

    def interpret(node):
        if isinstance(node, ast.Name) and node.id in ('x', 'lower', 'upper'):
            return {'x': x, 'lower': lower, 'upper': upper}[node.id]
        if isinstance(node, ast.Constant) and type(node.value) is int and abs(node.value) < 10**12:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -interpret(node.operand)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('min', 'max'):
            require(not node.keywords and len(node.args) == 2, 'two positional arguments required')
            values = [interpret(n) for n in node.args]
            return min(values) if node.func.id == 'min' else max(values)
        raise Rejected('unsupported expression; never execute on T')
    return interpret(body[0].value)


def verify_work(source, result, public_test, original_test):
    require(public_test == original_test, 'agent changed public tests')
    count = 0
    for lower in (-101, -1, 0, 3, 107):
        for width in (0, 1, 9, 100):
            upper = lower + width
            for x in (lower-1000, lower-1, lower, lower+1, upper, upper+1, upper+1000):
                expected = lower if x < lower else upper if x > upper else x
                require(safe_clamp(source, x, lower, upper) == expected, 'independent behavior mismatch')
                count += 1
    require(isinstance(result, dict) and set(result) == {'public_cases'} and
            isinstance(result['public_cases'], list) and
            all(type(v) is int for v in result['public_cases']) and
            result == {'public_cases': [0, 4, 9, 0]}, 'missing or incorrect agent result file')
    return {'source_sha256': digest(source.encode()), 'oracle_cases': count,
            'result_sha256': digest(json.dumps(result, sort_keys=True).encode())}


def verify_events(events):
    """OpenCode run --format json. Retain hashes/counts, not raw content."""
    require(0 < len(events) <= 2000, 'bounded event count required')
    sessions, calls, tools = set(), set(), set()
    text_seen = finished = ran_tests = False
    for event in events:
        require(isinstance(event, dict) and event.get('type') != 'error', 'agent error')
        session = event.get('sessionID')
        require(isinstance(session, str) and 0 < len(session) <= 128, 'session missing')
        sessions.add(session)
        part = event.get('part', {})
        require(isinstance(part, dict), 'event part must be an object')
        require(part.get('sessionID') == session, 'event/part session mismatch')
        kind = event.get('type')
        if kind == 'text':
            require(isinstance(part.get('text'), str), 'text must be a string')
            text_seen |= bool(part['text'].strip()) and not part.get('synthetic', False)
        if kind == 'step_finish':
            tokens = part.get('tokens', {})
            require(isinstance(tokens, dict) and type(tokens.get('output')) is int and
                    tokens['output'] > 0, 'model output usage absent')
            finished |= part.get('reason') == 'stop'
        if kind == 'tool_use':
            require(isinstance(part.get('state'), dict) and
                    part['state'].get('status') == 'completed', 'tool failed')
            call = part.get('callID')
            require(isinstance(call, str) and call and call not in calls, 'missing/duplicate tool call')
            calls.add(call)
            name = part.get('tool')
            require(isinstance(name, str), 'tool name required')
            tools.add(name)
            state = part['state']
            require(isinstance(state.get('input', {}), dict) and
                    isinstance(state.get('metadata', {}), dict), 'tool state fields')
            if name == 'bash' and state.get('input', {}).get('command') == 'python3 test_clamp.py':
                ran_tests |= state.get('metadata', {}).get('exit') == 0
    require(len(sessions) == 1, 'mixed sessions')
    require(text_seen and finished and ran_tests and tools.intersection({'edit', 'write', 'apply_patch'}),
            'need model text, completed edit, actual successful test command and final stop')
    return {'session_sha256': digest(next(iter(sessions)).encode()),
            'tool_calls': len(calls), 'test_command_completed': True, 'model_text_observed': True}


def read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                'regular file with one link required')
        require(metadata.st_size <= limit, 'file size bound')
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'file size bound')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, help='directory containing the three task outputs')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.work:
        source = read(args.work / 'clamp.py', 4096).decode()
        result = json.loads(read(args.work / 'result.json', 4096))
        public_test = read(args.work / 'test_clamp.py', 16384)
        original_test = (ROOT / 'tests/e2e/fixtures/project/test_clamp.py').read_bytes()
        summary = verify_work(source, result, public_test, original_test)
    else:
        data = sys.stdin.buffer.read(2_000_001)
        require(len(data) <= 2_000_000, 'event byte bound')
        summary = verify_events([json.loads(line) for line in data.splitlines() if line.strip()])
    report = {'schema': 1, 'scope': 'application evidence', **summary}
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print('Application check passed. Bind this result to the sandbox UID and deployed image for live acceptance.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, SyntaxError, RecursionError):
        print('Collection failed: missing or invalid task evidence; raw content suppressed.', file=sys.stderr)
        raise SystemExit(1)
