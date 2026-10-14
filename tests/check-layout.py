#!/usr/bin/env python3.11
"""Validate maintained documentation paths and configuration syntax offline."""
import ast
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
files = [ROOT / n for n in subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '--cached', '--others', '--exclude-standard'], text=True).splitlines()]
errors = []
count = 0
for path in files:
    if not path.is_file():
        continue
    rel = str(path.relative_to(ROOT))
    if rel.startswith('repos/'):
        continue
    if path.suffix == '.md':
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', path.read_text()):
            if target.startswith(('http:', 'https:', '#', 'mailto:')):
                continue
            local, _, anchor = target.partition('#')
            if local and not (path.parent / local).exists():
                errors.append(f'{rel}: missing link {target}')
            elif anchor:
                document = (path.parent / local) if local else path
                if document.suffix == '.md':
                    slugs = set()
                    in_code = False
                    for line in document.read_text().splitlines():
                        if line.startswith('```'):
                            in_code = not in_code
                        elif not in_code and re.match(r'#{1,6} ', line):
                            heading = line.lstrip('# ').strip().lower()
                            slugs.add(re.sub(r'[^\w -]', '', heading).replace(' ', '-'))
                    if anchor not in slugs:
                        errors.append(f'{rel}: missing anchor {target}')
    elif path.suffix == '.json' or path.name.endswith('.json.in'):
        try:
            json.loads(path.read_text())
        except ValueError as exc:
            errors.append(f'{rel}: {exc}')
    elif path.suffix == '.toml':
        try:
            tomllib.loads(path.read_text())
        except ValueError as exc:
            errors.append(f'{rel}: {exc}')
    elif path.suffix == '.py' or path.read_bytes().startswith(b'#!/usr/bin/env python'):
        try:
            ast.parse(path.read_text(), filename=rel)
        except SyntaxError as exc:
            errors.append(f'{rel}: {exc}')
    elif path.suffix == '.sh' or path.read_bytes().startswith(b'#!/usr/bin/env bash'):
        result = subprocess.run(['bash', '-n', str(path)], capture_output=True, text=True)
        if result.returncode:
            errors.append(f'{rel}: {result.stderr}')
    if rel.startswith('deployment/guest/') and 'deployment/artifacts/cache/' in path.read_text(errors='replace'):
        errors.append(f'{rel}: obsolete build cache location')
    count += 1
if errors:
    raise SystemExit('\n'.join(errors))
print(f'{count} maintained files checked: links, JSON/TOML, Python and shell syntax')
