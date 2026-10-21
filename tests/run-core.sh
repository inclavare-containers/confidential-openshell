#!/usr/bin/env bash
# Driver, deployment and failure-path contracts. No cloud credentials or services.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 -c 'import sys, cryptography, yaml, tomllib; assert sys.version_info >= (3, 11)'
python3 tests/check-layout.py
components/confidential-driver/controlled-diff.sh
cargo fmt --all -- --check
cargo test --offline --locked -p openshell-driver-confidential-kubernetes
PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}deployment/runtime" python3 -m unittest discover -s tests/contracts -v
python3 -m unittest discover -s tests/e2e -v
