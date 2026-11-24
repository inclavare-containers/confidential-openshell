"""The native boot reference profile follows the locked Kata release."""
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KataBootProfile(unittest.TestCase):
    def test_cmdline_profile_matches_locked_kata(self):
        profile = runpy.run_path(str(ROOT / 'deployment/baremetal/guest-references.py'))
        lock = json.loads((ROOT / 'deployment/runtime/artifacts.lock.json').read_text())
        self.assertIn(f"kata-deploy-{profile['KATA_VERSION']}.tgz", lock['charts'],
                         'Review the Go shim cmdline and TDX launch measurements for this release')
