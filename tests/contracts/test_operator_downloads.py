"""Checked downloads must survive failed transfers without trusting partial files."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = b'public release input\n'


class Downloads(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'archive'

    def run_download(self, url, digest):
        return subprocess.run([
            'bash', '-c', 'source "$1"; download "$2" "$3" "$4"',
            'download-test', str(ROOT / 'deployment/lib/common.sh'), url,
            digest, str(self.path),
        ], capture_output=True, text=True)

    def server(self, body):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}/archive'

    def test_verified_cache_needs_no_network(self):
        self.path.write_bytes(PAYLOAD)
        result = self.run_download('http://127.0.0.1:1/unreachable', hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Using verified cache', result.stdout)

    def test_bad_download_cannot_replace_existing_file(self):
        self.path.write_bytes(b'previous file')
        result = self.run_download(self.server(b'corrupt response'), hashlib.sha256(PAYLOAD).hexdigest())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum mismatch', result.stderr)
        self.assertEqual(self.path.read_bytes(), b'previous file')

    def test_retry_replaces_partial_file_after_validation(self):
        Path(str(self.path) + '.part').write_bytes(b'old partial response')
        result = self.run_download(self.server(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.path.read_bytes(), PAYLOAD)
        self.assertFalse(Path(str(self.path) + '.part').exists())
