"""Cloud-visible identities are independent of the trusted machine's local listeners."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Addresses(unittest.TestCase):
    def addresses(self, advertised):
        return subprocess.run(['bash', '-c', 'source "$1"; service_addresses; printf "%s" "$HOST_IP"',
                               'addresses-test', str(ROOT / 'deployment/lib/common.sh')],
                              env={**os.environ, 'HOST_IP': advertised}, capture_output=True, text=True)

    def test_service_address_accepts_public_or_private_unicast(self):
        for ip in ('203.0.113.10', '192.168.16.223'):
            with self.subTest(ip=ip):
                result = self.addresses(ip)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, ip)
        for ip in ('127.0.0.1', '0.0.0.0', '224.0.0.1'):
            with self.subTest(ip=ip):
                self.assertNotEqual(self.addresses(ip).returncode, 0)

    def test_public_trustee_url_keeps_aa_and_cdh_ca_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            ca = Path(temp) / 'ca.pem'
            ca.write_text('-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n')
            result = subprocess.run(['python3', str(ROOT / 'deployment/guest/render-guest-initdata.py'),
                                     '203.0.113.10', str(ca)], capture_output=True, text=True, check=True)
            data = tomllib.loads(result.stdout)['data']
            aa, cdh = tomllib.loads(data['aa.toml']), tomllib.loads(data['cdh.toml'])
            self.assertEqual(aa['token_configs']['kbs']['url'], 'https://203.0.113.10:8443')
            self.assertEqual(cdh['kbc']['url'], aa['token_configs']['kbs']['url'])
            self.assertEqual(cdh['kbc']['kbs_cert'].strip(), ca.read_text().strip())

    def test_tls_authenticates_advertised_ip_without_binding_that_address(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            def openssl(*args):
                subprocess.run(['openssl', *args], cwd=directory, check=True, capture_output=True)
            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=test-ca',
                    '-keyout', 'ca.key', '-out', 'ca.pem')
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=test-service',
                    '-keyout', 'server.key', '-out', 'server.csr')
            (directory / 'server.ext').write_text((ROOT / 'deployment/trustee/certificates/server.example.ext').read_text()
                                                  .replace('TRUSTED_SERVICE_IP', '203.0.113.10'))
            openssl('x509', '-req', '-days', '1', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                    '-CAcreateserial', '-extfile', 'server.ext', '-out', 'server.pem')
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'TLS identity verified')
                def log_message(self, *args):
                    pass
            config = tomllib.loads((ROOT / 'deployment/trustee/kbs-config.example.toml').read_text())
            listen_ip = config['http_server']['sockets'][0].split(':')[0]
            server = HTTPServer((listen_ip, 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory / 'server.pem', directory / 'server.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = ssl.create_default_context(cafile=str(directory / 'ca.pem'))
                with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as raw:
                    with client.wrap_socket(raw, server_hostname='203.0.113.10') as channel:
                        channel.sendall(b'GET / HTTP/1.0\r\nHost: service\r\n\r\n')
                        response = b''
                        while block := channel.recv(1024):
                            response += block
                        self.assertIn(b'200 OK', response)
                        self.assertIn(b'TLS identity verified', response)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
