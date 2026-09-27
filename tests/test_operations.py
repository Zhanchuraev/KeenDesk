"""Failure-oriented tests for update trust boundaries and crash protection."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import common
import health
import recover
import restarts
import update
import web


class RestartTests(unittest.TestCase):
    def test_backoff_and_persistent_halt_even_after_reboot(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'crash.json'
            b = restarts.Budget(path)
            delays = [b.failure('hbbr','signal',now=100+i) for i in range(5)]
            self.assertEqual(delays,[5,10,20,40,60])
            self.assertTrue(restarts.Budget(path).halted)
            b.stable()
            self.assertTrue(b.halted)

    def test_old_crashes_expire_and_stable_service_resets(self):
        with tempfile.TemporaryDirectory() as root:
            b = restarts.Budget(Path(root)/'crash.json')
            b.failure('hbbs','1',now=1)
            self.assertEqual(b.failure('hbbs','1',now=602),5)
            b.stable()
            self.assertEqual(b.state,{'events':[], 'halted':False})


class UpdateTests(unittest.TestCase):
    def test_manifest_cannot_introduce_paths_or_missing_payloads(self):
        good = dict(version='0.2.0',files={x:'a'*64 for x in update.FILES})
        update.validate_manifest(good,'v0.2.0')
        for files in ({'../common.py':'a'*64}, {x:'bad' for x in update.FILES}):
            with self.assertRaises(RuntimeError): update.validate_manifest(dict(version='0.2.0',files=files),'v0.2.0')
        with self.assertRaises(RuntimeError): update.validate_manifest(good,'v0.3.0')
        for tag in ('main','v1.2.3;reboot','../../v1.2.3','v1.2.3-rc1'):
            with self.assertRaises(ValueError): update.version_tuple(tag)

    def test_bad_download_never_executes_release_code(self):
        manifest = dict(version='9.0.0',files={x:'a'*64 for x in update.FILES})
        with tempfile.TemporaryDirectory() as root, \
             patch.object(update,'fetch',side_effect=[json.dumps(manifest).encode(),b'tampered']), \
             patch.object(update.tempfile,'TemporaryDirectory',return_value=tempfile.TemporaryDirectory(dir=root)), \
             patch.object(update.subprocess,'run') as execute:
            with self.assertRaisesRegex(RuntimeError,'SHA-256'): update.download_release('v9.0.0')
            execute.assert_not_called()

    def test_recovery_rejects_corruption_before_stopping_anything(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root); snapshot = base/'snapshot-test'; files = snapshot/'files'
            files.mkdir(parents=True); (files/'test').write_text('original')
            manifest = snapshot/'sha256.json'; manifest.write_text(json.dumps(recover.inventory(files)))
            record = dict(snapshot=str(snapshot),manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
            (files/'test').write_text('corrupt')
            with patch.object(recover,'ROOT',base),patch.object(recover,'stop_recorded_services') as stop:
                with self.assertRaisesRegex(RuntimeError,'резервная копия'): recover.restore(record)
                stop.assert_not_called()

    def test_protocol_parser_rejects_truncated_and_oversized_fields(self):
        for raw in (b'\x80',b'\x80'*12,b'\x0a\xff\xff\x7f',b'\x0a\x04x'):
            with self.assertRaises(ValueError): health.fields(raw)
        self.assertEqual(health.fields(health.field(3,'abc')),{3:b'abc'})


class WebTests(unittest.TestCase):
    def test_no_wan_or_wildcard_listener(self):
        cfg = dict(interfaces=['zt0'],networks=[])
        for addr,iface in [('0.0.0.0','zt0'),('8.8.8.8','zt0'),('192.168.1.1','br0'),('192.168.1.1','zt1')]:
            with self.assertRaises(ValueError): web.validate_listen(addr,iface,cfg)
        self.assertIsNone(web.validate_listen('127.0.0.1',None,cfg))

    def test_api_requires_token_and_rejects_cross_origin_host_and_writes(self):
        with web.HTTPServer(('127.0.0.1',0),web.Handler) as server:
            host = '127.0.0.1:'+str(server.server_port)
            server.allowed_host = host; server.token = 'test-token'; server.last_doctor = -100
            thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            def request(headers=None,method='GET',path='/api/status'):
                req = urllib.request.Request('http://'+host+path,headers=headers or {},method=method)
                return urllib.request.urlopen(req,timeout=3)
            try:
                for headers,code in [({},401),({'Authorization':'Bearer wrong'},401),({'Host':'evil.example'},403),({'Authorization':'Bearer test-token','Origin':'https://evil.example'},403)]:
                    with self.assertRaises(urllib.error.HTTPError) as error: request(headers)
                    self.assertEqual(error.exception.code,code)
                with patch.object(web,'dashboard',return_value={'ok':True}):
                    with request({'Authorization':'Bearer test-token'}) as response:
                        self.assertEqual(json.load(response),{'ok':True})
                        self.assertEqual(response.headers['Cache-Control'],'no-store')
                with self.assertRaises(urllib.error.HTTPError) as error: request({'Authorization':'Bearer test-token'},method='POST')
                self.assertEqual(error.exception.code,501)
                with self.assertRaises(urllib.error.HTTPError) as error: request(path='/../../id_ed25519')
                self.assertEqual(error.exception.code,404)
            finally: server.shutdown(); thread.join()


if __name__ == '__main__': unittest.main()
