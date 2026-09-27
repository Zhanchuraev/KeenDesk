import copy
import hashlib
import io
import os
from pathlib import Path
import shlex
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import common
import firewall
import install


def cfg(**overrides):
    value=dict(address='10.147.17.1',interfaces=['zt0'],networks=[],uid=21116,direct='off')
    value.update(overrides)
    return common.validate(value)


class ConfigTests(unittest.TestCase):
    def test_safe_addresses_and_interface_names(self):
        for address in ['10.147.17.1','rustdesk.example.net']:
            self.assertEqual(cfg(address=address)['address'],address)
        for address in ['wss://host/path','host:8443','0.0.0.0','127.0.0.1','999.1.1.1','-host','a;reboot','a\nreboot','a/b']:
            with self.subTest(address=address),self.assertRaises(ValueError): cfg(address=address)
        for interface in ['','*','+','zt0;reboot','zt0\nfoo','lo']:
            with self.subTest(interface=interface),self.assertRaises(ValueError): cfg(interfaces=[interface])

    def test_wildcard_requires_specific_source_network(self):
        for networks in [[],['0.0.0.0/0']]:
            with self.assertRaises(ValueError): cfg(interfaces=['ppp+'],networks=networks)
        self.assertEqual(cfg(interfaces=['ppp+'],networks=['10.77.0.0/24'])['interfaces'],['ppp+'])

    def test_reject_invalid_uid_and_network(self):
        for uid in [0,True,-1,999999,'21116']:
            with self.subTest(uid=uid),self.assertRaises(ValueError): cfg(uid=uid)
        for network in ['0/0','10.0.0.1/24','::/0','1;reboot']:
            with self.subTest(network=network),self.assertRaises(ValueError): cfg(networks=[network])

    def test_atomic_config_is_complete_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            common.atomic_json(path,cfg())
            self.assertEqual(common.json.loads(path.read_text()),cfg())
            self.assertFalse(path.with_name('config.json.new').exists())

    def test_refuse_foreign_installation_before_any_command(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(install,'CONF',Path(temp)),patch.object(install,'run') as command:
                with self.assertRaisesRegex(RuntimeError,'другая установка'): install.fresh_preflight()
                command.assert_not_called()


class FakeTables:
    """Small command adapter, allowing assertions on unrelated rules and closure."""
    def __init__(self):
        self.tables={('filter','INPUT'):[['-i','keep0','-j','ACCEPT']],
                     ('mangle','OUTPUT'):[['-j','XKEEN']],
                     ('nat','OUTPUT'):[['-j','OTHER_NAT']]}
        self.commands=[]

    def __call__(self,binary,table,*args,check=True):
        from types import SimpleNamespace
        action,chain,*tail=args
        key=(table,chain)
        self.commands.append((table,args))
        code=0; output=''
        if action=='-N':
            if key in self.tables: code=1
            else: self.tables[key]=[]
        elif key not in self.tables: code=1
        elif action=='-S':
            output='\n'.join(shlex.join(['-A',chain,*r]) for r in self.tables[key])
        elif action=='-C': code=0 if list(tail) in self.tables[key] else 1
        elif action=='-A': self.tables[key].append(list(tail))
        elif action=='-I': self.tables[key].insert(int(tail[0])-1,list(tail[1:]))
        elif action=='-D':
            if len(tail)==1 and tail[0].isdigit(): self.tables[key].pop(int(tail[0])-1)
            else: self.tables[key].remove(list(tail))
        elif action=='-F': self.tables[key]=[]
        elif action=='-X': del self.tables[key]
        else: raise AssertionError(args)
        if check and code: raise RuntimeError('fake iptables failure '+str(args))
        # Any attached IPv4 ingress chain remains closed by a terminal DROP.
        if any('RDE_INPUT' in row for row in self.tables[('filter','INPUT')]):
            assert self.tables[('filter','RDE_INPUT')][-1]==['-j','DROP']
        return SimpleNamespace(returncode=code,stdout=output,stderr='')


class FirewallTests(unittest.TestCase):
    def test_reconcile_never_flushes_input_or_touches_foreign_chains(self):
        kernel=FakeTables()
        with patch.object(firewall,'ipt',kernel):
            firewall.reconcile_input('iptables',cfg())
            firewall.reconcile_output('iptables',cfg())
            first=copy.deepcopy(kernel.tables)
            firewall.reconcile_input('iptables',cfg())
            firewall.reconcile_output('iptables',cfg())
            self.assertEqual(first,kernel.tables)
            self.assertIn(['-i','keep0','-j','ACCEPT'],kernel.tables[('filter','INPUT')])
            self.assertIn(['-j','XKEEN'],kernel.tables[('mangle','OUTPUT')])
            self.assertIn(['-j','OTHER_NAT'],kernel.tables[('nat','OUTPUT')])
            self.assertFalse(any(args[:2]==('-F','RDE_INPUT') for _,args in kernel.commands))

    def test_changing_network_revokes_old_allows_and_preserves_drop(self):
        kernel=FakeTables()
        with patch.object(firewall,'ipt',kernel):
            firewall.reconcile_input('iptables',cfg(interfaces=['br0']))
            firewall.reconcile_input('iptables',cfg(interfaces=['ppp+'],networks=['10.77.0.0/24']))
        rows=kernel.tables[('filter','RDE_INPUT')]
        self.assertFalse(any('br0' in row for row in rows))
        allowed=[row for row in rows if 'ppp+' in row]
        self.assertEqual(len(allowed),2)
        self.assertTrue(all('10.77.0.0/24' in row for row in allowed))

    def test_ipv6_blocks_all_external_access(self):
        self.assertEqual(firewall.input_rules(cfg(),True),[['-i','lo','-j','ACCEPT'],['-j','DROP']])

    def test_ws_ports_not_in_allow_list(self):
        rules=firewall.input_rules(cfg())
        self.assertTrue(any('21115:21117' in row for row in rules))
        self.assertFalse(any(any(p in row for p in ('21118','21119','21115:21119')) for row in rules))

    def test_public_cidr_has_stable_iptables_representation(self):
        self.assertEqual(firewall.input_rules(cfg()),firewall.input_rules(cfg(networks=['0.0.0.0/0'])))

    def test_direct_mark_only_for_known_mode_and_ipv4(self):
        self.assertEqual(firewall.direct_rules(cfg()),[['-j','ACCEPT']])
        self.assertIn(['-j','MARK','--set-mark','0xffffa00'],firewall.direct_rules(cfg(direct='xkeen')))
        self.assertEqual(firewall.direct_rules(cfg(direct='xkeen'),True),[['-j','ACCEPT']])

    def test_remove_only_owned_references(self):
        kernel=FakeTables()
        with patch.object(firewall,'ipt',kernel),patch.object(firewall,'binaries',return_value=[('iptables',False)]):
            firewall.reconcile_input('iptables',cfg())
            firewall.reconcile_output('iptables',cfg())
            firewall.remove()
        self.assertEqual(kernel.tables,FakeTables().tables)


def archive(machine=183,interpreter=False,paths=None):
    data=bytearray(12000)
    data[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<H',data,18,machine)
    struct.pack_into('<Q',data,32,64)
    struct.pack_into('<HH',data,54,56,1)
    struct.pack_into('<I',data,64,3 if interpreter else 1)
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        for name in paths or ('arm64v8/hbbs','arm64v8/hbbr'): z.writestr(name,data)
    return stream.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_checksum_mismatch_is_fatal_before_extract(self):
        with self.assertRaisesRegex(RuntimeError,'SHA-256'): install.verified_archive(b'untrusted')

    def test_only_expected_arm64_static_files_accepted(self):
        raw=archive()
        with patch.object(install,'UPSTREAM_SHA256',hashlib.sha256(raw).hexdigest()):
            self.assertEqual(set(install.verified_archive(raw)),{'hbbs','hbbr'})

    def test_reject_dynamic_wrong_architecture_and_paths(self):
        for raw in [archive(machine=62),archive(interpreter=True),archive(paths=['../hbbs','arm64v8/hbbr'])]:
            with patch.object(install,'UPSTREAM_SHA256',hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(RuntimeError): install.verified_archive(raw)

    def test_bootstrap_payload_hashes_match(self):
        text=(ROOT/'install.sh').read_text(encoding='utf-8')
        block=text.split("done <<'CHECKSUMS'\n",1)[1].split('\nCHECKSUMS',1)[0]
        for line in block.splitlines():
            digest,name=line.split()
            self.assertEqual(hashlib.sha256((ROOT/'src'/name).read_bytes()).hexdigest(),digest,name)

    @unittest.skipUnless(os.environ.get('RDE_TEST_ARCHIVE'),'Set RDE_TEST_ARCHIVE to test the official downloaded archive')
    def test_actual_official_archive(self):
        binaries=install.verified_archive(Path(os.environ['RDE_TEST_ARCHIVE']).read_bytes())
        self.assertEqual(set(binaries),{'hbbs','hbbr'})


if __name__=='__main__': unittest.main()
