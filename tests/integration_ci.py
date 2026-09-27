"""Destructive lifecycle tests: ONLY the disposable GitHub ARM64 runner."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from common import CONF, DATA, CONFIG, STATE, load_config, run


def command(*args, **kwargs):
    result = subprocess.run(list(map(str,args)),check=True,text=True,**kwargs)
    return result


def wait_until(test,timeout=25):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if test(): return
        time.sleep(.5)
    raise AssertionError('Condition not reached before timeout')


def fingerprint():
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (CONFIG,DATA/'id_ed25519',DATA/'id_ed25519.pub')}


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ARCH') == 'ARM64' and os.geteuid() == 0
    assert not CONF.exists(), 'Never test over an existing installation'
    env = dict(os.environ,RD_ADDRESS='192.0.2.1',RD_INTERFACES='rdeserver',
               RD_NETWORKS='192.0.2.0/30',RD_XKEEN='off')
    installer = [sys.executable,str(ROOT/'src/install.py')]
    ctl = '/opt/bin/rustdeskctl'
    command(*installer,env=env)
    cfg = load_config()
    saved = fingerprint()
    assert DATA.stat().st_uid == cfg['uid']
    assert DATA.stat().st_mode & 0o777 == 0o700
    assert (DATA/'id_ed25519').stat().st_mode & 0o777 == 0o600
    for pid in json.loads(STATE.read_text()).values():
        assert Path('/proc',str(pid)).stat().st_uid == cfg['uid']
    command('ip','netns','exec','rdeclient',sys.executable,
            ROOT/'tests/native_smoke.py','192.0.2.1',DATA/'id_ed25519.pub')
    command(*installer,env=env)
    assert saved == fingerprint(), 'Repeat install changed identity/config'
    before = json.loads(STATE.read_text())['hbbr']
    os.kill(before,signal.SIGKILL)
    wait_until(lambda: json.loads(STATE.read_text()).get('hbbr',before) != before)
    print('PASS child recovery',flush=True)
    rule = ['-p','tcp','-m','multiport','--dports','21115:21119','-j','RDE_INPUT']
    command('iptables','-D','INPUT',*rule)
    command('/opt/etc/ndm/netfilter.d/90-rustdesk.sh')
    wait_until(lambda: run(['iptables','-C','INPUT',*rule],check=False).returncode == 0)
    # Real iptables (not the unit-test model): a second reconcile must preserve rules.
    command('/opt/bin/python3',CONF/'firewall.py')
    before_rules = run(['iptables-save']).stdout
    command('/opt/bin/python3',CONF/'firewall.py')
    after_rules = run(['iptables-save']).stdout
    def stable(text): return [x for x in text.splitlines() if x.startswith('-A')]
    assert stable(before_rules) == stable(after_rules)
    print('PASS firewall hook and real-kernel reconciliation',flush=True)
    command(ctl,'configure','--networks','192.0.2.0/29')
    assert saved['id_ed25519'] == fingerprint()['id_ed25519']
    command(ctl,'backup')
    command(ctl,'status')
    command(ctl,'uninstall','--yes')
    assert not CONF.exists() and not DATA.exists()
    for binary in ('iptables','ip6tables'):
        for table in ('filter','mangle','nat'):
            assert 'RDE_' not in run([binary,'-t',table,'-S']).stdout
    command('iptables','-C','INPUT','-m','comment','--comment','rde-ci-foreign','-j','ACCEPT')
    archives = sorted(Path('/opt/var/backups/rustdesk-entware').glob('*.private.tar.gz'))
    assert len(archives) >= 3
    for archive in archives:
        assert archive.stat().st_mode & 0o777 == 0o600
        with tarfile.open(archive) as tar:
            private = tar.extractfile('opt/var/lib/rustdesk/id_ed25519').read()
            assert hashlib.sha256(private).hexdigest() == saved['id_ed25519']
    print('PASS configure, backup, uninstall; original key retained in private archives',flush=True)


if __name__ == '__main__': main()
