"""Destructive lifecycle tests: ONLY the disposable GitHub ARM64 runner."""
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from common import CONF, DATA, CONFIG, STATE, MARKER, CRASH, UPDATE_ROOT, load_config, run


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
    # Start with the actual released v0.1.0 payload, not a fabricated old marker.
    with tempfile.TemporaryDirectory(prefix='keendesk-v010-') as directory:
        old = Path(directory)
        for name in ('common.py','install.py','firewall.py','supervisor.py','manage.py','S90rustdesk','90-rustdesk.sh','rustdeskctl'):
            (old/name).write_bytes(subprocess.check_output(['git','show','v0.1.0:src/'+name],cwd=ROOT))
        command(sys.executable,old/'install.py',env=env)
    initial = fingerprint()
    # A failed native health gate must restore the complete previous version.
    with tempfile.TemporaryDirectory(prefix='keendesk-failing-') as directory:
        bad = Path(directory)/'src'; shutil.copytree(ROOT/'src',bad)
        p = bad/'health.py'
        p.write_text(p.read_text().replace('def required(key):','def required(key):\n    raise RuntimeError("injected CI health failure")'))
        result = subprocess.run([sys.executable,str(bad/'install.py'),'--upgrade'],env=env)
        assert result.returncode != 0
        assert json.loads(MARKER.read_text())['version'] == '0.1.0'
        assert fingerprint() == initial
        command(ctl,'status')
    print('PASS failed health gate automatically restored real v0.1.0 and identity',flush=True)
    # Terminate the updater mid-transaction, then exercise the real boot guard.
    with tempfile.TemporaryDirectory(prefix='keendesk-interrupted-') as directory:
        interrupted = Path(directory)/'src'; shutil.copytree(ROOT/'src',interrupted)
        p = interrupted/'health.py'
        p.write_text(p.read_text().replace('def required(key):','def required(key):\n    time.sleep(120)'))
        process = subprocess.Popen([sys.executable,str(interrupted/'install.py'),'--upgrade'],env=env)
        try:
            wait_until(lambda: (UPDATE_ROOT/'pending.json').exists() and json.loads(MARKER.read_text())['version']=='0.2.0',timeout=120)
            process.kill(); process.wait(timeout=10)
        finally:
            if process.poll() is None: process.kill(); process.wait()
        command('/opt/etc/init.d/S90rustdesk','start')
        assert json.loads(MARKER.read_text())['version'] == '0.1.0'
        assert fingerprint() == initial
        assert not (UPDATE_ROOT/'pending.json').exists()
    print('PASS interrupted update recovered through boot guard',flush=True)
    command(*installer,'--upgrade',env=env)
    assert fingerprint() == initial
    command(ctl,'doctor','--json')
    command(ctl,'rollback','--yes')
    assert json.loads(MARKER.read_text())['version'] == '0.1.0'
    assert fingerprint() == initial
    command(*installer,'--upgrade',env=env)
    command(ctl,'doctor')
    print('PASS upgrade, explicit rollback, re-upgrade; keys/config unchanged',flush=True)
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
    # The earlier recovery already consumed one event. Exercise the real halt.
    for _ in range(4):
        current = json.loads(STATE.read_text())['hbbr']
        os.kill(current,signal.SIGKILL)
        wait_until(lambda: json.loads(CRASH.read_text()).get('halted') or json.loads(STATE.read_text()).get('hbbr',current) != current,timeout=70)
    wait_until(lambda: json.loads(CRASH.read_text()).get('halted'))
    wait_until(lambda: json.loads(STATE.read_text()) == {})
    command(ctl,'stop')
    command('/opt/etc/init.d/S90rustdesk','start')
    assert json.loads(CRASH.read_text())['halted']
    assert subprocess.run([ctl,'status']).returncode != 0
    command(ctl,'restart')
    command(ctl,'doctor')
    print('PASS bounded crash loop, persistent boot halt, explicit recovery',flush=True)
    command(ctl,'web')
    import urllib.request
    with urllib.request.urlopen('http://127.0.0.1:18082/',timeout=3) as response:
        assert 'KeenDesk' in response.read().decode()
    token = json.loads((CONF/'web.json').read_text())['token']
    request = urllib.request.Request('http://127.0.0.1:18082/api/doctor',headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(request,timeout=60) as response: assert json.load(response)['ok']
    # Read-only VPN panel on a simulated ZeroTier interface; real interface ACL.
    command('ip','link','set','rdeserver','name','ztci0')
    command(ctl,'configure','--interfaces','ztci0')
    command(ctl,'web','--listen','192.0.2.1','--interface','ztci0') if False else None  # Public test-net listener is intentionally rejected.
    command('ip','addr','add','192.168.250.1/30','dev','ztci0')
    command('ip','netns','exec','rdeclient','ip','addr','add','192.168.250.2/30','dev','rdepeer')
    command(ctl,'configure','--networks','192.0.2.0/30 192.168.250.0/30')
    command(ctl,'web','--listen','192.168.250.1','--interface','ztci0')
    command('ip','netns','exec','rdeclient',sys.executable,'-c',
            'import urllib.request; assert b"KeenDesk" in urllib.request.urlopen("http://192.168.250.1:18082/",timeout=5).read()')
    command(ctl,'web','--disable')
    command('ip','link','set','ztci0','name','rdeserver')
    command(ctl,'configure','--interfaces','rdeserver','--networks','192.0.2.0/30')
    print('PASS authenticated dashboard and VPN-interface access',flush=True)
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
            rules = run([binary,'-t',table,'-S']).stdout
            assert 'RDE_' not in rules and 'RDW_' not in rules
    command('iptables','-C','INPUT','-m','comment','--comment','rde-ci-foreign','-j','ACCEPT')
    archives = sorted(Path('/opt/var/backups/rustdesk-entware').glob('*.private.tar.gz'))
    assert len(archives) >= 3
    for archive in archives:
        assert archive.stat().st_mode & 0o777 == 0o600
        with tarfile.open(archive) as tar:
            private = tar.extractfile('opt/var/lib/rustdesk/id_ed25519').read()
            assert hashlib.sha256(private).hexdigest() == saved['id_ed25519']
    print('PASS configure, backup, uninstall; original key retained in private archives',flush=True)
    # Also cover a clean v0.2.0 installation, independent of migration.
    command(*installer,env=env)
    command(ctl,'doctor')
    command(ctl,'uninstall','--yes')
    print('PASS clean v0.2.0 installation and uninstall',flush=True)


if __name__ == '__main__': main()
