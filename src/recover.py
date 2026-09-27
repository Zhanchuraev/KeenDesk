#!/opt/bin/python3
"""Standalone recovery, deliberately independent of installed KeenDesk modules.

A copy outside /opt/etc/rustdesk is invoked by the boot guard. Snapshots are
private directories, not archives extracted over the filesystem.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

ROOT = Path('/opt/var/lib/keendesk-update')
PENDING = ROOT/'pending.json'
TARGETS = ('/opt/etc/rustdesk','/opt/var/lib/rustdesk','/opt/sbin/hbbs',
           '/opt/sbin/hbbr','/opt/bin/rustdeskctl','/opt/etc/ndm/netfilter.d/90-rustdesk.sh',
           '/opt/etc/init.d/S90rustdesk')


def write_json(path,value):
    temp = path.with_name(path.name+'.new')
    with open(temp,'w') as stream:
        os.chmod(temp,0o600)
        json.dump(value,stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp,path)
    sync()


def sync():
    if hasattr(os,'sync'): os.sync()


def inventory(root):
    result = {}
    for p in sorted(root.rglob('*')):
        if p.is_symlink(): raise RuntimeError('Символические ссылки в снимке запрещены: '+str(p))
        if p.is_file(): result[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def validate_snapshot(record):
    snapshot = Path(record['snapshot'])
    if snapshot.parent != ROOT or not snapshot.name.startswith('snapshot-') or snapshot.resolve() != snapshot:
        raise RuntimeError('Недопустимый путь снимка обновления')
    payload = snapshot/'files'
    manifest = (snapshot/'sha256.json').read_bytes()
    if hashlib.sha256(manifest).hexdigest() != record['manifest_sha256']:
        raise RuntimeError('Повреждён манифест резервной копии')
    if inventory(payload) != json.loads(manifest):
        raise RuntimeError('Повреждена резервная копия; автоматическое восстановление остановлено')
    marker = json.loads((payload/'opt/etc/rustdesk/managed.json').read_text())
    if marker.get('owner') != 'Zhanchuraev/rustdesk-entware':
        raise RuntimeError('Снимок не принадлежит KeenDesk')
    for name in TARGETS:
        if not (payload/name.lstrip('/')).exists(): raise RuntimeError('Неполный снимок: '+name)
    return payload


def stop_recorded_services():
    # Exact executable arguments, never killall. Only KeenDesk's own known paths.
    expected = (b'/opt/etc/rustdesk/supervisor.py',b'/opt/etc/rustdesk/web.py',
                b'/opt/sbin/hbbs',b'/opt/sbin/hbbr')
    def matches():
        found = []
        for p in Path('/proc').glob('[0-9]*/cmdline'):
            try:
                if any(x in p.read_bytes().split(b'\0') for x in expected): found.append(int(p.parent.name))
            except OSError: pass
        return found
    for sig, duration in ((signal.SIGTERM,12),(signal.SIGKILL,3)):
        for pid in matches():
            try: os.kill(pid,sig)
            except ProcessLookupError: pass
        deadline = time.monotonic()+duration
        while matches() and time.monotonic() < deadline: time.sleep(.1)
        if not matches(): break
    if matches(): raise RuntimeError('Не удалось остановить службы для восстановления')


def restore(record):
    payload = validate_snapshot(record)  # Verify every byte BEFORE stopping/deleting anything.
    stop_recorded_services()
    # v0.1.0 does not know the optional panel chain. Remove only our exact
    # reference before restoring either version; its firewall recreates it if enabled.
    for binary in ('iptables','ip6tables'):
        if not shutil.which(binary): continue
        base = [binary,'-w','-t','filter']
        def command(args): return subprocess.run(base+args,capture_output=True,text=True,timeout=20)
        if command(['-S','RDW_INPUT']).returncode: continue
        import shlex
        for line in command(['-S','INPUT']).stdout.splitlines():
            row = shlex.split(line)
            if row[:2] == ['-A','INPUT'] and row[-2:] == ['-j','RDW_INPUT']:
                if command(['-D','INPUT',*row[2:]]).returncode: raise RuntimeError('Не удалось убрать правило веб-панели')
        for args in (['-F','RDW_INPUT'],['-X','RDW_INPUT']):
            if command(args).returncode: raise RuntimeError('Не удалось удалить цепочку веб-панели')
    for name in TARGETS:
        # Keep the already-installed recovery guard until the transaction is fully
        # restored. It also understands the older v0.1 manager's start command.
        if name == '/opt/etc/init.d/S90rustdesk': continue
        target = Path(name)
        source = payload/name.lstrip('/')
        if target.is_symlink(): raise RuntimeError('Неожиданная ссылка: '+name)
        if source.is_dir():
            # Snapshot stays intact, so retry after a power cut is idempotent.
            if target.exists(): shutil.rmtree(target)
            shutil.copytree(source,target)
        else:
            staged = target.with_name(target.name+'.restore')
            shutil.copy2(source,staged); os.replace(staged,target)
    cfg = json.loads(Path('/opt/etc/rustdesk/server.json').read_text())
    data = Path('/opt/var/lib/rustdesk')
    for path in [data,*data.rglob('*')]:
        os.chown(path,cfg['uid'],cfg['uid'])
        path.chmod(0o700 if path.is_dir() else 0o600)
    for name in ('rustdesk.pid','rustdesk-processes.json','keendesk-web.pid'):
        (Path('/opt/var/run')/name).unlink(missing_ok=True)
    sync()
    write_json(ROOT/'last-recovery.json',dict(time=time.time(),snapshot=record['snapshot'],reason=record.get('reason','Незавершённое обновление')))
    PENDING.unlink(missing_ok=True)
    sync()
    print('KeenDesk: предыдущая версия, настройки и ключи восстановлены.')


def main():
    import fcntl
    if os.geteuid() != 0: raise RuntimeError('Требуется root')
    with open('/opt/var/run/rustdesk-install.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if PENDING.exists(): restore(json.loads(PENDING.read_text()))


if __name__ == '__main__': main()
