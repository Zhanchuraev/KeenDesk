"""Verified release download and transactional upgrade with identity retention."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from common import (VERSION, UPSTREAM_VERSION, UPSTREAM_SHA256, OWNER, CONF, DATA,
                    MARKER, CONFIG, INIT, UPDATE_ROOT, atomic_json, run)
import recover

FILES = ('common.py','install.py','firewall.py','supervisor.py','manage.py','health.py',
         'doctor.py','restarts.py','recover.py','update.py','web.py','index.html',
         'S90rustdesk','90-rustdesk.sh','rustdeskctl')
REPOSITORY = 'Zhanchuraev/KeenDesk'


def fetch(url,limit):
    request = urllib.request.Request(url,headers={'User-Agent':'KeenDesk/'+VERSION})
    with urllib.request.urlopen(request,timeout=60) as response:
        data = response.read(limit+1)
    if len(data) > limit: raise RuntimeError('Ответ GitHub превышает допустимый размер')
    return data


def version_tuple(value):
    if not isinstance(value,str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',value):
        raise ValueError('Нужен стабильный тег vX.Y.Z')
    return tuple(map(int,value[1:].split('.')))


def validate_manifest(manifest,tag):
    if manifest.get('version') != tag[1:] or set(manifest.get('files',{})) != set(FILES):
        raise RuntimeError('Некорректный состав релиза KeenDesk')
    for digest in manifest['files'].values():
        if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):
            raise RuntimeError('Некорректная SHA-256 сумма')


def download_release(tag=None):
    if tag is None:
        release = json.loads(fetch('https://api.github.com/repos/'+REPOSITORY+'/releases/latest',65536))
        if release.get('draft') or release.get('prerelease'): raise RuntimeError('Релиз не является стабильным')
        tag = release['tag_name']
    target = version_tuple(tag)
    if target <= version_tuple('v'+VERSION):
        print('Установлена KeenDesk '+VERSION+'; более новая выбранная версия отсутствует.')
        return
    base = 'https://raw.githubusercontent.com/'+REPOSITORY+'/'+tag+'/'
    manifest = json.loads(fetch(base+'release.json',32768))
    validate_manifest(manifest,tag)
    with tempfile.TemporaryDirectory(prefix='keendesk-release-',dir='/opt/var/tmp') as directory:
        stage = Path(directory)
        for name,digest in manifest['files'].items():
            raw = fetch(base+'src/'+name,512*1024)
            if hashlib.sha256(raw).hexdigest() != digest: raise RuntimeError('SHA-256 не совпал: '+name)
            (stage/name).write_bytes(raw)
        # No release code is imported or run until EVERY payload has passed its hash.
        subprocess.run(['/opt/bin/python3',str(stage/'install.py'),'--upgrade'],check=True)


def identity():
    return {name:hashlib.sha256((DATA/name).read_bytes()).hexdigest()
            for name in ('id_ed25519','id_ed25519.pub')}


def boot_guard():
    return b'''#!/opt/bin/sh
PATH=/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ -f /opt/var/lib/keendesk-update/pending.json ]; then
    /opt/bin/python3 /opt/var/lib/keendesk-update/recover.py || exit 1
    exec /opt/etc/init.d/S90rustdesk "$@"
fi
case "$1" in
    start)
        if grep -q "'boot'" /opt/etc/rustdesk/manage.py; then rd_command=boot; else rd_command=start; fi
        exec /opt/bin/python3 /opt/etc/rustdesk/manage.py "$rd_command";;
    kill) exec /opt/bin/python3 /opt/etc/rustdesk/manage.py stop;;
    *) exec /opt/bin/python3 /opt/etc/rustdesk/manage.py "$@";;
esac
'''


def atomic_copy(source,target,mode=None):
    staged = target.with_name(target.name+'.upgrade')
    shutil.copy2(source,staged)
    if mode is not None: staged.chmod(mode)
    with open(staged,'rb') as stream: os.fsync(stream.fileno())
    os.replace(staged,target)


def snapshot():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    root = UPDATE_ROOT/('snapshot-'+stamp)
    root.mkdir(mode=0o700)
    files = root/'files'; files.mkdir(mode=0o700)
    for name in recover.TARGETS:
        source = Path(name)
        target = files/name.lstrip('/')
        if source.is_symlink(): raise RuntimeError('Ссылка в установленном пакете: '+name)
        target.parent.mkdir(parents=True,exist_ok=True)
        if source.is_dir(): shutil.copytree(source,target,symlinks=True)
        else: shutil.copy2(source,target)
    manifest = root/'sha256.json'
    atomic_json(manifest,recover.inventory(files))
    recover.sync()
    return dict(snapshot=str(root),manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())


def upgrade(payload,binaries):
    import fcntl
    from install import system_preflight
    system_preflight()
    with open('/opt/var/run/rustdesk-control.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if recover.PENDING.exists(): raise RuntimeError('Есть незавершённое обновление: запустите S90rustdesk start для восстановления')
        old = json.loads(MARKER.read_text())
        if version_tuple('v'+old['version']) >= version_tuple('v'+VERSION):
            print('Эта версия уже установлена. Изменений нет.'); return
        if shutil.disk_usage('/opt').free < 256*1024*1024:
            raise RuntimeError('Для обновления и отката нужно не менее 256 МиБ свободного места')
        before = identity()
        config_before = CONFIG.read_bytes()
        UPDATE_ROOT.mkdir(mode=0o700,parents=True,exist_ok=True); UPDATE_ROOT.chmod(0o700)
        with tempfile.TemporaryDirectory(prefix='keendesk-binaries-',dir='/opt/var/tmp') as directory:
            stage = Path(directory)
            for name,data in binaries.items():
                p = stage/name; p.write_bytes(data); p.chmod(0o700)
                if UPSTREAM_VERSION not in run([p,'--version']).stdout: raise RuntimeError('Неверная версия '+name)
            # Use old manager for graceful stop. No mutations until download/preflight passed.
            import importlib.util
            spec = importlib.util.spec_from_file_location('previous_manager',CONF/'manage.py')
            previous = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(previous)
            previous.stop()
            record = None
            try:
                record = snapshot()
                record.update(from_version=old['version'],to_version=VERSION,identity=before)
                recover.validate_snapshot(record)
                atomic_copy(payload/'recover.py',UPDATE_ROOT/'recover.py',0o600)
                # Recovery guard goes in BEFORE the transaction becomes pending.
                guard = stage/'S90rustdesk'; guard.write_bytes(boot_guard()); guard.chmod(0o755)
                atomic_copy(guard,INIT,0o755)
                recover.write_json(recover.PENDING,record)
                for name in FILES:
                    if name in ('install.py','S90rustdesk','90-rustdesk.sh','rustdeskctl'): continue
                    atomic_copy(payload/name,CONF/name,0o600)
                for name in ('hbbs','hbbr'): atomic_copy(stage/name,Path('/opt/sbin')/name,0o755)
                for name,target in [('90-rustdesk.sh',Path('/opt/etc/ndm/netfilter.d/90-rustdesk.sh')),('rustdeskctl',Path('/opt/bin/rustdeskctl'))]:
                    atomic_copy(payload/name,target,0o755)
                atomic_json(MARKER,dict(owner=OWNER,version=VERSION,upstream=UPSTREAM_VERSION,archive_sha256=UPSTREAM_SHA256))
                if CONFIG.read_bytes() != config_before or identity() != before:
                    raise RuntimeError('Ключи или конфигурация изменились во время обновления')
                run(['/opt/bin/python3',CONF/'firewall.py'],timeout=40)
                # The transaction already holds the control lock; internal operations are imports.
                import manage
                manage.start()
                from health import required
                required((DATA/'id_ed25519.pub').read_text().strip())
                time.sleep(3)
                required((DATA/'id_ed25519.pub').read_text().strip())
                if not manage.status(False) or identity() != before: raise RuntimeError('Проверка новой службы не пройдена')
                recover.write_json(UPDATE_ROOT/'last-update.json',record)
                recover.PENDING.unlink(); recover.sync()
                print('KeenDesk '+VERSION+' установлена; TCP, UDP и relay проверены, ключи сохранены.')
                print('Снимок отката: '+record['snapshot'])
            except BaseException:
                if record is not None:
                    # Also handles exceptions before pending.json was written.
                    recover.restore(record)
                run(['/opt/bin/python3',CONF/'firewall.py'],check=False,timeout=40)
                # Avoid deadlock with an older manager taking rustdesk-control.lock.
                fcntl.flock(lock,fcntl.LOCK_UN)
                restarted = run(['/opt/bin/python3',CONF/'manage.py','start'],check=False,timeout=40)
                if restarted.returncode: print('Старая версия восстановлена, но запуск требует диагностики.',file=sys.stderr)
                raise


def rollback():
    record = json.loads((UPDATE_ROOT/'last-update.json').read_text())
    if json.loads(MARKER.read_text())['version'] != record['to_version']:
        raise RuntimeError('Откат уже выполнен или версия не соответствует снимку')
    if identity() != record['identity']: raise RuntimeError('Идентичность сервера изменилась; автоматический откат отменён')
    recover.validate_snapshot(record)
    import manage
    manage.stop()
    manage.backup()  # Keep all registrations/configuration added since the update.
    recover.write_json(recover.PENDING,dict(record,reason='Ручной rollback'))
    recover.restore(record)
    run(['/opt/bin/python3',CONF/'firewall.py'],timeout=40)
    # Caller execs the restored manager after releasing its lock.
