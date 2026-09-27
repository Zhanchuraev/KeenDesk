#!/opt/bin/python3
"""Fresh install or explicit transactional upgrade; retain existing identity."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from common import (VERSION, UPSTREAM_VERSION, UPSTREAM_URL, UPSTREAM_SHA256,
    CONF, DATA, LOGS, RUN, INIT, HOOK, MARKER, CONFIG, OWNER,
    atomic_json, assert_managed, load_config, client_settings, run, validate)

PAYLOAD = Path(__file__).resolve().parent


def system_preflight():
    if os.geteuid() != 0:
        raise RuntimeError('Нужен root в SSH-сессии Entware.')
    if platform.system() != 'Linux' or platform.machine() not in ('aarch64','arm64'):
        raise RuntimeError('Эта версия поддерживает только Linux ARM64/aarch64; MIPS/ARMv7 не поддерживаются.')
    for name in ('/opt/bin/opkg','/opt/bin/sh','/opt/bin/python3','/bin/ndmc'):
        if not Path(name).is_file():
            raise RuntimeError('Не найден '+name+'. Требуется Keenetic с установленным Entware.')
    for cmd in ('iptables','ip'):
        if not shutil.which(cmd): raise RuntimeError('Не найдена команда '+cmd)
    if Path('/proc/net/if_inet6').exists() and not shutil.which('ip6tables'):
        raise RuntimeError('Нужен ip6tables для закрытия IPv6-портов сервера.')


def fresh_preflight():
    targets = [CONF,DATA,LOGS,INIT,HOOK,Path('/opt/sbin/hbbs'),Path('/opt/sbin/hbbr'),Path('/opt/bin/rustdeskctl')]
    conflicts = [str(x) for x in targets if x.exists() or x.is_symlink()]
    if conflicts:
        raise RuntimeError('Уже есть другая установка RustDesk; ничего не перезаписано: '+', '.join(conflicts))
    if shutil.disk_usage('/opt').free < 128*1024*1024:
        raise RuntimeError('Нужно не менее 128 МиБ свободного места на /opt.')
    for binary in ('iptables','ip6tables'):
        if shutil.which(binary):
            for table,chain in [('filter','RDE_INPUT'),('mangle','RDE_OUTPUT'),('nat','RDE_NAT')]:
                if run([binary,'-t',table,'-S',chain],check=False).returncode == 0:
                    raise RuntimeError('Уже есть чужая/оставшаяся цепочка '+chain+'; требуется ручная проверка.')
    for port,kind in [(p,socket.SOCK_STREAM) for p in range(21115,21120)]+[(21116,socket.SOCK_DGRAM)]:
        with socket.socket(socket.AF_INET,kind) as s:
            if kind == socket.SOCK_STREAM:
                # Ignore TIME_WAIT after a clean uninstall, but not live listeners.
                s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: s.bind(('0.0.0.0',port))
            except OSError as exc: raise RuntimeError('Порт занят: '+str(port)) from exc


def choose_uid():
    import grp
    import pwd
    used = {x.pw_uid for x in pwd.getpwall()} | {x.gr_gid for x in grp.getgrall()}
    for status in Path('/proc').glob('[0-9]*/status'):
        try:
            for line in status.read_text().splitlines():
                if line.startswith(('Uid:','Gid:')): used.update(map(int,line.split()[1:]))
        except (FileNotFoundError,PermissionError,ProcessLookupError): pass
    for uid in range(21116,21216):
        if uid not in used: return uid
    raise RuntimeError('Не найден свободный UID/GID 21116..21215.')


def detect_zerotier():
    candidates = []
    for line in run(['ip','-o','-4','addr','show']).stdout.splitlines():
        row = line.split()
        if len(row)>3 and row[1].startswith('zt') and row[2]=='inet':
            candidates.append((row[1].split('@')[0],row[3].split('/')[0]))
    return candidates


def ask(label):
    try:
        with open('/dev/tty','r+') as tty:
            tty.write(label+' '); tty.flush()
            return tty.readline().strip()
    except OSError as exc:
        raise RuntimeError('Нет терминала: задайте RD_ADDRESS и RD_INTERFACES.') from exc


def configuration():
    address = os.environ.get('RD_ADDRESS','').strip()
    interfaces = os.environ.get('RD_INTERFACES','').split()
    networks = os.environ.get('RD_NETWORKS','').split()
    candidates = detect_zerotier()
    if not address and not interfaces and len(candidates)==1:
        interface,address = candidates[0]
        interfaces = [interface]
        print('Обнаружен ZeroTier: '+interface+' / '+address)
    if not address:
        address = ask('Адрес роутера, доступный обоим клиентам RustDesk (IPv4/DNS):')
    if not interfaces:
        interfaces = ask('Linux-интерфейсы, через которые разрешён доступ (например zt0 или ppp+):').split()
    if any(x.endswith('+') for x in interfaces) and not networks:
        networks = ask('Подсеть адресов VPN-клиентов в CIDR (например 10.77.0.0/24):').split()
    direct = os.environ.get('RD_XKEEN','auto')
    if direct not in ('auto','off','xkeen'):
        raise RuntimeError('RD_XKEEN: auto, off или xkeen.')
    if direct == 'auto':
        xkeen = Path('/opt/etc/init.d/S05xkeen').exists()
        marks = run(['ip','rule','show']).stdout
        if xkeen and 'fwmark 0xffffa00 lookup main' not in marks:
            raise RuntimeError('Незнакомая схема XKeen. Проверьте маршрутизацию; RD_XKEEN=off отключает специальный обход.')
        direct = 'xkeen' if xkeen else 'off'
    return validate(dict(address=address,interfaces=interfaces,networks=networks,uid=choose_uid(),direct=direct))


def verified_archive(raw):
    if hashlib.sha256(raw).hexdigest() != UPSTREAM_SHA256:
        raise RuntimeError('SHA-256 официального архива не совпал. Запуск запрещён.')
    binaries = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in ('hbbs','hbbr'):
            matches = [info for info in archive.infolist() if info.filename == 'arm64v8/'+name]
            if len(matches)!=1 or not 10000 <= matches[0].file_size <= 40*1024*1024:
                raise RuntimeError('Неожиданный состав архива: '+name)
            data = archive.read(matches[0])
            if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=183:
                raise RuntimeError('Бинарник не является ELF64 AArch64: '+name)
            offset = struct.unpack_from('<Q',data,32)[0]
            size,count = struct.unpack_from('<HH',data,54)
            if size<56 or any(struct.unpack_from('<I',data,offset+i*size)[0]==3 for i in range(count)):
                raise RuntimeError('Ожидался статический ELF без PT_INTERP: '+name)
            binaries[name] = data
    return binaries


def download_binaries():
    print('Скачивание официального RustDesk Server OSS '+UPSTREAM_VERSION+'...')
    with urllib.request.urlopen(UPSTREAM_URL,timeout=60) as response:
        raw = response.read(16*1024*1024+1)
    if len(raw)>16*1024*1024: raise RuntimeError('Архив неожиданно большой.')
    return verified_archive(raw)


def deploy(cfg,binaries):
    created = []
    with tempfile.TemporaryDirectory(prefix='rustdesk-stage-',dir='/opt/var/tmp') as tempdir:
        stage = Path(tempdir)
        for name,data in binaries.items():
            target = stage/name
            target.write_bytes(data); target.chmod(0o700)
            output = run([target,'--version']).stdout.strip()
            if UPSTREAM_VERSION not in output: raise RuntimeError('Неожиданная версия '+name)
        try:
            for path in (CONF,DATA,LOGS):
                path.mkdir(mode=0o700,parents=True); created.append(path)
            os.chown(DATA,cfg['uid'],cfg['uid'])
            from update import FILES, boot_guard
            for name in FILES:
                if name in ('install.py','S90rustdesk','90-rustdesk.sh','rustdeskctl'): continue
                shutil.copyfile(PAYLOAD/name,CONF/name)
                (CONF/name).chmod(0o600)
            atomic_json(CONFIG,cfg)
            atomic_json(MARKER,dict(owner=OWNER,version=VERSION,upstream=UPSTREAM_VERSION,archive_sha256=UPSTREAM_SHA256))
            for name in ('hbbs','hbbr'):
                target = Path('/opt/sbin')/name
                shutil.copyfile(stage/name,target); target.chmod(0o755); created.append(target)
            for name,target in [('S90rustdesk',INIT),('90-rustdesk.sh',HOOK),('rustdeskctl',Path('/opt/bin/rustdeskctl'))]:
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(PAYLOAD/name,target); target.chmod(0o755); created.append(target)
            # Install firewall before either binary starts listening.
            run(['/opt/bin/python3',CONF/'firewall.py'],timeout=40)
            print(run(['/opt/bin/python3',CONF/'manage.py','start'],timeout=35).stdout)
            if run(['/opt/bin/python3',CONF/'manage.py','status'],check=False).returncode:
                raise RuntimeError('Службы не готовы; установка отменяется.')
            private = DATA/'id_ed25519'
            if not private.exists(): raise RuntimeError('Сервер не создал ключ.')
            private.chmod(0o600)
            (DATA/'id_ed25519.pub').chmod(0o600)
            # hbbs reserves loopback:21115 for its text administration protocol.
            # The main TCP listener accepts TestNatRequest on loopback too.
            with socket.create_connection(('127.0.0.1',21116),timeout=5) as probe:
                probe.sendall(b'\x0c\xa2\x01\x00')
                def exact(length):
                    result = b''
                    while len(result) < length:
                        chunk = probe.recv(length-len(result))
                        if not chunk: raise RuntimeError('ID-служба закрыла проверочное соединение.')
                        result += chunk
                    return result
                first = exact(1)
                header = first+exact(first[0] & 3)
                length = int.from_bytes(header,'little') >> 2
                if not 3 <= length <= 128 or not exact(length).startswith(b'\xaa\x01'):
                    raise RuntimeError('ID-служба не вернула TestNatResponse.')
        except Exception:
            if MARKER.exists():
                stopped = run(['/opt/bin/python3',CONF/'manage.py','stop'],check=False,timeout=45)
                if stopped.returncode:
                    raise RuntimeError('Не удалось остановить частичную установку; файлы сохранены для диагностики.')
                # Do not discard a generated identity on failed installation.
                from importlib.util import spec_from_file_location,module_from_spec
                spec=spec_from_file_location('installed_manager',CONF/'manage.py')
                manager=module_from_spec(spec); spec.loader.exec_module(manager)
                manager.backup()
                removed = run(['/opt/bin/python3',CONF/'firewall.py','remove'],check=False,timeout=40)
                if removed.returncode:
                    raise RuntimeError('Частичная установка остановлена; очистка firewall требует проверки, файлы сохранены.')
            for path in reversed(created):
                if path.is_dir(): shutil.rmtree(path)
                else: path.unlink(missing_ok=True)
            raise


def main():
    import fcntl
    os.umask(0o077)
    parser=argparse.ArgumentParser(description='Установщик RustDesk Server для Keenetic ARM64 + Entware')
    parser.add_argument('--check',action='store_true',help='Проверить среду и план; сервер не устанавливать')
    parser.add_argument('--upgrade',action='store_true',help='Обновить управляемую установку, сохранив ключи и снимок отката')
    args=parser.parse_args()
    system_preflight()
    RUN.mkdir(parents=True,exist_ok=True)
    lock=open(RUN/'rustdesk-install.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if MARKER.exists():
        assert_managed()
        if args.upgrade and not args.check:
            from update import upgrade
            Path('/opt/var/tmp').mkdir(parents=True,exist_ok=True)
            upgrade(PAYLOAD,download_binaries())
            return
        print('RustDesk уже установлен. Ключи и конфигурация сохранены.')
        print(client_settings(load_config()))
        return
    fresh_preflight()
    cfg=configuration()
    print('План установки: '+json.dumps(cfg,ensure_ascii=False))
    if args.check:
        print('Проверка завершена; службы и firewall не изменены.'); return
    Path('/opt/var/tmp').mkdir(parents=True,exist_ok=True)
    binaries=download_binaries()
    deploy(cfg,binaries)
    print(client_settings(cfg))
    print('Управление: rustdeskctl doctor | client | logs | restart | backup | update | web')
    print('Удаление с резервной копией: rustdeskctl uninstall --yes')


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('Ошибка установки: '+str(exc),file=sys.stderr)
        sys.exit(1)
