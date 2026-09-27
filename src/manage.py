#!/opt/bin/python3
"""Management commands do not modify any RustDesk GUI client."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from common import (CONF, DATA, LOGS, RUN, INIT, HOOK, MARKER, CONFIG, PID,
    STATE, PENDING, assert_managed, atomic_json, client_settings, load_config,
    process_matches, run, validate)


def alive():
    try:
        pid = int(PID.read_text())
        return pid if process_matches(pid,CONF/'supervisor.py') else None
    except (FileNotFoundError,ValueError):
        return None


def status(verbose=True):
    pid = alive()
    if not pid:
        if verbose: print('RustDesk остановлен.')
        return False
    try:
        state = json.loads(STATE.read_text())
        ready = set(state) == {'hbbs','hbbr'} and all(process_matches(v,'/opt/sbin/'+k) for k,v in state.items())
    except (OSError,ValueError):
        state, ready = {}, False
    if verbose:
        print('Supervisor PID='+str(pid))
        for name,child in state.items(): print(name+' PID='+str(child))
        print('Работает.' if ready else 'Ожидание сети/firewall; см. supervisor.log.')
    return ready


def start():
    if not alive():
        log = open(LOGS/'startup.log','ab')
        subprocess.Popen(['/opt/bin/python3',str(CONF/'supervisor.py')],stdin=subprocess.DEVNULL,
                         stdout=log,stderr=log,start_new_session=True,close_fds=True)
        log.close()
    for _ in range(20):
        if status(False):
            print('RustDesk запущен.')
            return
        time.sleep(1)
    if alive():
        print('Supervisor запущен; ожидает сеть/firewall. rustdeskctl status / logs')
    else:
        raise RuntimeError('Не удалось запустить supervisor; см. startup.log.')


def stop():
    pid = alive()
    if pid:
        os.kill(pid,signal.SIGTERM)
        for _ in range(35):
            if not process_matches(pid,CONF/'supervisor.py'):
                break
            time.sleep(1)
        else:
            raise RuntimeError('Supervisor не завершился; принудительное удаление отменено.')
    # A crashed supervisor can leave children; only touch recorded exact executables.
    if STATE.exists():
        for name,child in json.loads(STATE.read_text()).items():
            if name not in ('hbbs','hbbr'): raise RuntimeError('Неизвестный процесс в state.')
            if process_matches(child,'/opt/sbin/'+name):
                os.kill(child,signal.SIGTERM)
                for _ in range(50):
                    if not process_matches(child,'/opt/sbin/'+name): break
                    time.sleep(.1)
                else: raise RuntimeError('Оставшийся сервер не завершился: '+name)
        STATE.unlink(missing_ok=True)
    PID.unlink(missing_ok=True)
    print('RustDesk остановлен.')


def backup():
    root = Path('/opt/var/backups/rustdesk-entware')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    root.chmod(0o700)
    archive = root / ('backup-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.private.tar.gz')
    with tarfile.open(archive,'w:gz') as tar:
        for path in (CONF,DATA,LOGS,INIT,HOOK,Path('/opt/bin/rustdeskctl')):
            if path.exists(): tar.add(path,arcname=str(path).lstrip('/'))
    archive.chmod(0o600)
    print('Закрытая резервная копия: '+str(archive))
    return archive


def main():
    os.umask(0o077)
    if os.geteuid() != 0: raise RuntimeError('Запустите от root в Entware.')
    assert_managed()
    parser = argparse.ArgumentParser(description='RustDesk Server в Entware')
    parser.add_argument('command',choices=['start','stop','restart','status','check','reconfigure','client','logs','backup','configure','uninstall'])
    parser.add_argument('--address')
    parser.add_argument('--interfaces',help='Linux-интерфейсы через пробел, в кавычках')
    parser.add_argument('--networks',help='IPv4 CIDR через пробел; пустая строка снимает ограничение источника')
    parser.add_argument('--direct',choices=['off','xkeen'])
    parser.add_argument('--yes',action='store_true',help='Подтверждение удаления с резервной копией')
    args = parser.parse_args()
    if args.command in ('status','check'):
        return 0 if status() else 1
    if args.command == 'client':
        print(client_settings(load_config())); return 0
    if args.command == 'logs':
        for name in ('supervisor.log','hbbs.log','hbbr.log'):
            print('\n'+name)
            path = LOGS/name
            if path.exists(): print('\n'.join(path.read_text(errors='replace').splitlines()[-30:]))
        return 0
    lock = open(RUN/'rustdesk-control.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX)
    if args.command == 'start': start()
    elif args.command == 'stop': stop()
    elif args.command == 'restart': stop(); start()
    elif args.command == 'reconfigure': PENDING.touch(mode=0o600)
    elif args.command == 'backup':
        was_running = bool(alive())
        stop()
        try: backup()
        finally:
            if was_running: start()
    elif args.command == 'configure':
        cfg = load_config()
        before = dict(cfg)
        for arg,key in [(args.address,'address'),(args.direct,'direct')]:
            if arg is not None: cfg[key] = arg
        if args.interfaces is not None: cfg['interfaces'] = args.interfaces.split()
        if args.networks is not None: cfg['networks'] = args.networks.split()
        cfg = validate(cfg)
        if cfg == before:
            print(client_settings(cfg)); return 0
        stop()
        backup()
        try:
            atomic_json(CONFIG,cfg)
            run(['/opt/bin/python3',CONF/'firewall.py'])
            start()
        except Exception:
            atomic_json(CONFIG,before)
            run(['/opt/bin/python3',CONF/'firewall.py'],check=False)
            start()
            raise
        print(client_settings(cfg))
    elif args.command == 'uninstall':
        if not args.yes: raise RuntimeError('Для удаления выполните rustdeskctl uninstall --yes; будет сохранён архив с ключами.')
        stop()
        backup()
        run(['/opt/bin/python3',CONF/'firewall.py','remove'])
        for path in (HOOK,INIT,Path('/opt/sbin/hbbs'),Path('/opt/sbin/hbbr'),Path('/opt/bin/rustdeskctl')):
            path.unlink(missing_ok=True)
        for path in (CONF,DATA,LOGS):
            if path.is_symlink() or path.resolve() != path:
                raise RuntimeError('Неожиданная ссылка: '+str(path))
            shutil.rmtree(path)
        for path in (PID,STATE,PENDING,RUN/'rustdesk.lock'):
            path.unlink(missing_ok=True)
        print('RustDesk удалён. Зависимости Entware и закрытые резервные копии сохранены.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('Ошибка: '+str(exc),file=sys.stderr)
        sys.exit(1)
