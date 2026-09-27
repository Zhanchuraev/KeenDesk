#!/opt/bin/python3
"""Bounded logs, child restart, serialized NDM firewall reconciliation."""
import fcntl
import logging
import logging.handlers
import os
import selectors
import signal
import subprocess
import time
from common import CONF, DATA, LOGS, RUN, PID, STATE, PENDING, atomic_json, load_config
from restarts import Budget, WINDOW


def main():
    os.umask(0o077)
    RUN.mkdir(parents=True, exist_ok=True)
    lock = open(RUN / 'rustdesk.lock', 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    cfg = load_config()
    budget = Budget()
    PID.write_text(str(os.getpid()))
    LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    def logger(name):
        log = logging.getLogger(name)
        log.setLevel(logging.INFO)
        handler = logging.handlers.RotatingFileHandler(LOGS / (name + '.log'),
                    maxBytes=2*1024*1024, backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        log.addHandler(handler)
        return log
    audit = logger('supervisor')
    services = {'hbbs': ['/opt/sbin/hbbs','-p','21116','-r',cfg['address']+':21117','-k','-'],
                'hbbr': ['/opt/sbin/hbbr','-p','21117','-k','-']}
    children, next_start = {}, {}
    logs = {name: logger(name) for name in services}
    poller = selectors.DefaultSelector()
    stopping = False
    def stop_signal(*_):
        nonlocal stopping
        stopping = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop_signal)
    def demote():
        os.setgroups([])
        os.setgid(cfg['uid'])
        os.setuid(cfg['uid'])
    def save_state():
        atomic_json(STATE, {name: p.pid for name,p in children.items() if p.poll() is None})
    def drain(timeout):
        for key,_ in poller.select(timeout):
            data = os.read(key.fileobj.fileno(),8192)
            if data:
                logs[key.data].info(data.decode('utf-8','replace').rstrip())
            else:
                poller.unregister(key.fileobj)
                key.fileobj.close()
    def stop_children():
        for p in children.values():
            if p.poll() is None:
                p.terminate()
        deadline = time.monotonic()+8
        while any(p.poll() is None for p in children.values()) and time.monotonic()<deadline:
            drain(.1)
        for p in children.values():
            if p.poll() is None:
                p.kill()
            p.wait()
        drain(0)
        children.clear()
        save_state()
    next_firewall, firewall_ready = 0, False
    next_web, web_waiting = 0, False
    healthy_since = None
    audit.info('Started; uid=%s; relay=%s:21117',cfg['uid'],cfg['address'])
    save_state()
    try:
        while not stopping:
            if time.monotonic() >= next_firewall or (PENDING.exists() and firewall_ready):
                PENDING.unlink(missing_ok=True)
                command = subprocess.Popen(['/opt/bin/python3',str(CONF/'firewall.py')],
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    output = command.communicate(timeout=20)[0]
                    success = command.returncode == 0
                except subprocess.TimeoutExpired:
                    os.killpg(command.pid,signal.SIGKILL)
                    output = command.communicate()[0]
                    success = False
                if success:
                    if not firewall_ready:
                        audit.info('Firewall ready')
                    firewall_ready = True
                    next_firewall = time.monotonic()+30
                else:
                    audit.warning('Firewall not ready; servers stopped: %s',output.decode('utf-8','replace')[-1000:])
                    stop_children()
                    firewall_ready = False
                    next_firewall = time.monotonic()+5
            if not firewall_ready:
                healthy_since = None
                time.sleep(.5)
                continue
            if time.monotonic() >= next_web:
                next_web = time.monotonic()+30
                try:
                    from web import reconcile_web
                    reconcile_web()
                    if web_waiting: audit.info('Dashboard startup condition cleared')
                    web_waiting = False
                except Exception as exc:
                    if not web_waiting: audit.warning('Dashboard waiting; retry every 30s: %s',exc)
                    web_waiting = True
            if budget.halted:
                if children:
                    audit.error('Restart budget exhausted; services halted. Inspect logs, then rustdeskctl restart.')
                    stop_children()
                drain(.5)
                continue
            for name,args in services.items():
                p = children.get(name)
                if p is not None and p.poll() is None:
                    continue
                if p is not None:
                    delay = budget.failure(name,p.returncode)
                    healthy_since = None
                    audit.warning('%s exited %s; delay=%ss; halted=%s',name,p.returncode,delay,budget.halted)
                    del children[name]
                    next_start[name] = time.monotonic()+delay
                    save_state()
                    if budget.halted: break
                if time.monotonic() < next_start.get(name,0):
                    continue
                if name == 'hbbr' and not (DATA/'id_ed25519.pub').exists():
                    continue
                env = dict(os.environ,RUST_LOG='info',HOME=str(DATA),XDG_CONFIG_HOME=str(DATA/'.config'))
                for var in ('http_proxy','https_proxy','all_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'):
                    env.pop(var,None)
                try:
                    p = subprocess.Popen(args,cwd=DATA,env=env,stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=demote,start_new_session=True)
                except OSError as exc:
                    next_start[name] = time.monotonic()+budget.failure(name,str(exc))
                    healthy_since = None
                    audit.error('%s start failed: %s; halted=%s',name,exc,budget.halted)
                    if budget.halted: break
                    continue
                children[name] = p
                poller.register(p.stdout,selectors.EVENT_READ,name)
                audit.info('%s started, PID=%s',name,p.pid)
                save_state()
            if len(children) == 2 and all(p.poll() is None for p in children.values()):
                if healthy_since is None: healthy_since = time.monotonic()
                if time.monotonic()-healthy_since >= WINDOW: budget.stable()
            else: healthy_since = None
            drain(.5)
    finally:
        stop_children()
        STATE.unlink(missing_ok=True)
        PID.unlink(missing_ok=True)
        audit.info('Stopped')
        lock.close()


if __name__ == '__main__':
    main()
