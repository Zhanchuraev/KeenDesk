#!/opt/bin/python3
"""Small authenticated, read-only dashboard. No shell or arbitrary file API."""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
from common import (VERSION, CONF, DATA, LOGS, WEB_CONFIG, WEB_PID, CRASH,
                    atomic_json, load_config, process_matches, run)

PORT = 18082
CHAIN = 'RDW_INPUT'


def config():
    if not WEB_CONFIG.exists(): return {'enabled':False}
    return json.loads(WEB_CONFIG.read_text())


def validate_listen(address,interface,cfg):
    if address == '127.0.0.1': return None
    ip = ipaddress.IPv4Address(address)
    private = any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
    if not private or not interface or not re.fullmatch(r'(?:zt|tun|tap|ppp)[A-Za-z0-9_.:-]{1,12}',interface):
        raise ValueError('Панель разрешена на 127.0.0.1 либо частном IPv4 VPN-интерфейса zt/tun/tap/ppp')
    if not any(interface.startswith(x[:-1]) if x.endswith('+') else interface == x for x in cfg['interfaces']):
        raise ValueError('Этот VPN-интерфейс не разрешён в конфигурации RustDesk')
    rows = run(['ip','-o','-4','addr','show','dev',interface]).stdout.splitlines()
    if not any(len(x.split()) > 3 and x.split()[3].split('/')[0] == address for x in rows):
        raise ValueError('Адрес не назначен указанному VPN-интерфейсу')
    return interface


def remove_web_rules():
    from firewall import binaries,ipt,rules
    for binary,_ in binaries():
        if ipt(binary,'filter','-S',CHAIN,check=False).returncode: continue
        for row in rules(binary,'filter','INPUT'):
            if row[-2:] == ['-j',CHAIN]: ipt(binary,'filter','-D','INPUT',*row)
        ipt(binary,'filter','-F',CHAIN); ipt(binary,'filter','-X',CHAIN)


def apply_web_rules():
    from firewall import binaries,ipt,rules,ensure_chain,jump_first
    value = config()
    if not value.get('enabled'):
        remove_web_rules(); return
    cfg = load_config()
    for binary,v6 in binaries():
        ensure_chain(binary,'filter',CHAIN)
        drop = ['-j','DROP']
        if ipt(binary,'filter','-C',CHAIN,*drop,check=False).returncode:
            ipt(binary,'filter','-A',CHAIN,*drop)
        desired = [['-i','lo','-j','ACCEPT']]
        if not v6 and value.get('interface'):
            # Intersect with current service policy on every reconcile.
            allowed = any(value['interface'].startswith(x[:-1]) if x.endswith('+') else value['interface']==x for x in cfg['interfaces'])
            if allowed:
                for net in cfg['networks'] or [None]:
                    source = ['-s',net] if net and net != '0.0.0.0/0' else []
                    desired.append([*source,'-i',value['interface'],'-j','ACCEPT'])
        desired.append(drop)
        for row in rules(binary,'filter',CHAIN):
            if row not in desired: ipt(binary,'filter','-D',CHAIN,*row)
        for row in reversed(desired[:-1]):
            if ipt(binary,'filter','-C',CHAIN,*row,check=False).returncode:
                ipt(binary,'filter','-I',CHAIN,'1',*row)
        jump_first(binary,'filter','INPUT',['-p','tcp','-m','tcp','--dport',str(PORT),'-j',CHAIN])


def web_alive():
    try:
        pid = int(WEB_PID.read_text())
        return pid if process_matches(pid,CONF/'web.py') else None
    except (OSError,ValueError): return None


def stop_web():
    pid = web_alive()
    if pid:
        os.kill(pid,signal.SIGTERM)
        for _ in range(50):
            if not process_matches(pid,CONF/'web.py'): break
            time.sleep(.1)
        else: raise RuntimeError('Веб-панель не завершилась')
    WEB_PID.unlink(missing_ok=True)


def start_web():
    if config().get('enabled') and not web_alive():
        with open(LOGS/'web-startup.log','ab') as log:
            if log.tell() > 1024*1024: log.truncate(0)
            process = subprocess.Popen(['/opt/bin/python3',str(CONF/'web.py')],stdin=subprocess.DEVNULL,
                                       stdout=log,stderr=log,start_new_session=True,close_fds=True)
        # Imports/startup on an embedded CPU can exceed 500 ms. Retain the child
        # handle until readiness so timeout cleanup also catches an unrecorded child.
        for _ in range(100):
            if web_alive() == process.pid: return
            if process.poll() is not None: break
            time.sleep(.1)
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
        WEB_PID.unlink(missing_ok=True)
        raise RuntimeError('Веб-панель не достигла готовности за 10 секунд; см. web-startup.log')


def reconcile_web():
    """Retry optional dashboard after VPN appears, without racing management."""
    import fcntl
    from common import RUN
    with open(RUN/'rustdesk-control.lock','a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return
        value = config()
        if not value.get('enabled') or web_alive(): return
        # Missing VPN is checked before spawning; no rapid child restart loop.
        validate_listen(value['listen'],value.get('interface'),load_config())
        start_web()


def configure_web(address,interface,disable):
    old = config()
    if address is None and not disable and old.get('enabled'):
        print('Веб-панель: http://'+old['listen']+':'+str(PORT))
        print('Ключ входа: rustdeskctl web-token'); return
    address = address or '127.0.0.1'
    iface = validate_listen(address,interface,load_config()) if not disable else None
    new = dict(enabled=not disable,listen=address,interface=iface,token=old.get('token') or secrets.token_urlsafe(32))
    stop_web()
    try:
        atomic_json(WEB_CONFIG,new)
        apply_web_rules()
        if not disable:
            start_web(); time.sleep(.5)
            if not web_alive(): raise RuntimeError('Панель не запустилась; проверьте web-startup.log и занятость порта 18082')
    except Exception:
        stop_web(); atomic_json(WEB_CONFIG,old); apply_web_rules(); start_web()
        raise
    print('Веб-панель выключена.' if disable else 'Веб-панель: http://'+address+':'+str(PORT)+'\nКлюч входа: rustdeskctl web-token')


def dashboard():
    import manage
    cfg = load_config()
    crash = json.loads(CRASH.read_text()) if CRASH.exists() else {'events':[], 'halted':False}
    return dict(version=VERSION,running=manage.status(False),address=cfg['address'],
                id=cfg['address']+':21116',relay=cfg['address']+':21117',
                key=(DATA/'id_ed25519.pub').read_text().strip(),direct=cfg['direct'],
                interfaces=cfg['interfaces'],crashes=len(crash['events']),halted=crash['halted'])


class Handler(BaseHTTPRequestHandler):
    server_version = 'KeenDesk'
    def setup(self):
        super().setup(); self.connection.settimeout(5)
    def log_message(self,*args): pass  # Never log Authorization or request paths.
    def reply(self,status,body,mime='application/json; charset=utf-8'):
        if isinstance(body,dict): body = json.dumps(body,ensure_ascii=False).encode()
        elif isinstance(body,str): body = body.encode()
        self.send_response(status)
        for name,value in [('Content-Type',mime),('Content-Length',str(len(body))),('Cache-Control','no-store'),
                           ('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),
                           ('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")]:
            self.send_header(name,value)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        host = self.headers.get('Host','')
        if host != self.server.allowed_host:
            self.reply(403,{'error':'Недопустимый Host'}); return
        if self.headers.get('Origin') not in (None,'http://'+host):
            self.reply(403,{'error':'Недопустимый Origin'}); return
        if self.path == '/':
            self.reply(200,(CONF/'index.html').read_bytes(),'text/html; charset=utf-8'); return
        if self.path not in ('/api/status','/api/doctor','/api/logs'):
            self.reply(404,{'error':'Не найдено'}); return
        supplied = self.headers.get('Authorization','')
        if not hmac.compare_digest(supplied,'Bearer '+self.server.token):
            self.reply(401,{'error':'Введите ключ веб-панели'}); return
        try:
            if self.path == '/api/status': result = dashboard()
            elif self.path == '/api/doctor':
                if time.monotonic()-self.server.last_doctor > 30:
                    import doctor
                    self.server.doctor_result = doctor.inspect()
                    self.server.last_doctor = time.monotonic()
                result = self.server.doctor_result
            else:
                result = {}
                for name in ('supervisor.log','hbbs.log','hbbr.log'):
                    path = LOGS/name
                    if path.exists():
                        with open(path,'rb') as stream:
                            stream.seek(max(0,path.stat().st_size-12000))
                            result[name] = '\n'.join(stream.read(12000).decode('utf-8','replace').splitlines()[-30:])
            self.reply(200,result)
        except Exception as exc: self.reply(503,{'error':str(exc)[:300]})


def main():
    import fcntl
    os.umask(0o077)
    with open('/opt/var/run/keendesk-web.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        value = config()
        if not value.get('enabled'): return
        validate_listen(value['listen'],value.get('interface'),load_config())
        with HTTPServer((value['listen'],PORT),Handler) as server:
            server.allowed_host = value['listen']+':'+str(PORT)
            server.token = value['token']
            server.last_doctor = -100
            WEB_PID.write_text(str(os.getpid()))
            try: server.serve_forever()
            finally: WEB_PID.unlink(missing_ok=True)


if __name__ == '__main__': main()
