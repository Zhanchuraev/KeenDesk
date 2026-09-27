"""Read-only host inspection plus short native network probes."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from common import (VERSION, CONF, DATA, CONFIG, MARKER, CRASH, PID, STATE,
                    load_config, process_matches, run)
import health


def inspect():
    checks = []
    def check(name, fn, warning=False):
        try:
            detail = fn()
            checks.append(dict(name=name,status='ok',detail=str(detail or 'OK')))
        except Exception as exc:
            checks.append(dict(name=name,status='warn' if warning else 'fail',detail=str(exc)[:700]))
    def require(test, message):
        if not test: raise RuntimeError(message)
    cfg = load_config()
    def processes():
        require(process_matches(int(PID.read_text()),CONF/'supervisor.py'),'Supervisor не работает')
        state = json.loads(STATE.read_text())
        require(set(state) == {'hbbs','hbbr'},'Одна из служб не работает')
        for name,pid in state.items():
            require(process_matches(pid,'/opt/sbin/'+name),'Не работает '+name)
            uid = next(x.split()[1:] for x in Path('/proc',str(pid),'status').read_text().splitlines() if x.startswith('Uid:'))
            require(all(int(x) == cfg['uid'] for x in uid),'Неверный UID '+name)
        return 'Supervisor, hbbs и hbbr; серверные процессы не root'
    def crash():
        if CRASH.exists():
            value = json.loads(CRASH.read_text())
            require(not value['halted'],'Перезапуски заблокированы после повторных падений; logs, затем restart')
            return str(len(value['events']))+' падений в сохранённом счётчике'
        return 'Блокировки нет'
    def identity():
        import base64
        for name in ('id_ed25519','id_ed25519.pub'):
            p = DATA/name
            require(not p.is_symlink() and p.is_file(),'Нет обычного файла '+name)
            require(stat.S_IMODE(p.stat().st_mode) == 0o600,'Ожидаются права 600: '+name)
            require(p.stat().st_uid == cfg['uid'],'Неверный владелец '+name)
        require(len(base64.b64decode((DATA/'id_ed25519.pub').read_text().strip(),validate=True)) == 32,'Неверный публичный ключ')
        return 'Ключи на месте, права 600, владелец — UID службы'
    def database():
        db = DATA/'db_v2.sqlite3'
        require(db.is_file(),'Нет db_v2.sqlite3')
        with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True,timeout=2) as conn:
            require(conn.execute('PRAGMA quick_check').fetchone()[0] == 'ok','SQLite quick_check failed')
        return 'SQLite quick_check: ok (только чтение)'
    def firewall():
        from firewall import binaries, rules, input_rules, direct_rules
        for binary,v6 in binaries():
            require(rules(binary,'filter','RDE_INPUT') == input_rules(cfg,v6),'Отличаются правила RDE_INPUT: '+binary)
            for table,parent,chain in [('filter','INPUT','RDE_INPUT'),('mangle','OUTPUT','RDE_OUTPUT'),('nat','OUTPUT','RDE_NAT')]:
                rows = rules(binary,table,parent)
                relevant = [x for x in rows if x[-2:] == ['-j',chain]]
                require(len(relevant) == (2 if table == 'filter' else 1),'Нет нужных переходов '+chain)
                require(all(x in rows[:3 if table == 'filter' else 1] for x in relevant),'Переход в '+chain+' не в начале')
                if table != 'filter':
                    require(relevant[0][:4] == ['-m','owner','--uid-owner',str(cfg['uid'])],'Неверный UID в firewall')
                    current = rules(binary,table,chain)
                    normalized = [[{'--set-xmark':'--set-mark','0xffffa00/0xffffffff':'0xffffa00','0x3e':'62'}.get(x,x) for x in row] for row in current]
                    require(normalized == (direct_rules(cfg,v6) if table == 'mangle' else [['-j','ACCEPT']]),'Неверные правила '+chain)
        return 'IPv4/IPv6: собственные ACL и исключения OUTPUT соответствуют конфигурации'
    def routes():
        addresses = run(['ip','-o','-4','addr','show']).stdout
        names = {x.split()[1].split('@')[0] for x in addresses.splitlines() if len(x.split()) > 3}
        for interface in cfg['interfaces']:
            require(any(x.startswith(interface[:-1]) if interface.endswith('+') else x == interface for x in names),'Нет IPv4 на интерфейсе '+interface)
        if cfg['direct'] == 'xkeen':
            require(any('fwmark 0xffffa00' in x and 'lookup main' in x for x in run(['ip','rule','show']).stdout.splitlines()),'Нет ожидаемого правила XKeen')
        return 'Интерфейсы доступны; режим маршрутизации '+cfg['direct']
    def disk():
        free = shutil.disk_usage('/opt').free
        require(free >= 128*1024*1024,'Свободно менее 128 МиБ; обновление может не поместиться')
        return str(free//(1024*1024))+' МиБ свободно'
    check('processes',processes)
    check('restart_budget',crash)
    check('identity',identity)
    check('database',database)
    check('firewall',firewall)
    check('interfaces_and_xkeen',routes,warning=True)
    check('disk',disk,warning=True)
    check('id_tcp',health.id_probe)
    check('id_udp',health.udp_probe)
    check('relay',lambda: health.relay_probe((DATA/'id_ed25519.pub').read_text().strip()))
    return dict(version=VERSION,ok=not any(x['status']=='fail' for x in checks),checks=checks,
                scope='Локальные проверки. Доступ извне, рабочий стол и передача файлов GUI-клиентов проверяются отдельно.')


def display(report):
    for item in report['checks']:
        print(item['status'].upper()+' '+item['name']+': '+item['detail'])
    print(report['scope'])
