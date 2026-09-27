"""Configuration and paths shared by the Entware installer and services."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

VERSION = '0.2.1'
UPSTREAM_VERSION = '1.1.16'
UPSTREAM_URL = ('https://github.com/rustdesk/rustdesk-server/releases/download/'
                + UPSTREAM_VERSION + '/rustdesk-server-linux-arm64v8.zip')
UPSTREAM_SHA256 = '6a4ae3c5ca257a4278ded72fd17eb2ca4eeb0356a5425e63a3e7fcb0ec6c155c'
CONF = Path('/opt/etc/rustdesk')
DATA = Path('/opt/var/lib/rustdesk')
LOGS = Path('/opt/var/log/rustdesk')
RUN = Path('/opt/var/run')
INIT = Path('/opt/etc/init.d/S90rustdesk')
HOOK = Path('/opt/etc/ndm/netfilter.d/90-rustdesk.sh')
MARKER = CONF / 'managed.json'
CONFIG = CONF / 'server.json'
PID = RUN / 'rustdesk.pid'
STATE = RUN / 'rustdesk-processes.json'
PENDING = RUN / 'rustdesk-firewall.pending'
CRASH = CONF / 'crash-state.json'
WEB_CONFIG = CONF / 'web.json'
WEB_PID = RUN / 'keendesk-web.pid'
UPDATE_ROOT = Path('/opt/var/lib/keendesk-update')
# Kept deliberately: v0.1.0 installations must remain recognizable after the rename.
OWNER = 'Zhanchuraev/rustdesk-entware'


def run(args, check=True, **kwargs):
    return subprocess.run([str(x) for x in args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=kwargs.pop('timeout', 20), **kwargs)


def atomic_json(path, obj):
    temp = path.with_name(path.name + '.new')
    with open(temp, 'w', encoding='utf-8') as f:
        os.chmod(temp, 0o600)
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def validate(cfg):
    address = str(cfg.get('address', '')).strip()
    if not address or len(address) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', address):
        raise ValueError('Адрес: IPv4 или DNS-имя без протокола, порта и пути.')
    try:
        ip = ipaddress.IPv4Address(address)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            raise ValueError('Нужен адрес, доступный клиентам, не localhost.')
    except ipaddress.AddressValueError:
        if re.fullmatch(r'[0-9.]+', address):
            raise ValueError('Некорректный IPv4-адрес.')
        if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x)
               for x in address.rstrip('.').split('.')):
            raise ValueError('Некорректное DNS-имя.')
    interfaces = cfg.get('interfaces', [])
    if not isinstance(interfaces, list) or not interfaces:
        raise ValueError('Укажите хотя бы один Linux-интерфейс доступа.')
    for interface in interfaces:
        if not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}\+?', interface):
            raise ValueError('Некорректный Linux-интерфейс: ' + str(interface))
        if interface == 'lo':
            raise ValueError('localhost разрешён автоматически; укажите интерфейс клиентов.')
    networks = cfg.get('networks', [])
    if not isinstance(networks, list):
        raise ValueError('networks должен быть списком IPv4 CIDR.')
    for network in networks:
        ipaddress.IPv4Network(network, strict=True)
    if any(x.endswith('+') for x in interfaces) and (not networks or '0.0.0.0/0' in networks):
        raise ValueError('Для шаблона интерфейса (например ppp+) обязательна конкретная подсеть VPN.')
    uid = cfg.get('uid', 21116)
    if not isinstance(uid, int) or isinstance(uid, bool) or not 1000 <= uid <= 60000:
        raise ValueError('UID должен быть в пределах 1000..60000.')
    direct = cfg.get('direct', 'off')
    if direct not in ('off', 'xkeen'):
        raise ValueError('direct: off или xkeen.')
    return dict(address=address, interfaces=list(dict.fromkeys(interfaces)),
                networks=list(dict.fromkeys(networks)), uid=uid, direct=direct)


def load_config():
    return validate(json.loads(CONFIG.read_text(encoding='utf-8')))


def assert_managed():
    if not MARKER.is_file() or json.loads(MARKER.read_text()).get('owner') != OWNER:
        raise RuntimeError('Эта установка не принадлежит rustdesk-entware. Изменения отменены.')


def process_matches(pid, executable):
    try:
        args = Path('/proc', str(int(pid)), 'cmdline').read_bytes().split(b'\0')
        return os.fsencode(str(executable)) in args
    except (OSError, ValueError):
        return False


def client_settings(cfg):
    key = (DATA / 'id_ed25519.pub').read_text().strip()
    return ('\nНастройки RustDesk на ОБОИХ устройствах:\n'
            f'  Сервер ID:     {cfg["address"]}:21116\n'
            f'  Ретранслятор:  {cfg["address"]}:21117\n'
            '  Сервер API:    оставить пустым\n'
            f'  Key:           {key}\n'
            '  WebSocket:     выключено\n'
            '  Отключить UDP: выключено\n'
            '  Небезопасный TLS: выключено\n'
            '\nОба клиента должны иметь маршрут до указанного сервера.\n')
