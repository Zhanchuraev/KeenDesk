#!/opt/bin/python3
"""Own chains only; keep a terminal DROP while reconciling access rules."""
import os
from pathlib import Path
import shlex
import shutil
import sys
from common import load_config, run

INPUT = 'RDE_INPUT'
OUTPUT = 'RDE_OUTPUT'
NAT = 'RDE_NAT'


def ipt(binary, table, *args, check=True):
    return run([binary, '-w', '-t', table, *args], check=check)


def rules(binary, table, chain):
    output = ipt(binary, table, '-S', chain).stdout
    return [shlex.split(x)[2:] for x in output.splitlines() if x.startswith('-A ')]


def ensure_chain(binary, table, chain):
    if ipt(binary, table, '-N', chain, check=False).returncode:
        ipt(binary, table, '-S', chain)


def input_rules(cfg, ipv6=False):
    desired = [['-i', 'lo', '-j', 'ACCEPT']]
    if not ipv6:
        for iface in cfg['interfaces']:
            for network in cfg['networks'] or [None]:
                source = ['-s', network] if network and network != '0.0.0.0/0' else []
                desired.append(['-i', iface, *source, '-p', 'tcp', '-m', 'multiport',
                                '--dports', '21115:21117', '-j', 'ACCEPT'])
                desired.append(['-i', iface, *source, '-p', 'udp', '-m', 'udp',
                                '--dport', '21116', '-j', 'ACCEPT'])
    return desired + [['-j', 'DROP']]


def reconcile_input(binary, cfg, ipv6=False):
    ensure_chain(binary, 'filter', INPUT)
    drop = ['-j', 'DROP']
    if ipt(binary, 'filter', '-C', INPUT, *drop, check=False).returncode:
        ipt(binary, 'filter', '-A', INPUT, *drop)
    desired = input_rules(cfg, ipv6)
    # Remove stale allows before adding new ones; never flush an attached INPUT chain.
    for existing in rules(binary, 'filter', INPUT):
        if existing not in desired:
            ipt(binary, 'filter', '-D', INPUT, *existing)
    for rule in reversed(desired[:-1]):
        if ipt(binary, 'filter', '-C', INPUT, *rule, check=False).returncode:
            ipt(binary, 'filter', '-I', INPUT, '1', *rule)
    jump_first(binary, 'filter', 'INPUT', ['-p', 'tcp', '-m', 'multiport', '--dports', '21115:21119', '-j', INPUT])
    jump_first(binary, 'filter', 'INPUT', ['-p', 'udp', '-m', 'udp', '--dport', '21116', '-j', INPUT])


def jump_first(binary, table, chain, rule):
    existing = rules(binary, table, chain)
    # The first two entries are both ours for INPUT, just one for OUTPUT.
    count = 2 if chain == 'INPUT' else 1
    hits = [i for i, x in enumerate(existing, 1) if x == rule]
    if hits and hits[0] <= count:
        for index in reversed(hits[1:]):
            ipt(binary, table, '-D', chain, str(index))
        return
    ipt(binary, table, '-I', chain, '1', *rule)
    for index in reversed(hits):
        ipt(binary, table, '-D', chain, str(index + 1))


def direct_rules(cfg, ipv6=False):
    if cfg['direct'] == 'xkeen' and not ipv6:
        return [['-j', 'DSCP', '--set-dscp', '62'],
                ['-j', 'MARK', '--set-mark', '0xffffa00'], ['-j', 'ACCEPT']]
    return [['-j', 'ACCEPT']]


def reconcile_output(binary, cfg, ipv6=False):
    # No broad routing rules are installed. Xkeen's known main-table mark is reused.
    for table, chain, desired in [('mangle', OUTPUT, direct_rules(cfg, ipv6)),
                                  ('nat', NAT, [['-j', 'ACCEPT']])]:
        ensure_chain(binary, table, chain)
        current = rules(binary, table, chain)
        # iptables canonicalizes DSCP to hexadecimal and MARK to --set-xmark.
        normalized = []
        for row in current:
            row = [('--set-mark' if x == '--set-xmark' else x) for x in row]
            row = [('0xffffa00' if x == '0xffffa00/0xffffffff' else x) for x in row]
            row = [('62' if x.lower() == '0x3e' else x) for x in row]
            normalized.append(row)
        if normalized != desired:
            ipt(binary, table, '-F', chain)
            for rule in desired:
                ipt(binary, table, '-A', chain, *rule)
        jump_first(binary, table, 'OUTPUT', ['-m', 'owner', '--uid-owner', str(cfg['uid']), '-j', chain])


def binaries():
    v4 = shutil.which('iptables')
    if not v4:
        raise RuntimeError('Не найден iptables. Установите компонент Netfilter в KeeneticOS.')
    result = [(v4, False)]
    if Path('/proc/net/if_inet6').exists():
        v6 = shutil.which('ip6tables')
        if not v6:
            raise RuntimeError('IPv6 включён, но нет ip6tables: небезопасный запуск запрещён.')
        result.append((v6, True))
    return result


def apply(cfg):
    if cfg['direct'] == 'xkeen':
        lines = run(['ip', 'rule', 'show']).stdout.splitlines()
        if not any('fwmark 0xffffa00' in x and 'lookup main' in x for x in lines):
            raise RuntimeError('Ожидается штатное правило XKeen fwmark 0xffffa00 -> main.')
    for binary, ipv6 in binaries():
        reconcile_input(binary, cfg, ipv6)
        reconcile_output(binary, cfg, ipv6)


def remove():
    for binary, _ in binaries():
        for table, parent, chain in [('filter','INPUT',INPUT), ('mangle','OUTPUT',OUTPUT), ('nat','OUTPUT',NAT)]:
            if ipt(binary, table, '-S', chain, check=False).returncode:
                continue
            for rule in rules(binary, table, parent):
                if rule[-2:] == ['-j', chain]:
                    ipt(binary, table, '-D', parent, *rule)
            ipt(binary, table, '-F', chain)
            ipt(binary, table, '-X', chain)


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == 'remove':
            remove()
        else:
            apply(load_config())
    except Exception as exc:
        print('Firewall RustDesk: ' + str(exc), file=sys.stderr)
        sys.exit(1)
