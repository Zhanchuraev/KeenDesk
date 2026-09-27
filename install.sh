#!/bin/sh
# rustdesk-entware 0.1.0. Download to a file before running; see README.md.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[ "$(id -u)" = 0 ] || { echo 'Нужен root в Entware.' >&2; exit 1; }
case "$(uname -m)" in aarch64|arm64) ;; *) echo 'Поддерживается только ARM64/aarch64, не MIPS/ARMv7.' >&2; exit 1;; esac
[ -x /opt/bin/opkg ] && [ -x /opt/bin/sh ] && [ -x /bin/ndmc ] || { echo 'Нужен Keenetic с Entware.' >&2; exit 1; }
if [ -e /opt/etc/rustdesk ] && [ ! -f /opt/etc/rustdesk/managed.json ]; then
    echo 'Найдена существующая установка RustDesk. Ничего не перезаписано.' >&2
    exit 1
fi
rd_deps=''
if ! /opt/bin/python3 -c 'import argparse, fcntl, grp, pwd, hashlib, json, logging.handlers, selectors, ssl, tarfile, urllib.request, zipfile' 2>/dev/null; then
    rd_deps="$rd_deps python3 ca-bundle"
fi
command -v iptables >/dev/null 2>&1 || rd_deps="$rd_deps iptables"
command -v ip >/dev/null 2>&1 || rd_deps="$rd_deps ip-full"
if [ -n "$rd_deps" ]; then
    opkg update
    opkg install $rd_deps
fi
for tool in curl sha256sum iptables ip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Нет команды $tool; см. README.md." >&2; exit 1; }
done
rd_stage=$(mktemp -d /tmp/rustdesk-entware.XXXXXX)
trap 'rm -rf "$rd_stage"' EXIT
trap 'exit 130' HUP INT TERM
rd_base='https://raw.githubusercontent.com/Zhanchuraev/rustdesk-entware/v0.1.0/src'
while read -r rd_hash rd_file; do
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 90 "$rd_base/$rd_file" -o "$rd_stage/$rd_file"
    (cd "$rd_stage" && printf '%s  %s\n' "$rd_hash" "$rd_file" | sha256sum -c -)
done <<'CHECKSUMS'
516513cdd15cc814ce15f1af6f88cbba00e1a0298b4a6e2bf6259a70e3f3d8d2 common.py
aaff7403bfd815a143500997160affd99cf9d4d355d6e609ba7299d2ea15fbf6 install.py
0c4e7b81f4d467c89546e9f2692b25a4dc5e534a35f5fa67a0435420e54e6670 firewall.py
ba5bed200725bd64740dc333f4eebf663f50e27d72531c8236af1c897b0b32b3 supervisor.py
dc75930e52a5b98b277613010b15f81201ff3a31ec61578541936b64a8739b91 manage.py
d774662d25e93dca96336b7217a9fe590c96a5125623330b328fc6fbb9b9efea S90rustdesk
eb8e945cd02e6f8d5032eea15b267cca789e569d72777650850e7f21a6e3f3ea 90-rustdesk.sh
93b56ea6944ddd1551a0ccbe8eaae643ed7ad0114e71571c6a127dce7d7649b7 rustdeskctl
CHECKSUMS
/opt/bin/python3 "$rd_stage/install.py" "$@"
