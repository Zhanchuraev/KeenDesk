"""Regenerate the small, pinned bootstrap after changing src/*."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ['common.py','install.py','firewall.py','supervisor.py','manage.py','health.py','doctor.py','restarts.py','recover.py','update.py','web.py','index.html','S90rustdesk','90-rustdesk.sh','rustdeskctl']
header = '''#!/bin/sh
# KeenDesk 0.2.2. Download to a file before running; see README.md.
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
if ! /opt/bin/python3 -c 'import argparse, fcntl, grp, pwd, hashlib, json, logging.handlers, selectors, ssl, sqlite3, secrets, http.server, tarfile, urllib.request, zipfile' 2>/dev/null; then
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
rd_base='https://raw.githubusercontent.com/Zhanchuraev/KeenDesk/v0.2.2/src'
while read -r rd_hash rd_file; do
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 90 "$rd_base/$rd_file" -o "$rd_stage/$rd_file"
    (cd "$rd_stage" && printf '%s  %s\\n' "$rd_hash" "$rd_file" | sha256sum -c -)
done <<'CHECKSUMS'
'''
checksums = ''.join(hashlib.sha256((ROOT/'src'/name).read_bytes()).hexdigest()+' '+name+'\n' for name in FILES)
footer = "CHECKSUMS\n/opt/bin/python3 \"$rd_stage/install.py\" \"$@\"\n"
(ROOT/'install.sh').write_text(header+checksums+footer,encoding='utf-8',newline='\n')
(ROOT/'release.json').write_text(json.dumps(dict(version='0.2.2',files={name:hashlib.sha256((ROOT/'src'/name).read_bytes()).hexdigest() for name in FILES}),indent=2)+'\n',encoding='utf-8',newline='\n')
print('install.sh generated with',len(FILES),'pinned payload checksums')
