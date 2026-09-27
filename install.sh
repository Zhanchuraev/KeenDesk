#!/bin/sh
# KeenDesk 0.2.1. Download to a file before running; see README.md.
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
rd_base='https://raw.githubusercontent.com/Zhanchuraev/KeenDesk/v0.2.1/src'
while read -r rd_hash rd_file; do
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 90 "$rd_base/$rd_file" -o "$rd_stage/$rd_file"
    (cd "$rd_stage" && printf '%s  %s\n' "$rd_hash" "$rd_file" | sha256sum -c -)
done <<'CHECKSUMS'
b341b69c0f285bc816c22c65463961316e163e8d17ac0d41e2054b08e5fe961b common.py
03f834ed44f149b18752c1532e8d10ad37b4884f95661565a874853f6a20095d install.py
8cec6177e68b93ba4f633535ea5ee87dad39870ab4c9560daf95d662e7545fd4 firewall.py
e68c7a383882c32ed1226de17dbaecc23d9041cc4ddd1f8ecd22254fbcf59417 supervisor.py
93addad8d6cbd69b53a5271a16dad82cafd665c0f173c252ae7ba988e0c2a637 manage.py
deca1571f87770df19894784bd16ee125d88edd11eab9a8022722cfd39a90eb4 health.py
a25b696016b8ef6356d9f4b720cbd12980dd09379fe1a7e556b874ddde460153 doctor.py
1848f1f1aaf4cf4729fcd9a63e0c5e9215a56b14a90b7b8f073514ba4e17e87e restarts.py
11289f5f21c0f2687d0250b3fb3b0d4afa8a74028087f54e7c0fb05d4ffda116 recover.py
efd26a1d6ec608fa7619f86a57e0fffface150c3f7a717148e9b188c50bb3f79 update.py
4d0d15ad85685cca5a8e4e25563b58345930153eb9d80ee2d2388476254081bf web.py
c65ef2677960424a885a8e7bf21e147ec933ec0383d25a72b9c88f8e67344294 index.html
23c9c47cdb829a38692dcd0de4b5c645a72051a28c45f0a32e60da108c58ec70 S90rustdesk
eb8e945cd02e6f8d5032eea15b267cca789e569d72777650850e7f21a6e3f3ea 90-rustdesk.sh
93b56ea6944ddd1551a0ccbe8eaae643ed7ad0114e71571c6a127dce7d7649b7 rustdeskctl
CHECKSUMS
/opt/bin/python3 "$rd_stage/install.py" "$@"
