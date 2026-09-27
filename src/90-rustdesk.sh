#!/opt/bin/sh
# NDM can recreate tables during boot. Let the one supervisor reconcile them.
/opt/bin/touch /opt/var/run/rustdesk-firewall.pending
