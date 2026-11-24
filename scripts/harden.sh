#!/usr/bin/env bash
# harden.sh - Ubuntu 24.04 server hardening. See docs/controls.md.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

log() { printf '[%s] %s\n' "$1" "$2"; }

# write_file PATH MODE  (content comes from stdin)
# Writes the file only if the content differs from what is there.
# Returns 0 if it changed the file, 1 if it was already identical.
write_file() {
  local path="$1" mode="$2" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    return 1
  fi
  install -m "$mode" -o root -g root "$tmp" "$path"
  rm -f "$tmp"
  return 0
}

# C10 + C12: kernel network and information-leak settings
c10_c12_sysctl() {
  local conf=/etc/sysctl.d/99-hardening.conf state
  if write_file "$conf" 0644 <<'EOF'
# Managed by harden.sh - controls C10 and C12 (docs/controls.md)
# C10: network settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# C12: kernel information leaks
kernel.kptr_restrict = 2
kernel.sysrq = 0
net.core.bpf_jit_harden = 2
fs.protected_fifos = 2
dev.tty.ldisc_autoload = 0
EOF
  then state="written"; else state="unchanged"; fi
  sysctl -q -p "$conf"
  log C10/C12 "config $state; values loaded"
}

# C13: disable core dumps
c13_coredumps() {
  local limits_state sysctl_state
  if write_file /etc/security/limits.d/99-hardening.conf 0644 <<'EOF'
# Managed by harden.sh - control C13 (docs/controls.md)
* hard core 0
EOF
  then limits_state="written"; else limits_state="unchanged"; fi

  if write_file /etc/sysctl.d/99-hardening-coredump.conf 0644 <<'EOF'
# Managed by harden.sh - control C13 (docs/controls.md)
fs.suid_dumpable = 0
EOF
  then sysctl_state="written"; else sysctl_state="unchanged"; fi
  sysctl -q -p /etc/sysctl.d/99-hardening-coredump.conf
  log C13 "limits $limits_state; sysctl $sysctl_state; values loaded"
}

# C14: block unused network protocol modules
c14_protocols() {
  local state
  if write_file /etc/modprobe.d/99-hardening-protocols.conf 0644 <<'EOF'
# Managed by harden.sh - control C14 (docs/controls.md)
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
  then state="written"; else state="unchanged"; fi
  log C14 "config $state"
}

# C05, C06, C07, C09: SSH hardening via a drop-in file
c05_c09_ssh() {
  local conf=/etc/ssh/sshd_config.d/10-hardening.conf state prev had_prev=0
  prev="$(mktemp)"
  if [[ -f "$conf" ]]; then cp -p "$conf" "$prev"; had_prev=1; fi

  if write_file "$conf" 0644 <<'EOF'
# Managed by harden.sh - controls C05, C06, C07, C08, C09 (docs/controls.md)
# C05: no direct root login
PermitRootLogin no
# C06: turn off features this server does not use
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
# C07: limit guessing and parallel sessions
MaxAuthTries 3
MaxSessions 2
# C08: drop dead connections (idle shells are handled by TMOUT)
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
# C09: log which key was used to log in
LogLevel VERBOSE
EOF
  then state="written"; else state="unchanged"; fi

  install -d -m 0755 /run/sshd   # sshd -t needs this directory to exist
  if ! sshd -t; then
    echo "SSH config invalid - rolling back $conf" >&2
    if [[ $had_prev -eq 1 ]]; then cp -p "$prev" "$conf"; else rm -f "$conf"; fi
    rm -f "$prev"
    return 1
  fi
  rm -f "$prev"
  systemctl reload ssh
  log C05-C09 "config $state; validated and reloaded"
}


# C08 (second half): end idle interactive shells
c08_idle_shell() {
  local state
  if write_file /etc/profile.d/99-hardening-tmout.sh 0644 <<'EOF'
# Managed by harden.sh - control C08 (docs/controls.md)
# End idle interactive shells after 10 minutes
if [ -z "${TMOUT:-}" ]; then
  readonly TMOUT=600
fi
export TMOUT
EOF
  then state="written"; else state="unchanged"; fi
  log C08 "shell timeout $state"
}

# C15: hide the nginx version
c15_nginx_version() {
  local conf=/etc/nginx/conf.d/10-hardening.conf state prev had_prev=0
  prev="$(mktemp)"
  if [[ -f "$conf" ]]; then cp -p "$conf" "$prev"; had_prev=1; fi

  if write_file "$conf" 0644 <<'EOF'
# Managed by harden.sh - control C15 (docs/controls.md)
# Do not tell visitors which nginx version is running
server_tokens off;
EOF
  then state="written"; else state="unchanged"; fi

  if ! nginx -t; then
    echo "nginx config invalid - rolling back $conf" >&2
    if [[ $had_prev -eq 1 ]]; then cp -p "$prev" "$conf"; else rm -f "$conf"; fi
    rm -f "$prev"
    return 1
  fi
  rm -f "$prev"
  systemctl reload nginx
  log C15 "config $state; validated and reloaded"
}

main() {
  c10_c12_sysctl
  c13_coredumps
  c14_protocols
  c05_c09_ssh
  c08_idle_shell
  c15_nginx_version
}

main "$@"