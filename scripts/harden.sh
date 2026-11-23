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

main() {
  c10_c12_sysctl
}

main "$@"