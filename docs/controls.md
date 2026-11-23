# Hardening Controls

This document lists every change planned for the server, why it is planned, how it will be tested, and what could break. It also lists what was considered and deliberately skipped.

**Status of this document:** DRAFT. Every control below is Planned. Nothing has been applied or tested yet. The "Status" column will be updated only after a control has actually been applied and its test has actually been run.

## Scenario

A new Ubuntu 24.04 web server is to go live. It must serve a website (nginx) and be reachable by SSH for administration. The task is harden it, prove it is safer than before, and prove it still works.

## Where the controls come from

- **Baseline evidence** captured before any change (`evidence/before/`): nmap full-port scan, Lynis audit (index 62, 1 warning, 47 suggestions), `ss` listening ports, pending updates, firewall state, effective SSH settings (`sshd -T`) and kernel settings (`sysctl -a`).
- **Lynis suggestion IDs** (e.g. SSH-7408) where Lynis flagged something.
- **CIS Ubuntu Linux 24.04 LTS Benchmark** for controls Lynis does not check (for example, disabling SSH password login). Exact benchmark section numbers will be added when the benchmark has been read; they are not filled in yet.

## Controls

Risk means the chance of breaking the server's job or locking out the administrator: **Low**, **Medium**, **High**.

### Updates and firewall

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C01 | Apply pending package updates; check whether automatic security updates are enabled | 28 packages were waiting for updates at baseline (none from the security channel) | `apt list --upgradable` shows nothing pending; automatic update settings checked | Low (a kernel update needs a reboot) | Planned |
| C02 | Firewall: block all inbound traffic except SSH (22), HTTP (80), HTTPS (443), for IPv4 and IPv6 | Lynis FIRE-4512; baseline nmap showed 65,533 ports "closed (reset)", meaning no filtering | Full-port nmap from Windows: only allowed ports open, the rest **filtered**; website still loads; SSH still works | High (can lock out SSH) | Planned |
| C03 | Firewall: rate-limit new SSH connections (`ufw limit`) | Slows password guessing without installing another service | Rapid repeated connection attempts get blocked; normal login still works | Medium | Planned |

### SSH

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C04 | Key-only SSH login (`PasswordAuthentication no`) | `sshd -T` at baseline: `passwordauthentication yes`. Not flagged by Lynis; comes from CIS | Login attempt with password only is refused; login with key works | High (can lock out SSH) | Planned |
| C05 | Root login disabled (`PermitRootLogin no`) | Baseline: `without-password` (keys only, but not explicit) | `ssh root@...` is refused; `sshd -T` shows `no` | Low | Planned |
| C06 | Turn off unused SSH features: TCP forwarding, X11 forwarding, agent forwarding | Lynis SSH-7408; baseline: all three enabled | Attempt an SSH tunnel and it fails; `sshd -T` shows `no` | Low | Planned |
| C07 | Limit login attempts and sessions (`MaxAuthTries 3`, `MaxSessions 2`) | Lynis SSH-7408; baseline: `maxauthtries 6` | `sshd -T` shows new values; repeated bad attempts disconnect after 3 | Low | Planned |
| C08 | Drop idle SSH sessions (`ClientAliveInterval`, `ClientAliveCountMax 2`, `TCPKeepAlive no`) | Lynis SSH-7408 | `sshd -T` shows values; idle session test (using a temporary short interval) | Low | Planned |
| C09 | SSH logging at `VERBOSE` | Lynis SSH-7408; baseline: `loglevel INFO`. Verbose records which key logged in | After a login, the SSH log shows the key fingerprint | Low | Planned |

### Kernel and system

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C10 | Network settings: ignore ICMP redirects, refuse source-routed packets, do not send redirects, log impossible source addresses (IPv4 and IPv6) | Lynis KRNL-6000; baseline values listed as DIFFERENT in `lynis-before.txt` | `sysctl` values match; they survive a reboot | Low | Planned |
| C11 | Strict reverse-path filtering (`rp_filter = 1`) | Baseline value is 2 (loose). Separate from C10 because it can drop traffic on multi-network machines | Value is 1; SSH works over both network adapters after a reboot | Medium | Planned |
| C12 | Kernel information-leak settings: `kptr_restrict 2`, `sysrq 0`, `bpf_jit_harden 2`, `protected_fifos 2`, `ldisc_autoload 0` | Lynis KRNL-6000; baseline: kptr_restrict 1, sysrq 176, protected_fifos 1 | Values match and survive a reboot | Low | Planned |
| C13 | Core dumps disabled (`limits.conf` and `fs.suid_dumpable 0`) | Lynis KRNL-5820; crash dumps can leak secrets from memory | New session shows core limit 0; `fs.suid_dumpable` is 0 | Low | Planned |
| C14 | Unused network protocols blocked: dccp, sctp, rds, tipc | Lynis NETW-3200 | Loading each module is refused | Low | Planned |

### Web server

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C15 | nginx hides its version (`server_tokens off`) | Baseline nmap `-sV` reported `nginx 1.24.0` to any visitor | `curl -I` shows no version; nmap `-sV` no longer reports it | Low | Planned |
| C16 | nginx HTTPS with a self-signed certificate, TLS 1.2 and above only, HTTP redirects to HTTPS | Lynis HTTP-6710. Certificate is self-signed because the server has no real domain | HTTP returns a redirect; old TLS versions are refused; TLS 1.2/1.3 work; page loads | Medium | Planned |

### Accounts and passwords

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C17 | Default umask `027` | Lynis AUTH-9328 | New files are not world-readable; **the website still serves files after a new page is added** | Medium (can stop nginx reading files) | Planned |
| C18 | Password ageing: minimum and maximum age | Lynis AUTH-9286 | `chage -l` shows the limits | Low | Planned |
| C19 | Password strength checking (`libpam-pwquality`) | Lynis AUTH-9262 | A weak password is rejected (tested on a throwaway account, not the admin) | Medium (PAM mistakes can break `sudo`) | Planned |
| C20 | Consistent password hashing: set `ENCRYPT_METHOD YESCRYPT` and re-set the admin password so the stored hash is yescrypt | Baseline: `/etc/pam.d/common-password` uses yescrypt for new passwords, but `login.defs` says SHA512 and the admin hash is `$6$` (SHA-512). Replaces the earlier idea of tuning SHA-512 rounds | Stored hash prefix is `$y$`; `sudo` still works with the new password | Medium (admin password change) | Planned |

### Integrity and auditing

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| C21 | `debsums` package-file integrity check | Lynis PKGS-7370. Detects modified program files. Does not cover files outside packages | `debsums -s` is clean; deliberately modify a packaged file and confirm it is reported | Low | Planned |
| C22 | Login banner in `/etc/issue`, `/etc/issue.net` and for SSH | Lynis BANN-7126, BANN-7130 | Banner appears on SSH connection | Low | Planned |
| C23 | auditd with a short rule set that watches the files this project hardens (SSH config, firewall config, sysctl files, `login.defs`, sudoers) | Lynis ACCT-9628; no audit logging exists on this server. Aim: record changes to the hardening itself | Edit a watched file and find the event with `ausearch` | Low | Planned |

### Stretch goal (only if everything above is finished)

| ID | Control | Why / evidence | How it will be tested | Risk | Status |
|---|---|---|---|---|---|
| S01 | systemd sandboxing for nginx | Lynis BOOT-5264 (`systemd-analyze security`) | Exposure score improves; website still works | Medium | Not started |

## Considered and skipped

| Item | Reason |
|---|---|
| fail2ban (DEB-0880) | `ufw limit` (C03) covers brute-force slowdown without another service |
| GRUB boot password (BOOT-5122), USB storage (USB-1000) | Defend against someone physically at the machine. This server is a VM, so out of scope |
| Change the SSH port (SSH-7408) | Hides rather than protects; a full port scan finds it. Ubuntu 24.04 also starts SSH through systemd, which complicates the change |
| Account expiry dates (AUTH-9282) | One admin account; expiry could lock out the only administrator |
| Separate partitions for /home, /tmp, /var (FILE-6310) | An install-time decision; not sensible to change after installation. Noted as a recommendation for new builds |
| External log host (LOGG-2154) | Out of scope for this project |
| AIDE / full file integrity monitoring (FINT-4350) | Needs ongoing maintenance of a baseline database. `debsums` (C21) covers part of it; the gap is listed under limitations |
| Convenience packages: libpam-tmpdir, apt-listbugs, apt-listchanges, apt-show-versions | Little or no security value on this server |
| Process accounting, sysstat (ACCT-9622, ACCT-9626) | Performance and accounting tools, not security controls here |
| Automation tool suggestion (TOOL-5002), DNS domain name (NAME-4028) | Informational; this project provides its own script |
| Malware scanner (HRDN-7230) | Not decided to be worth the extra software on a small web server. Revisit if scope changes |
| `kernel.modules_disabled = 1` | Blocks all kernel module loading until reboot, which risks breaking the firewall and cannot be undone while running |
| `kernel.core_uses_pid` | Only changes crash-dump file names; core dumps are disabled anyway (C13) |
| `kernel.perf_event_paranoid` | Baseline value is 4, already stricter than Lynis's target of 3 |
| `kernel.unprivileged_bpf_disabled` | Baseline value is 2: already disabled for unprivileged users. Lynis's target (1) differs only in being impossible to switch back without a reboot |
| Updating Lynis (LYNIS) | The same Lynis version must be used for the "before" and "after" scans so the results are comparable |

## Open items

- **FILE-7524** (restrict file permissions): Lynis did not print which files it means. To be identified before deciding.
- **Automatic security updates:** current state not checked yet (part of C01).
- **SSH key pair:** needed before C04 can be applied. Not created yet.
- **CIS Benchmark section numbers:** to be added to the controls table.
