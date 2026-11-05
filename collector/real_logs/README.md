# Real logs from the lab VM

These logs were captured on Nov 5, 2026 from a ParrotOS 6.4 virtual machine
(UTM on macOS, isolated "Shared Network" 192.168.64.0/24) owned by the team.
They are real system output, not hand-written samples. Only lab activity is
included: no real credentials or personal data (NFR-19).

| File | How it was produced | Lines | Events |
| --- | --- | --- | --- |
| `parrot_auth.log` | `sudo useradd -m labtest`, `sudo usermod -aG sudo labtest` and other sudo commands on the VM, exported with `journalctl -o short _COMM=sudo _COMM=useradd _COMM=usermod` (Parrot has no rsyslog, so the journal was exported in syslog format) | 18 | 7 (5 `sudo_command`, 1 `user_added`, 1 `privilege_change`) |
| `parrot_ufw.log` | TCP connect scan from the Mac host (192.168.64.1) to ports 21, 23, 25, 80, 110, 139, 443, 445, 3306, 8080 with `nc -z`; exported with `journalctl -k -o short \| grep UFW` | 10 | 10 `firewall_block` |

Detection results (`tests/test_real_logs.py`):

- `parrot_auth.log` raises **Privilege Change Detected** (labtest added to sudo).
- `parrot_ufw.log` raises **Port Scan Detected** and **Repeated Blocked Connections**.

The test account `labtest` was deleted after the capture.

## Findings from real data

- Each scanned port appears twice: the client retransmits the SYN after one
  second, and UFW logs both. Counting distinct ports (as the port-scan rule
  does) is not affected; counting blocked packets doubles.
- Only 5 of the 10 scanned ports were logged. UFW's default logging level
  ("low") rate-limits log lines, so a fast scan is under-reported. The scan was
  still detected, but thresholds should not assume every packet is logged.
- On this VM `sudo` did not ask for a password, so no real `sudo_failure`
  lines exist here; sudo failures are covered by `collector/scenarios/`.
- The 11 skipped auth lines are `pam_unix` session open/close lines, the
  `new group` line from useradd and usermod's duplicate "shadow group" line.
  All are skipped on purpose.

## Reproduce

```bash
python3 collector/normalize_logs.py collector/real_logs/parrot_auth.log collector/real_logs/parrot_ufw.log -q -o real_events.json
```
