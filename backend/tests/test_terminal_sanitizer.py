"""Regression tests for the restricted terminal sanitizer.

These lock in the fixes for the four bypasses that existed before:
  1. `docker` in the allowlist  -> container escape / root on the host
  2. `find /var/log -exec …`    -> only parts[1] was path-checked
  3. `grep -r root /etc/shadow` -> no path restriction at all
  4. `systemctl edit …`         -> writing a unit file = code execution

Run: cd backend && pytest tests/test_terminal_sanitizer.py -q
"""
import pytest

from app.interface.api.terminal import ALLOWED_COMMANDS, sanitize_command


# ── legitimate diagnostics must keep working ────────────────────────────
@pytest.mark.parametrize("cmd,target", [
    ("cat /var/ossec/logs/ossec.log", "wazuh"),
    ("tail -n 100 /var/ossec/logs/ossec.log", "wazuh"),
    ("head -20 /var/log/syslog", "wazuh"),
    ("ls /var/log", "wazuh"),
    ("ls /var/log/", "wazuh"),
    ("journalctl -u wazuh-manager --no-pager", "wazuh"),
    ("systemctl status wazuh-manager", "wazuh"),
    ("systemctl is-active wazuh-manager", "wazuh"),
    ("ps aux", "wazuh"),
    ("ss -tulpn", "wazuh"),
    ("df -h", "suricata"),
    ("uptime", "suricata"),
    ("suricatasc -c ps", "suricata"),
    ("cat /etc/suricata/suricata.yaml", "suricata"),
])
def test_allows_legitimate_diagnostics(cmd, target):
    assert sanitize_command(cmd, target) == cmd


# ── the four historical bypasses ────────────────────────────────────────
@pytest.mark.parametrize("cmd,target", [
    # 1. docker / container escape
    ("docker run --privileged -v /:/host alpine chroot /host", "wazuh"),
    ("docker ps", "wazuh"),
    # 2. find -exec / -delete (and the `+` terminator that was not blocked)
    ("find /var/log -type f -exec cat /etc/shadow +", "wazuh"),
    ("find /var/log -delete", "wazuh"),
    ("find /var/log -execdir id ;", "wazuh"),
    # 3. unrestricted readers
    ("grep -r root /etc/shadow", "wazuh"),
    ("grep password /etc/suricata/suricata.yaml", "suricata"),
    # 4. systemctl as a write primitive
    ("systemctl edit wazuh-manager", "wazuh"),
    ("systemctl set-property wazuh CPUQuota=1%", "wazuh"),
])
def test_blocks_the_known_bypasses(cmd, target):
    with pytest.raises(ValueError):
        sanitize_command(cmd, target)


# ── path confinement for every reading command ──────────────────────────
@pytest.mark.parametrize("cmd", [
    "cat /etc/shadow",
    "cat /etc/passwd",
    "tail -f /root/.ssh/id_rsa",
    "head /var/ossec/etc/../../etc/shadow",
    "ls /etc",
])
def test_blocks_paths_outside_the_safe_directories(cmd):
    with pytest.raises(ValueError):
        sanitize_command(cmd, "wazuh")


def test_blocks_path_traversal_even_inside_a_safe_prefix():
    with pytest.raises(ValueError):
        sanitize_command("cat /var/log/../../etc/shadow", "wazuh")


# ── flag-level confinement ─────────────────────────────────────────────
@pytest.mark.parametrize("cmd", [
    "journalctl --file=/etc/shadow",
    "journalctl --directory=/etc",
    "cat -o /var/log/syslog",
])
def test_blocks_dangerous_flags(cmd):
    with pytest.raises(ValueError):
        sanitize_command(cmd, "wazuh")


# ── shell metacharacters and size limit (pre-existing behaviour kept) ───
@pytest.mark.parametrize("cmd", [
    "cat /var/log/syslog | grep root",
    "cat /var/log/syslog; reboot",
    "cat $(whoami)",
    "cat `id`",
    "cat /var/log/syslog && curl http://evil",
])
def test_blocks_shell_metacharacters(cmd):
    with pytest.raises(ValueError):
        sanitize_command(cmd, "wazuh")


def test_rejects_overlong_commands():
    with pytest.raises(ValueError):
        sanitize_command("cat " + "/var/log/" + "a" * 600, "wazuh")


def test_rejects_empty_and_unknown_commands():
    with pytest.raises(ValueError):
        sanitize_command("   ", "wazuh")
    with pytest.raises(ValueError):
        sanitize_command("reboot", "wazuh")
    with pytest.raises(ValueError):
        sanitize_command("cat /etc/passwd", "not-a-target")


def test_no_interactive_or_docker_binaries_in_any_allowlist():
    for target, allowed in ALLOWED_COMMANDS.items():
        for binary in ("docker", "grep", "find", "top", "htop", "sh", "bash", "python", "curl", "wget"):
            assert binary not in allowed, f"{binary} must not be reachable via the {target} terminal"
        # every two-word entry must actually be reachable by the prefix matcher
        for entry in allowed:
            if " " in entry:
                assert entry.split()[0] not in allowed, (
                    f"'{entry}' is shadowed by the bare '{entry.split()[0]}' allowlist entry"
                )
