import logging
import shlex
import subprocess

import paramiko
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...config import settings
from ...db import get_db
from ...schemas import CommandRequest

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# FIX — the previous allowlist only ever checked parts[0], which made it
# trivially escapable:
#   • `docker` was allowed -> `docker exec <c> docker run --privileged -v /:/h …`
#     (the Wazuh container is entered from the backend host, i.e. with the docker
#      socket => root on the host);
#   • `find` only had its FIRST path argument checked, so
#     `find /var/log -type f -exec cat /etc/shadow +` ran `cat` anywhere
#     (`+` and `-exec` were not in the blocked-character list);
#   • `grep` had no path restriction at all -> `grep -r root /etc/shadow`;
#   • `systemctl` allowed `edit` / `set-property` (writing a unit file = RCE);
#   • `top` / `htop` are interactive and always burned the 15 s timeout;
#   • the multi-word entries "docker ps" / "docker stats" could never match,
#     because only the first word was compared.
# Below: two-word commands are matched as such, dangerous flags are rejected, and
# every absolute path argument of a read command must be inside a safe directory.
# ══════════════════════════════════════════════════════════════════════
ALLOWED_COMMANDS = {
    "wazuh": {
        "status", "agent_control", "ossec-control",
        "cat", "tail", "head", "ls", "df", "free", "uptime", "whoami", "id",
        "ps", "netstat", "ss", "ip", "journalctl",
        "systemctl status", "systemctl is-active", "systemctl list-units", "systemctl show",
    },
    "suricata": {
        "status", "cat", "tail", "head", "ls", "df", "free", "uptime", "whoami", "id",
        "ps", "netstat", "ss", "ip", "suricatasc",
        "systemctl status", "systemctl is-active", "systemctl list-units", "systemctl show",
    },
}

# `grep` and `find` were deliberately REMOVED from the allowlists above: even with a
# directory restriction they are execution primitives (`find -exec`) and arbitrary
# file readers. `ls` + `cat` + `tail` + `head` + `journalctl` cover every legitimate
# diagnostic need. They stay listed here as defence in depth if re-added later.
FILE_READING_COMMANDS = {"cat", "tail", "head", "ls", "grep", "find"}

# Flags that turn a "read-only" binary into an execution/arbitrary-read primitive.
FORBIDDEN_FLAGS = {
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls",
    "--directory", "--file", "--output", "-o", "--eval", "-e",
}

# Restrict file-reading commands to known safe directories only
SAFE_READ_DIRS = {
    "wazuh": ["/var/log/", "/var/ossec/logs/", "/var/ossec/etc/"],
    "suricata": ["/var/log/", "/etc/suricata/"],
}


def sanitize_command(cmd: str, target: str) -> str:
    cmd = cmd.strip()
    if not cmd:
        raise ValueError("Empty command")

    if len(cmd) > 500:
        raise ValueError("Command too long")

    for char in ['|', '&', ';', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r']:
        if char in cmd:
            raise ValueError(f"Invalid character in command: {char}")

    try:
        parts = shlex.split(cmd)
    except ValueError:
        raise ValueError("Invalid command syntax")

    if not parts:
        raise ValueError("Empty command")

    lowered = [part.lower() for part in parts]
    allowed = ALLOWED_COMMANDS.get(target, set())

    # Match the longest allowed prefix ("systemctl status" beats "systemctl").
    base_cmd = None
    for words in (2, 1):
        candidate = " ".join(lowered[:words])
        if candidate in allowed:
            base_cmd = candidate
            break
    if base_cmd is None:
        raise ValueError(f"Command '{lowered[0]}' is not allowed. Allowed: {', '.join(sorted(allowed))}")

    argv = parts[len(base_cmd.split()):]

    for arg in argv:
        if arg in FORBIDDEN_FLAGS or arg.split("=", 1)[0] in FORBIDDEN_FLAGS:
            raise ValueError(f"Flag '{arg}' is not allowed")
        if arg.startswith("-exec") or arg.startswith("-delete"):
            raise ValueError(f"Flag '{arg}' is not allowed")

    # Every absolute path handed to a reading command must be inside a safe dir.
    if lowered[0] in FILE_READING_COMMANDS:
        safe_dirs = SAFE_READ_DIRS.get(target, [])
        for arg in argv:
            if ".." in arg:
                raise ValueError("Path traversal ('..') is not allowed")
            if not arg.startswith("/"):
                continue
            if not any(arg == d.rstrip("/") or arg.startswith(d) for d in safe_dirs):
                raise ValueError(f"Access to '{arg}' is restricted to: {', '.join(safe_dirs)}")

    return cmd


router = APIRouter(prefix="/api/terminal", tags=["Terminal"], dependencies=[Depends(get_api_key_or_jwt)])

def _get_ssh_config(db: Session, target: str, request: Request = None) -> dict:
    from ...services.system_config_service import get_config_value
    if target == "wazuh":
        return {
            "docker_container": get_config_value(db, "wazuh_ssh", "docker_container", settings.WAZUH_DOCKER_CONTAINER),
            "ssh_port": int(get_config_value(db, "wazuh_ssh", "ssh_port", str(settings.WAZUH_SSH_PORT))),
            "ssh_user": get_config_value(db, "wazuh_ssh", "ssh_user", settings.WAZUH_SSH_USER),
            "ssh_password": get_config_value(db, "wazuh_ssh", "ssh_password", ""),
        }
    else:
        return {
            "host": get_config_value(db, "suricata_ssh", "host", settings.SURICATA_HOST),
            "port": int(get_config_value(db, "suricata_ssh", "port", str(settings.SURICATA_PORT))),
            "user": get_config_value(db, "suricata_ssh", "user", settings.SURICATA_USER),
            "password": get_config_value(db, "suricata_ssh", "password", ""),
        }


@router.post("/exec")
async def execute_ssh_command(request: Request, req: CommandRequest, db: Session = Depends(get_db),
                              _=Depends(has_scopes_or_api_key(["terminal:exec"]))):
    try:
        if req.target not in ("wazuh", "suricata"):
            return {"output": "Invalid target", "status": "error"}

        cmd = sanitize_command(req.command, req.target)
        cfg = _get_ssh_config(db, req.target, request)

        if req.target == "wazuh":
            try:
                args_list = shlex.split(cmd)
                process = subprocess.run(
                    ["docker", "exec", cfg["docker_container"], *args_list],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                output = process.stdout[:4096]
                error = process.stderr[:1024]
                return {
                    "output": output if output else error,
                    "status": "success" if process.returncode == 0 else "error"
                }
            except subprocess.TimeoutExpired:
                return {"output": "Command timed out", "status": "error"}
            except Exception as e:
                logger.error("Docker exec error: %s", e)
                return {"output": "Failed to execute command on Wazuh", "status": "error"}

        elif req.target == "suricata":
            if not cfg.get("password"):
                return {"output": "Suricata SSH password not configured. Go to Settings.", "status": "error"}
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            try:
                client.connect(
                    cfg["host"],
                    port=cfg["port"],
                    username=cfg["user"],
                    password=cfg["password"],
                    timeout=10,
                    banner_timeout=200,
                    look_for_keys=False,
                    allow_agent=False
                )
                stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
                output = stdout.read().decode('utf-8', errors='replace')[:4096]
                error = stderr.read().decode('utf-8', errors='replace')[:1024]
                client.close()
                return {
                    "output": output if output else error,
                    "status": "success" if not error else "warning"
                }
            except paramiko.ssh_exception.SSHException as e:
                if "Unknown server" in str(e) or "host key" in str(e).lower():
                    logger.warning("SSH host key verification failed for %s", cfg["host"])
                    return {"output": "Host key verification failed. Add the host key to known_hosts.", "status": "error"}
                logger.error("SSH error: %s", e)
                return {"output": "SSH connection failed", "status": "error"}
            except Exception as e:
                logger.error("Suricata SSH error: %s", e)
                return {"output": "Connection to Suricata failed", "status": "error"}

    except ValueError as e:
        # FIX: a rejected command used to come back as HTTP 200 with
        # {"status": "error"}, which the UI cannot distinguish from success.
        raise HTTPException(status_code=400, detail=f"Command rejected: {e}")
    except Exception as e:
        logger.exception("Terminal execution failed")
        return {"output": "Internal error during command execution", "status": "error"}
