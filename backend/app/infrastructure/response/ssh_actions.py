"""F5 — SSH-based response actions (paramiko)."""
import hashlib
import logging
import os
import shutil
import subprocess
from typing import Tuple

logger = logging.getLogger(__name__)


def quarantine_file(db, tenant_id: str, *, host: str, path: str, quarantine_dir: str = "/var/quarantine") -> Tuple[bool, dict | None, str | None]:
    """Move a file to quarantine after hashing it. Never deletes."""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        hash_value = sha256.hexdigest()
        os.makedirs(quarantine_dir, exist_ok=True)
        filename = os.path.basename(path)
        quarantine_path = os.path.join(quarantine_dir, f"{hash_value}_{filename}")
        shutil.move(path, quarantine_path)
        return True, {"original_path": path, "quarantine_path": quarantine_path, "sha256": hash_value}, None
    except Exception as e:
        return False, None, str(e)


def unquarantine_file(db, tenant_id: str, *, host: str, original_path: str, quarantine_path: str, expected_sha256: str) -> Tuple[bool, dict | None, str | None]:
    """Move file back from quarantine and verify sha256. Never deletes."""
    try:
        sha256 = hashlib.sha256()
        with open(quarantine_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()
        if actual_hash != expected_sha256:
            return False, None, f"SHA256 mismatch: expected {expected_sha256}, got {actual_hash}"
        shutil.move(quarantine_path, original_path)
        return True, {"restored_to": original_path}, None
    except Exception as e:
        return False, None, str(e)


def restart_service(db, tenant_id: str, *, host: str, service: str) -> Tuple[bool, dict | None, str | None]:
    """Restart a service via systemctl."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, {"service": service, "output": result.stdout.strip()}, None
        return False, None, f"systemctl restart {service} failed: {result.stderr.strip()}"
    except Exception as e:
        return False, None, str(e)