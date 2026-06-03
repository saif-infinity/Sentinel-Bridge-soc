import paramiko
import subprocess
import logging
from fastapi import APIRouter, Depends
from ..auth import api_key_auth
from ..config import settings
from ..schemas import CommandRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/terminal", tags=["Terminal"], dependencies=[Depends(api_key_auth)])

@router.post("/exec")
async def execute_ssh_command(req: CommandRequest):
    try:
        if req.target == "wazuh":
            try:
                process = subprocess.run(
                    ["docker", "exec", settings.WAZUH_DOCKER_CONTAINER, "sh", "-c", req.command],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                output = process.stdout
                error = process.stderr
                return {
                    "output": output if output else error,
                    "status": "success" if process.returncode == 0 else "error"
                }
            except subprocess.TimeoutExpired:
                return {"output": "Command timed out", "status": "error"}
            except Exception as e:
                return {"output": f"Docker Exec Error: {str(e)}", "status": "error"}

        elif req.target == "suricata":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    settings.SURICATA_HOST,
                    port=settings.SURICATA_PORT,
                    username=settings.SURICATA_USER,
                    password=settings.SURICATA_PASS,
                    timeout=10,
                    banner_timeout=200,
                    look_for_keys=False,
                    allow_agent=False
                )
                stdin, stdout, stderr = client.exec_command(req.command)
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')
                client.close()
                return {
                    "output": output if output else error,
                    "status": "success" if not error else "warning"
                }
            except paramiko.SSHException as e:
                return {"output": f"SSH Protocol Error: {str(e)}", "status": "error"}
            except Exception as e:
                return {"output": f"Connection Error: {str(e)}", "status": "error"}
        else:
            return {"output": f"Unknown target: {req.target}", "status": "error"}
    except Exception as e:
        logger.exception("Terminal execution failed")
        return {"output": f"Error: {str(e)}", "status": "error"}
