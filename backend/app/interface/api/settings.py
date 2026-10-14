from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id
from ...services.system_config_service import _init_defaults, get_all_settings, update_settings

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsUpdateRequest(BaseModel):
    section: str
    data: dict


@router.get("", dependencies=[Depends(get_api_key_or_jwt)])
def read_settings(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)
    return get_all_settings(db, tenant_id=tenant_id)


@router.put("", dependencies=[Depends(has_scopes_or_api_key(["admin:manage"]))])
def write_settings(request: Request, body: SettingsUpdateRequest, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)
    updated = update_settings(db, body.section, body.data, tenant_id=tenant_id)
    if not updated:
        raise HTTPException(status_code=400, detail="No valid fields updated")

    try:
        from ...services.wazuh_service import wazuh_service
        wazuh_service.reload_config(db)
    except Exception:
        pass

    return {"status": "ok", "section": body.section}
