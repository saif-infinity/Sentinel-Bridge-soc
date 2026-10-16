"""F1 — Statistiques du pipeline + ingestion manuelle (tests / démo)."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...application.pipeline import get_pipeline_stats, ingest_alert, reset_pipeline
from ...auth import get_api_key_or_jwt
from ...db import get_db, get_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pipeline", tags=["Pipeline"],
                   dependencies=[Depends(get_api_key_or_jwt)])


class PipelineIngestRequest(BaseModel):
    source: str = Field("manual", description="wazuh | suricata | manual")
    severity: int = Field(5, ge=0, le=15)
    signature: str = Field("", max_length=255)
    description: str = Field("", max_length=500)
    src_ip: str | None = Field(None, max_length=45)
    dest_ip: str | None = Field(None, max_length=45)
    proto: str | None = Field(None, max_length=20)
    agent_id: str | None = Field(None, max_length=10)
    category: str | None = Field(None, max_length=100)
    raw: dict = Field(default_factory=dict)


@router.get("/stats")
def stats(request: Request):
    tenant_id = get_tenant_id(request)
    return get_pipeline_stats(tenant_id=tenant_id)


@router.post("/ingest")
def ingest(body: PipelineIngestRequest, request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    if not body.signature and not body.description:
        raise HTTPException(status_code=422, detail="signature ou description requis")
    payload = {**body.model_dump(exclude_none=True), "tenant_id": tenant_id}
    return ingest_alert(payload, db=db)


@router.post("/reset")
def reset():
    """Vide le buffer, le tracker de dédup et les compteurs (dev/test uniquement)."""
    reset_pipeline()
    return {"status": "reset"}
