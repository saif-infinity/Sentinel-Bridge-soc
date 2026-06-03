from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class DeviceBase(BaseModel):
    ip: Optional[str] = None
    mac: str
    is_wazuh_agent: bool = False

class DeviceCreate(DeviceBase):
    pass

class DeviceRead(DeviceBase):
    id: int
    is_online: bool

    class Config:
        from_attributes = True

class ScanResult(BaseModel):
    ip: str
    mac: str
    status: List[str]

class ThreatAnalysisRequest(BaseModel):
    timeline: List[str]

class ThreatAnalysisResponse(BaseModel):
    analysis: str
    detected_attack: bool
    risk_level: str

class SuricataAlertRead(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    proto: Optional[str] = None
    alert_msg: Optional[str] = None
    severity: int
    payload: Optional[str] = None

    class Config:
        from_attributes = True

class TaskResponse(BaseModel):
    task_id: str
    status: str

class CommandRequest(BaseModel):
    command: str
    target: str

class IaReportRead(BaseModel):
    id: int
    timestamp: datetime
    report_type: str
    agent_id: Optional[str] = None
    content: str

    class Config:
        from_attributes = True
