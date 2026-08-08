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
    # Le backend ignore toute donnée frontend et récupère directement
    # les 10 dernières alertes Wazuh critiques (level >= 7) depuis la DB.
    pass

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
    verdict: Optional[str] = None
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

class AssetBase(BaseModel):
    ip: str
    employee_name: str
    department: str

class AssetCreate(AssetBase):
    pass

class AssetRead(AssetBase):
    id: int
    mac: Optional[str] = None
    is_online: bool = False
    is_wazuh_agent: bool = False
    bandwidth_in: float = 0.0
    bandwidth_out: float = 0.0

    class Config:
        from_attributes = True


class AccessLogCreate(BaseModel):
    username: str
    face_image: Optional[str] = None
    face_verified: bool = False
    ip_address: Optional[str] = None
    login_method: str = "password"


class AccessLogRead(BaseModel):
    id: int
    username: str
    login_time: datetime
    logout_time: Optional[datetime] = None
    is_online: bool
    face_image: Optional[str] = None
    face_verified: bool
    ip_address: Optional[str] = None
    login_method: str
    session_duration: Optional[int] = None

    class Config:
        from_attributes = True


class AccessLogStatus(BaseModel):
    username: str
    is_online: bool
    login_time: Optional[datetime] = None
    face_verified: bool = False


class SurveillanceStats(BaseModel):
    total_logins_today: int
    users_online: int
    avg_session_minutes: Optional[float] = None
    total_users_registered: int
    face_auth_percentage: float


class ActionLogCreate(BaseModel):
    username: str
    action: str
    details: Optional[str] = None
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    face_verified: bool = False


class ActionLogRead(BaseModel):
    id: int
    username: str
    action: str
    details: Optional[str] = None
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    face_verified: bool
    timestamp: datetime

    class Config:
        from_attributes = True


class AdminStats(BaseModel):
    total_analysts: int
    active_sessions: int
    total_actions_today: int
    actions_by_type: dict
    hourly_activity: list


class NetworkSensorCreate(BaseModel):
    username: str
    ip_address: Optional[str] = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    bandwidth_mbps: float = 0.0
    interface: Optional[str] = None


class NetworkSensorRead(BaseModel):
    id: int
    username: str
    ip_address: Optional[str] = None
    bytes_sent: int
    bytes_recv: int
    bandwidth_mbps: float
    interface: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True
