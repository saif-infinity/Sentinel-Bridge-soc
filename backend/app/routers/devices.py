from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Device
from ..schemas import DeviceCreate, DeviceRead
from ..auth import api_key_auth
from typing import List

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(api_key_auth)])

@router.get("", response_model=List[DeviceRead])
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()

@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
def create_device(device: DeviceCreate, db: Session = Depends(get_db)):
    # Check if IP or MAC already exists
    existing_device = db.query(Device).filter(
        (Device.ip == device.ip) | (Device.mac == device.mac)
    ).first()
    
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset already exists"
        )
    
    new_device = Device(ip=device.ip, mac=device.mac, is_online=True)
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device
    