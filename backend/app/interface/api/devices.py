from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from ...db import get_db, get_tenant_id, query_with_tenant
from ...models import Device, Asset, SuricataAlert
from ...schemas import DeviceCreate, DeviceRead, AssetRead, AssetCreate
from ...auth import has_scopes_or_api_key
from typing import List, Optional
import json

router = APIRouter(prefix="/devices", tags=["devices"])

@router.get("", response_model=List[DeviceRead], dependencies=[Depends(has_scopes_or_api_key(["devices:read"]))])
def list_devices(request: Request, db: Session = Depends(get_db)):
    return query_with_tenant(Device, request, db).all()

@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED, dependencies=[Depends(has_scopes_or_api_key(["devices:write"]))])
def create_device(request: Request, device: DeviceCreate, db: Session = Depends(get_db)):
    # Check if IP or MAC already exists (scoped by tenant)
    existing_device = query_with_tenant(Device, request, db).filter(
        (Device.ip == device.ip) | (Device.mac == device.mac)
    ).first()
    
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset already exists"
        )
    
    new_device = Device(ip=device.ip, mac=device.mac, is_online=True, tenant_id=get_tenant_id(request))
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device

# Inventory Center - Combined Assets + Devices
@router.get("/inventory", response_model=List[AssetRead], dependencies=[Depends(has_scopes_or_api_key(["devices:read"]))])
def get_inventory(request: Request, db: Session = Depends(get_db)):
    """
    Retourne l'inventaire enrichi : tous les Device de la DB,
    complétés avec les infos Asset (employé, département) si disponibles.
    Retourne toujours les données même si la table Asset est vide.
    """
    # Charger tout en une seule passe (scoped by tenant)
    all_devices = query_with_tenant(Device, request, db).all()
    all_assets  = query_with_tenant(Asset, request, db).all()

    # Indexer les assets par IP pour lookup O(1)
    asset_by_ip = {a.ip: a for a in all_assets}
    # Suivre les IPs déjà traitées
    seen_ips = set()
    result = []

    # Calculer la bande passante par IP depuis les flows Suricata (scoped by tenant)
    bw_in = {}
    bw_out = {}
    flow_alerts = query_with_tenant(SuricataAlert, request, db).filter(SuricataAlert.event_type == "flow").all()
    for alert in flow_alerts:
        if not alert.payload:
            continue
        try:
            data = json.loads(alert.payload)
            flow = data.get("flow") or data
            bytes_toclient = int(flow.get("bytes_toclient", 0))
            bytes_toserver = int(flow.get("bytes_toserver", 0))
            src = alert.src_ip
            dst = alert.dest_ip
            if src:
                bw_out[src] = bw_out.get(src, 0) + bytes_toserver
                bw_in[src] = bw_in.get(src, 0) + bytes_toclient
            if dst:
                bw_out[dst] = bw_out.get(dst, 0) + bytes_toclient
                bw_in[dst] = bw_in.get(dst, 0) + bytes_toserver
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    # 1. Parcourir tous les devices (source principale)
    for device in all_devices:
        ip = device.ip or ""
        seen_ips.add(ip)
        asset = asset_by_ip.get(ip)
        result.append(AssetRead(
            id=device.id,
            ip=ip,
            employee_name=asset.employee_name if asset else "Unknown",
            department=asset.department    if asset else "Unassigned",
            mac=device.mac,
            is_online=device.is_online,
            is_wazuh_agent=device.is_wazuh_agent,
            bandwidth_in=round(bw_in.get(ip, 0) / (1024 * 1024), 2),
            bandwidth_out=round(bw_out.get(ip, 0) / (1024 * 1024), 2),
        ))

    # 2. Ajouter les assets sans device correspondant (orphelins)
    for asset in all_assets:
        ip = asset.ip
        if ip not in seen_ips:
            result.append(AssetRead(
                id=asset.id,
                ip=ip,
                employee_name=asset.employee_name,
                department=asset.department,
                mac=None,
                is_online=False,
                is_wazuh_agent=False,
                bandwidth_in=round(bw_in.get(ip, 0) / (1024 * 1024), 2),
                bandwidth_out=round(bw_out.get(ip, 0) / (1024 * 1024), 2),
            ))

    return result

@router.post("/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED, dependencies=[Depends(has_scopes_or_api_key(["devices:write"]))])
def create_asset(request: Request, asset: AssetCreate, db: Session = Depends(get_db)):
    """Create or update an asset (employee mapping)"""
    existing = query_with_tenant(Asset, request, db).filter(Asset.ip == asset.ip).first()
    if existing:
        existing.employee_name = asset.employee_name
        existing.department = asset.department
        db.commit()
        db.refresh(existing)
        return existing
    
    new_asset = Asset(**asset.model_dump(), tenant_id=get_tenant_id(request))
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    return new_asset