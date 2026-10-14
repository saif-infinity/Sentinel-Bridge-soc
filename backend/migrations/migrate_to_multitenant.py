#!/usr/bin/env python3
"""
Migration Script: Single-tenant → Multi-tenant
Creates a "default" tenant and migrates all existing data.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal
from app.models import (
    AccessLog,
    ActionLog,
    Alert,
    Asset,
    ConnectionLog,
    Device,
    IaReport,
    NetworkDevice,
    NetworkSensor,
    SuricataAlert,
    SystemConfig,
    Tenant,
    TenantUser,
)
from app.services.password_manager import _read_store


def migrate():
    print("=" * 60)
    print("MIGRATION: Single-Tenant → Multi-Tenant")
    print("=" * 60)

    db = SessionLocal()
    try:
        # Step 1: Create default tenant if not exists
        existing = db.query(Tenant).filter(Tenant.id == "default").first()
        if existing:
            print("[SKIP] Default tenant already exists")
            default_tenant = existing
        else:
            default_tenant = Tenant(
                id="default",
                company_name="Default",
                email="admin@sentinelbridge.local",
                plan="enterprise",
                status="active",
                max_agents=999,
                max_endpoints=999,
                retention_days=365,
            )
            db.add(default_tenant)
            db.flush()
            print("[OK] Created default tenant")

        # Step 2: Update all existing records to tenant_id="default"
        models = [
            Device, ConnectionLog, SuricataAlert,
            Asset, Alert, IaReport, AccessLog, ActionLog,
            SystemConfig, NetworkSensor, NetworkDevice
        ]

        for model in models:
            from sqlalchemy import or_
            count = db.query(model).filter(or_(model.tenant_id == None, model.tenant_id == "")).count()
            if count > 0:
                db.query(model).filter(or_(model.tenant_id == None, model.tenant_id == "")).update(
                    {"tenant_id": "default"}, synchronize_session=False
                )
                print(f"[MIGRATED] {model.__tablename__}: {count} records → tenant_id='default'")
            else:
                print(f"[OK] {model.__tablename__}: clean")

        db.flush()

        # Step 3: Migrate passwords from JSON file to TenantUser table
        password_store = _read_store()
        migrated = 0
        for key, pwd_hash in password_store.items():
            if key.startswith("user:"):
                username = key.replace("user:", "", 1)
                existing_user = db.query(TenantUser).filter(
                    TenantUser.username == username,
                    TenantUser.tenant_id == "default"
                ).first()
                if not existing_user:
                    # Read role from JSON store

                    from app.services.password_manager import _read_store as read_store
                    role_store = read_store()
                    role = role_store.get(f"role:{username}", "analyst")

                    user = TenantUser(
                        tenant_id="default",
                        username=username,
                        password_hash=pwd_hash,
                        role=role,
                        is_active=True,
                    )
                    db.add(user)
                    migrated += 1

        db.flush()
        if migrated:
            print(f"[MIGRATED] {migrated} password hashes → TenantUser table")
        else:
            print("[OK] No password hashes to migrate")

        # Step 4: Remove unique=False on IP/MAC columns if needed
        # (Already handled in models.py schema change)

        db.commit()
        print("=" * 60)
        print("MIGRATION COMPLETE!")
        print("=" * 60)

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Migration failed: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate()
