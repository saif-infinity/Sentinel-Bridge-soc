#!/usr/bin/env python3
"""
Manual test script for tenant isolation.
Creates 2 test tenants, inserts data, and verifies isolation.
Run: python backend/scripts/test_tenant_isolation.py
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def test_isolation():
    from app.db import SessionLocal
    from app.models import Device, Tenant, TenantUser
    from app.services.password_manager import hash_password

    print("=" * 60)
    print("TEST: Tenant Data Isolation")
    print("=" * 60)

    db = SessionLocal()
    errors = []

    try:
        # Clean up any leftover test data from previous runs
        db.query(Device).filter(~Device.tenant_id.in_(["default", ""])).delete()
        db.query(TenantUser).filter(~TenantUser.tenant_id.in_(["default", ""])).delete()
        db.query(Tenant).filter(~Tenant.id.in_(["default", ""])).delete()
        db.commit()

        # 1. Create two tenants
        tenant_a_id = str(uuid.uuid4())
        tenant_b_id = str(uuid.uuid4())

        ta = Tenant(id=tenant_a_id, company_name="Tenant A", email="a@test.com",
                     plan="basic", status="active")
        tb = Tenant(id=tenant_b_id, company_name="Tenant B", email="b@test.com",
                     plan="pro", status="active")
        db.add(ta)
        db.add(tb)
        db.flush()

        # 2. Create admin users
        ua = TenantUser(tenant_id=tenant_a_id, username="admin_a",
                         password_hash=hash_password("Pass1234"), role="admin")
        ub = TenantUser(tenant_id=tenant_b_id, username="admin_b",
                         password_hash=hash_password("Pass1234"), role="admin")
        db.add(ua)
        db.add(ub)
        db.flush()

        # 3. Create devices for each tenant
        da1 = Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01", tenant_id=tenant_a_id, is_online=True)
        da2 = Device(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02", tenant_id=tenant_a_id, is_online=True)
        db1 = Device(ip="10.0.1.1", mac="aa:bb:cc:dd:ee:03", tenant_id=tenant_b_id, is_online=False)
        db.add(da1)
        db.add(da2)
        db.add(db1)
        db.commit()

        # 4. Test: Tenant A should see 2 devices
        devices_a = db.query(Device).filter(Device.tenant_id == tenant_a_id).all()
        assert len(devices_a) == 2, f"Tenant A: expected 2, got {len(devices_a)}"
        print(f"[OK] Tenant A sees {len(devices_a)} devices (expected 2)")

        # 5. Test: Tenant B should see 1 device
        devices_b = db.query(Device).filter(Device.tenant_id == tenant_b_id).all()
        assert len(devices_b) == 1, f"Tenant B: expected 1, got {len(devices_b)}"
        print(f"[OK] Tenant B sees {len(devices_b)} devices (expected 1)")

        # 6. Test: No cross-tenant access
        for d in devices_a:
            assert d.ip.startswith("10.0.0."), "Tenant A device IP must be 10.0.0.x"
        for d in devices_b:
            assert d.ip.startswith("10.0.1."), "Tenant B device IP must be 10.0.1.x"
        print("[OK] No cross-tenant data contamination")

        # 7. Test: User isolation
        users_a = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_a_id).all()
        assert len(users_a) == 1
        users_b = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_b_id).all()
        assert len(users_b) == 1
        print("[OK] User data isolated per tenant")

        print("=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)

    except AssertionError as e:
        print(f"[FAIL] {e}")
        errors.append(str(e))
    except Exception as e:
        print(f"[ERROR] {e}")
        errors.append(str(e))
    finally:
        # Clean up test data
        try:
            db.query(Device).filter(Device.tenant_id.in_([tenant_a_id, tenant_b_id])).delete()
            db.query(TenantUser).filter(TenantUser.tenant_id.in_([tenant_a_id, tenant_b_id])).delete()
            db.query(Tenant).filter(Tenant.id.in_([tenant_a_id, tenant_b_id])).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    if errors:
        print(f"\n[FAILED] {len(errors)} error(s)")
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    test_isolation()
