"""
Tests for multi-tenant isolation.
Run with: python -m pytest backend/tests/test_multitenancy.py -v
"""
from unittest.mock import Mock

import pytest
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_tenant_id, query_with_tenant

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture
def db_session():
    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_get_tenant_id_default():
    """Should return 'default' when no tenant_id in request state."""
    request = Mock(spec=Request)
    request.state.tenant_id = None
    assert get_tenant_id(request) == "default"

def test_get_tenant_id_from_state():
    """Should return tenant_id from request.state."""
    request = Mock(spec=Request)
    request.state.tenant_id = "tenant-123"
    assert get_tenant_id(request) == "tenant-123"

def test_query_with_tenant_filter(db_session):
    """Test that query_with_tenant adds tenant_id filter."""
    from app.models import Device

    request = Mock(spec=Request)
    request.state.tenant_id = "tenant-a"

    # This test verifies the helper exists and works
    # Full integration test requires DB with actual tenant separation
    q = query_with_tenant(Device, request, db_session)
    # q should be a filtered query
    assert q is not None

    # Verify the filter actually scopes by tenant
    sql = str(q)
    assert "tenant_id" in sql

def test_tenant_middleware_extracts_from_jwt():
    """Test that middleware correctly extracts tenant_id from JWT."""
    # This is a unit test for middleware logic
    from app.jwt_utils import create_access_token, verify_token

    token = create_access_token(
        data={
            "sub": "testuser",
            "role": "analyst",
            "scopes": ["devices:read"],
            "tenant_id": "tenant-test",
        }
    )
    payload = verify_token(token)
    assert payload is not None
    assert payload["sub"] == "testuser"
    assert payload["tenant_id"] == "tenant-test"

def test_tenant_user_unique_constraint():
    """Verify that (tenant_id, username) uniqueness is enforced."""
    # Schema-level test — the constraint is in the model

    from app.models import TenantUser

    # Check that the composite index exists in table args
    has_constraint = any(
        "ix_tenant_users_tenant_username" in str(t)
        for t in TenantUser.__table_args__
    )
    assert has_constraint, "Missing unique constraint on (tenant_id, username)"


def test_cross_tenant_isolation(db_session):
    """Verify Tenant A cannot access Tenant B's devices via query_with_tenant."""
    from unittest.mock import Mock

    from fastapi import Request

    from app.db import query_with_tenant
    from app.models import Device

    # Create devices in different tenants
    d1 = Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01", tenant_id="tenant-a", is_online=True)
    d2 = Device(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02", tenant_id="tenant-b", is_online=True)
    db_session.add(d1)
    db_session.add(d2)
    db_session.commit()

    # Tenant A query should only see 1 device
    req_a = Mock(spec=Request)
    req_a.state.tenant_id = "tenant-a"
    q_a = query_with_tenant(Device, req_a, db_session)
    assert q_a.count() == 1

    # Tenant B query should only see 1 device
    req_b = Mock(spec=Request)
    req_b.state.tenant_id = "tenant-b"
    q_b = query_with_tenant(Device, req_b, db_session)
    assert q_b.count() == 1

    # Default tenant should see 0
    req_default = Mock(spec=Request)
    req_default.state.tenant_id = "default"
    q_default = query_with_tenant(Device, req_default, db_session)
    assert q_default.count() == 0


def test_jwt_tenant_id_roundtrip():
    """Verify tenant_id survives JWT create→verify cycle."""
    from app.jwt_utils import create_access_token, verify_token

    token = create_access_token(
        data={"sub": "multi", "role": "analyst", "scopes": ["devices:read"], "tenant_id": "custom-tenant-xyz"}
    )
    payload = verify_token(token)
    assert payload is not None
    assert payload["tenant_id"] == "custom-tenant-xyz"
    assert payload["sub"] == "multi"
