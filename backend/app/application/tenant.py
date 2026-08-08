from fastapi import Request

def get_tenant_id(request: Request) -> str:
    """Extract tenant_id from request.state (set by middleware)."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("get_tenant_id: no tenant_id in request.state, returning 'default'")
        return "default"
    return tenant_id

def query_with_tenant(model, request: Request, db):
    """Create a query filtered by tenant_id."""
    tenant_id = get_tenant_id(request)
    return db.query(model).filter(model.tenant_id == tenant_id)
