# projet-pfe-version4/

## Multi-Tenant SaaS Migration — Phase 2 Lane B Complete

### What Lane B covered
- **surveillance.py + surveillance_service.py** — Added `tenant_id` filtering to all AccessLog queries (record_login, record_logout, get_online_users, get_logs, get_stats). Face image storage now tenant-isolated under `face_data/surveillance/{tenant_id}/`.
- **settings.py + system_config_service.py** — Added `tenant_id` parameter to all SystemConfig CRUD operations. Config is now scoped per tenant.
- **tasks.py + worker.py** — Celery tasks (`analyze_threat_task`, `analyze_network_global_task`) now accept `tenant_id` parameter, filter Wazuh/Suricata alerts and Device queries by tenant, and tag IaReports with tenant_id.
- **faces.py + face_service.py** — Face registration/verification storage is now tenant-isolated under `face_data/{tenant_id}/`. `_require_jwt_user` extracts `tenant_id` from JWT payload.
- **database.py** — Added optional `tenant_filter` query parameter to `GET /tables/{name}/rows` for filtering by tenant_id.

### Tenant ID flow
1. `TenantMiddleware` extracts tenant_id from JWT or X-Tenant-ID header → `request.state.tenant_id`
2. Routers call `get_tenant_id(request)` to get the current tenant
3. For DB queries: `query_with_tenant(Model, request, db)` adds `.filter(Model.tenant_id == tenant_id)`
4. For record creation: `tenant_id=get_tenant_id(request)` is passed explicitly
5. Celery workers receive `tenant_id` as a task parameter for filtering DB queries
6. Face data stored in `face_data/{tenant_id}/` directories for isolation
7. Falls back to `"default"` for backward compatibility with single-tenant mode
