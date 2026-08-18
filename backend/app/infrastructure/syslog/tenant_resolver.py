"""Resolve syslog source IP to tenant_id. Config-driven mapping."""
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Default: empty mapping. Configured via SYSLOG_TENANT_MAPPINGS env var or API.
# Format: {"192.168.1.0/24": "tenant-a", "10.0.0.0/8": "tenant-b"}
_tenant_map: dict[str, str] = {}
_default_tenant: str = "default"


def configure(mappings: dict[str, str] | None = None, default_tenant: str = "default") -> None:
    """Configure IP→tenant mappings. Called at startup."""
    global _tenant_map, _default_tenant
    _tenant_map = mappings or {}
    _default_tenant = default_tenant
    if _tenant_map:
        logger.info("Syslog tenant mapping: %d CIDR entries, default=%s", len(_tenant_map), _default_tenant)


def resolve_tenant(source_ip: str) -> str:
    """Resolve source IP to tenant_id. Falls back to default tenant."""
    if not _tenant_map:
        return _default_tenant

    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return _default_tenant

    for cidr, tenant_id in _tenant_map.items():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return tenant_id
        except ValueError:
            continue

    return _default_tenant