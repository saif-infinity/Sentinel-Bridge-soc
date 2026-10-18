"""IP privée detection — pour TI (jamais requêter) et normalisation."""
import ipaddress


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

_RESERVED_DOC = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def is_private_or_reserved(ip: str) -> bool:
    """True si IP privée, loopback, link-local ou réservée doc."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip.strip())
        # is_private covers RFC1918, is_loopback, is_link_local
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return True
        # Check doc networks explicitly
        for net in _PRIVATE_NETWORKS + _RESERVED_DOC:
            if addr in net:
                return True
        return False
    except ValueError:
        # Malformed IP → treat as private to avoid TI call
        return True


def is_public_ip(ip: str) -> bool:
    """True uniquement pour IP publique routable."""
    return not is_private_or_reserved(ip)
