import nmap
import socket
import psutil
import logging
import ctypes
import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Device
from ..schemas import ScanResult
from ..auth import api_key_auth
from typing import List, Optional

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan-network", tags=["Scan"], dependencies=[Depends(api_key_auth)])

def get_local_subnet():
    """Helper to detect the active local subnet, avoiding virtual interfaces if possible."""
    try:
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        # Sort interfaces: prefer physical ones that are UP
        potential_ifaces = []
        for interface, addrs in interfaces.items():
            is_up = stats[interface].isup if interface in stats else False
            if not is_up: continue
            
            # Skip common virtual interface names
            if any(virtual in interface.lower() for virtual in ['vbox', 'virtual', 'docker', 'wsl', 'vmware', 'vpn']):
                continue
                
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    potential_ifaces.append((interface, addr.address))
        
        if potential_ifaces:
            # Pick the first "real" looking interface
            interface, ip = potential_ifaces[0]
            parts = ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            logger.info(f"Auto-detected subnet: {subnet} on interface {interface} (IP: {ip})")
            return subnet
            
        for interface, addrs in interfaces.items():
            if any(virtual in interface.lower() for virtual in ['vbox', 'virtual', 'docker', 'wsl', 'vmware', 'vpn']):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    parts = addr.address.split('.')
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception as e:
        logger.error(f"Error detecting subnet: {e}")
    return "192.168.1.0/24" # Fallback

@router.get("", response_model=List[ScanResult])
def scan_network(
    subnet: Optional[str] = None, 
    scan_type: str = "fast", 
    db: Session = Depends(get_db)
):
    if not subnet or subnet == "" or subnet == "undefined" or subnet == "null":
        subnet = get_local_subnet()
        
    is_admin = False
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
         except Exception as e:
             logger.warning(f"Could not check admin privileges: {e}")
    else:
        is_admin = os.getuid() == 0
        
    logger.info(f"Starting Nmap scan on target: {subnet} (Type: {scan_type}, Admin: {is_admin})")
    
    nm = nmap.PortScanner()
    try:
        # Base arguments: -n (No DNS), -T3 (Normal timing for reliability)
        # Increased timeouts and added --privileged to ensure admin features on Windows
        base_args = "-n -T3 --min-parallelism 10 --privileged"
        if not is_admin and os.name == 'nt':
             logger.warning("NOT running as Administrator. Nmap might fail to detect MAC addresses or OS versions.")
             # Remove --privileged if not admin on Windows to avoid error
             base_args = "-n -T4 --min-parallelism 10"
        
        # Check if scanning a single IP or a range
        is_single_ip = "/" not in subnet and subnet.count('.') == 3
        
        # Aggressive discovery probes to find modern firewalled devices (PCs/Mobiles)
        # -PS: TCP SYN discovery, -PU: UDP discovery, -PE/PP: ICMP Echo/Timestamp
        discovery_probes = "-PS22,80,443,3389,8080 -PU161 -PE -PP"
        
        if scan_type == "fast":
            # Discovery: ARP + TCP/UDP probes. We bypass host discovery if it fails by using -Pn logic
            scan_args = f"{base_args} -sn -PR {discovery_probes}"
        elif scan_type == "ports":
            # Treat all hosts as online (-Pn) to find modern firewalled devices
            scan_args = f"{base_args} -Pn -sS -p 1-1000"
        elif scan_type == "services":
            scan_args = f"{base_args} -Pn -sV -sS --version-intensity 5 --host-timeout 180s"
        elif scan_type == "os":
            scan_args = f"{base_args} -Pn -O -sS --host-timeout 180s"
        elif scan_type == "vuln":
            scan_args = f"{base_args} -Pn -sV --script=vuln -sS --host-timeout 600s"
        else:
            scan_args = f"{base_args} -sn -PR {discovery_probes}"

        # If it's a single IP, we force -Pn to bypass host discovery (always scan)
        if is_single_ip:
            scan_args += " -Pn"
            logger.info(f"Single IP detected: forcing -Pn for {subnet}")
        
        logger.info(f"Executing: nmap {scan_args} {subnet}")
        nm.scan(hosts=subnet, arguments=scan_args)
        
        results = []
        known_devices = {d.mac.lower(): d for d in db.query(Device).all()}
        
        for host in nm.all_hosts():
            ip = host
            host_info = nm[host]
            addresses = host_info.get('addresses', {})
            
            # Robust MAC detection
            mac = addresses.get('mac')
            if not mac and 'mac' in host_info: mac = host_info['mac']
            
            mac = (mac or 'UNKNOWN').upper()
            
            # Vendor detection
            vendor = addresses.get('vendor', {}).get(mac, 'N/A')
            if vendor == 'N/A' and 'vendor' in host_info:
                vendor = host_info['vendor'].get(mac, 'N/A')
            
            details = []
            
            # Status check
            state = host_info.get('status', {}).get('state', 'up')
            if state != 'up':
                details.append(f"State: {state}")
            
            # Check if Known
            if mac.lower() in known_devices:
                details.append("Known Employee Asset")
            else:
                details.append("Unknown Device")

            # OS Info
            os_match = host_info.get('osmatch', [])
            if os_match:
                details.append(f"OS: {os_match[0].get('name')}")
            
            # Vendor info (using the robust detection from above)
            if vendor != 'N/A':
                details.append(f"Vendor: {vendor}")

            # Ports info
            found_ports = False
            for proto in host_info.all_protocols():
                lport = host_info[proto].keys()
                for port in lport:
                    found_ports = True
                    service = host_info[proto][port]['name']
                    product = host_info[proto][port].get('product', '')
                    details.append(f"• {port}/{proto}: {service} {product}")
            
            if not found_ports and scan_type in ["ports", "services", "vuln"]:
                details.append("No open ports detected in scanned range")
            
            # Vulnerability findings
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    details.append(f"⚠ {script['id']}: {script['output'][:100]}...")

            if not details:
                details.append("Active Node (No services found)")
            
            results.append(ScanResult(ip=ip, mac=mac, status=details))
            
        logger.info(f"Nmap scan completed. Found {len(results)} active hosts.")
        return results
    except Exception as e:
        logger.error(f"Nmap Scan Failed: {str(e)}")
        return []
