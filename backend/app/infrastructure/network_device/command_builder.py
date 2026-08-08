from typing import Any, Optional, Dict, List

def _sec(c, *lines):
    """Collect non-empty lines."""
    return [l for l in lines if l]


def _CiscoIOS_cmds(c: dict, device_type: str = "switch") -> list:
    """Cisco IOS / IOS-XE / IOS-XR style commands (also Arista EOS, Aruba, Dell OS9/OS10, Netgear)."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    # System
    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"hostname {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    gateway = sys_.get("gateway", "")
    if gateway:
        cmds.append(f"ip default-gateway {gateway}")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"ip name-server {dns}")

    # Terminal
    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.extend(["line console 0", f" password {console_pw}", " login", "exit"])
    timeout = term.get("exec_timeout", "10")
    if timeout and timeout != "0":
        cmds.extend(["line console 0", f" exec-timeout {timeout} 0", "exit"])
    banner = term.get("banner", "")
    if banner:
        cmds.extend([f"banner motd ^{banner}^"])
    if term.get("password_encryption", False):
        cmds.append("service password-encryption")
    if term.get("aaa_new_model", False):
        cmds.append("aaa new-model")

    # Logging
    log_level = term.get("logging_level", "informational")
    log_map = {
        "emergencies": "0", "alerts": "1", "critical": "2", "errors": "3",
        "warnings": "4", "notifications": "5", "informational": "6", "debugging": "7",
    }
    if log_level in log_map:
        cmds.append(f"logging {log_map[log_level]}")

    # Security
    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"enable password {enable_pw}")
    if sec.get("telnet_disable", False):
        cmds.extend(["line vty 0 15", " transport input ssh", "exit"])
    port_sec = sec.get("port_security", 0)
    if port_sec and device_type == "switch":
        cmds.append(f"switchport port-security maximum {port_sec}")

    # Switch-specific
    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"vlan {vid}")
                if vname:
                    cmds.append(f" name {vname}")
                cmds.append("exit")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            shutdown = p.get("shutdown", False)
            if iface:
                cmds.append(f"interface {iface}")
                if desc:
                    cmds.append(f" description {desc}")
                if mode:
                    cmds.append(f" switchport mode {mode}")
                if vlan and mode == "access":
                    cmds.append(f" switchport access vlan {vlan}")
                if shutdown:
                    cmds.append(" shutdown")
                cmds.append("exit")
    else:
        # Router-specific
        rt = c.get("Routage", {})
        if rt.get("ospf_enable", False):
            area = rt.get("ospf_area", "0")
            cmds.append("router ospf 1")
            networks = rt.get("ospf_networks", "")
            if networks:
                for net in networks.strip().split("\n"):
                    net = net.strip()
                    if net:
                        cmds.append(f" network {net} area {area}")
            cmds.append("exit")
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    cmds.append(f"ip route {route}")
        if rt.get("dhcp_enable", False):
            cmds.append("ip dhcp pool LAN")
            cmds.append(" exit")

        # NAT
        nat = c.get("NAT / PAT", {})
        if nat.get("nat_enable", False):
            cmds.append(f"interface {nat.get('nat_outside', 'GigabitEthernet0/1')}")
            cmds.append(" ip nat outside")
            cmds.append("exit")
            cmds.append(f"interface {nat.get('nat_inside', 'GigabitEthernet0/0')}")
            cmds.append(" ip nat inside")
            cmds.append("exit")
            if nat.get("nat_overload", True):
                cmds.append("ip nat inside source list NAT_INTERFACE interface GigabitEthernet0/1 overload")

    return cmds


def _CiscoIOS_sec(c, cmds):
    """Shared security commands for IOS-like brands."""
    sec = c.get("Sécurité", {})
    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"enable password {enable_pw}")
    if sec.get("telnet_disable", False):
        cmds.extend(["line vty 0 15", " transport input ssh", "exit"])
    port_sec = sec.get("port_security", 0)
    if port_sec:
        cmds.append(f"switchport port-security maximum {port_sec}")
    if sec.get("ssh_enable", False):
        cmds.extend(["ip domain-name lab.local", "crypto key generate rsa modulus 2048", "ip ssh version 2"])
    return cmds


def _mikrotik_cmds(c: dict, device_type: str = "switch") -> list:
    """MikroTik RouterOS commands."""
    cmds = []
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname") or sys_.get("identity", "")
    if hostname:
        cmds.append(f"/system identity set name={hostname}")

    # Terminal
    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.extend(["/user set admin password=" + console_pw])
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"/system note set note=\"{banner}\"")
    timeout = term.get("exec_timeout", "10")
    if timeout and timeout != "0":
        cmds.append(f"/user set admin session-timeout={timeout}")

    sec = c.get("Sécurité", {})
    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"/user set admin password={enable_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("/ip ssh set always-allow-password-login=yes")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            iface = v.get("interface", "")
            if vid:
                cmds.append(f"/interface vlan add name={vname or 'vlan' + vid} vlan-id={vid}" + (f" interface={iface}" if iface else ""))
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            pvid = p.get("pvid", "")
            shutdown = p.get("shutdown", False)
            if iface:
                if desc:
                    cmds.append(f"/interface set {iface} comment=\"{desc}\"")
                if shutdown:
                    cmds.append(f"/interface disable {iface}")
                if mode == "access" and vlan:
                    cmds.append(f"/interface ethernet set {iface} vlan-mode=access vlan={vlan}")
                elif mode == "trunk":
                    cmds.append(f"/interface ethernet set {iface} vlan-mode=tagged vlan={vlan or ''}")
                if pvid:
                    cmds.append(f"/interface ethernet set {iface} vlan-mode=access vlan={pvid}")
    else:
        rt = c.get("Routage", {})
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    parts = route.split()
                    if len(parts) >= 3:
                        cmds.append(f"/ip route add dst-address={parts[0]} gateway={parts[2]}")
        if rt.get("dhcp_enable", False):
            cmds.append("/ip dhcp-server setup")

    return cmds


def _huawei_vrp_cmds(c: dict, device_type: str = "switch") -> list:
    """Huawei VRP commands (similar to Cisco IOS but Huawei syntax)."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"sysname {hostname}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.extend(["user-interface console 0", f" authentication-mode password", f" set authentication password cipher {console_pw}", "quit"])

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.extend([f"super password level 3 cipher {enable_pw}"])
    if sec.get("ssh_enable", False):
        cmds.extend(["stelnet server enable", "rsa local-key-pair create", "user-interface vty 0 4", " protocol inbound ssh", "quit"])

    banner = term.get("banner", "")
    if banner:
        cmds.append(f"header shell information \"{banner}\"")
    if term.get("password_encryption", False):
        cmds.append("undo telnet server enable")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"vlan {vid}")
                if vname:
                    cmds.append(f" description {vname}")
                cmds.append("quit")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            shutdown = p.get("shutdown", False)
            if iface:
                cmds.extend([f"interface {iface}"])
                if desc:
                    cmds.append(f" description {desc}")
                if mode == "access":
                    cmds.extend([" port link-type access", f" port default vlan {vlan or '1'}"])
                elif mode == "trunk":
                    cmds.extend([" port link-type trunk", f" port trunk allow-pass vlan {vlan or 'all'}"])
                elif mode == "hybrid":
                    cmds.extend([" port link-type hybrid"])
                if shutdown:
                    cmds.append(" shutdown")
                cmds.append("quit")
    else:
        rt = c.get("Routage", {})
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    cmds.append(f"ip route-static {route}")
        if rt.get("ospf_enable", False):
            cmds.extend(["ospf 1", " area 0.0.0.0", "  quit", "quit"])

    return cmds


def _juniper_junos_cmds(c: dict, device_type: str = "switch") -> list:
    """Juniper JunOS set-style commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"set system host-name {hostname}")
    domain = sys_.get("domain_name", "")
    if domain:
        cmds.append(f"set system domain-name {domain}")
    ntp = sys_.get("ntp_server", "")
    if ntp:
        cmds.append(f"set system ntp server {ntp}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"set system root-authentication plain-text-password-value {console_pw}")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"set system login message \"{banner}\"")

    root_pw = sec.get("root_password", "")
    if root_pw:
        cmds.append(f"set system root-authentication plain-text-password-value {root_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("set system services ssh")
    if sec.get("telnet_disable", False):
        cmds.append("delete system services telnet")
    if sec.get("netconf_enable", False):
        cmds.append("set system services netconf ssh")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"set vlans {vname or 'vlan' + vid} vlan-id {vid}")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            if iface:
                if mode == "access" and vlan:
                    cmds.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode access vlan members vlan{vlan}")
                elif mode == "trunk":
                    cmds.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode trunk vlan members all")
                if desc:
                    cmds.append(f"set interfaces {iface} description \"{desc}\"")
    else:
        rt = c.get("Routage", {})
        if rt.get("ospf_enable", False):
            area = rt.get("ospf_area", "0")
            cmds.extend([
                f"set protocols ospf area {area}",
                f"set protocols ospf area {area} interface all"
            ])
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    cmds.append(f"set routing-options static route {route}")
        if rt.get("bgp_enable", False):
            bgp_as = rt.get("bgp_as", "")
            if bgp_as:
                cmds.append(f"set protocols bgp group external type external")
                cmds.append(f"set protocols bgp group external local-as {bgp_as}")

    return cmds


def _fortinet_fortios_cmds(c: dict, device_type: str = "switch") -> list:
    """Fortinet FortiOS commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"config system global\n    set hostname {hostname}\nend")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"config system global\n    set admin-password {console_pw}\nend")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"config system global\n    set admin-motd \"{banner}\"\nend")

    admin_pw = sec.get("admin_password", "")
    if admin_pw:
        cmds.append(f"config system admin\n    edit admin\n    set password {admin_pw}\n    next\nend")
    if sec.get("ssh_enable", False):
        cmds.append("config system global\n    set admin-ssh-grace-time 120\nend")

    if device_type == "switch":
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            if iface:
                cmds.append(f"config system interface\n    edit {iface}")
                if desc:
                    cmds.append(f"    set description \"{desc}\"")
                cmds.append("    next\nend")
    else:
        if sec.get("vpn_enable", False):
            cmds.append("config vpn ipsec phase1-interface\nend")
        if sec.get("ips_enable", False):
            cmds.append("config ips global\n    set engine-mode inline\nend")
        if sec.get("av_enable", False):
            cmds.append("config antivirus profile\nend")
        rt = c.get("Routage", {})
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    cmds.append(f"config router static\n    edit 0\n        set dst {route}\n    next\nend")

    return cmds


def _paloalto_cmds(c: dict, device_type: str = "switch") -> list:
    """Palo Alto PAN-OS commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"set deviceconfig system hostname {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"set deviceconfig system ip-address {mgmt_ip}")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"set deviceconfig system dns-primary {dns}")
    ntp = sys_.get("ntp_server", "")
    if ntp:
        cmds.append(f"set deviceconfig system ntp-servers {ntp}")
    tz = sys_.get("timezone", "")
    if tz:
        cmds.append(f"set deviceconfig system timezone {tz}")

    admin_pw = sec.get("admin_password", "")
    if admin_pw:
        cmds.append(f"set mgt-config users admin password '{admin_pw}'")
    if sec.get("ssh_enable", False):
        cmds.append("set deviceconfig system services ssh")
    nat_rules = sec.get("nat_rules", "")
    if nat_rules:
        for i, rule in enumerate(nat_rules.strip().split("\n"), 1):
            rule = rule.strip()
            if rule:
                cmds.append(f"set rulebase nat rules {rule}")
    sec_rules = sec.get("security_rules", "")
    if sec_rules:
        for rule in sec_rules.strip().split("\n"):
            rule = rule.strip()
            if rule:
                cmds.append(f"set rulebase security rules {rule}")
    if sec.get("threat_enable", False):
        cmds.append("set profiles vulnerability-protection default setting block-critical yes")
    if sec.get("wildfire_enable", False):
        cmds.append("set profiles wildfire-analysis file-type any action alert")
    if sec.get("url_filter_enable", False):
        cmds.append("set profiles url-filtering credential-enforcement enabled yes")
    if sec.get("globalprotect_enable", False):
        cmds.append("set global-protect global-portal-configs default")

    return cmds


def _sonicwall_cmds(c: dict, device_type: str = "switch") -> list:
    """SonicWall SonicOS CLI commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"ip host-name {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"interface management0 ip address {mgmt_ip} 255.255.255.0")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"dns name-server {dns}")

    admin_pw = sec.get("admin_password", "")
    if admin_pw:
        cmds.append(f"admin user password {admin_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("ssh")
    if sec.get("gav_enable", False):
        cmds.append("gateway-antivirus enable")
    if sec.get("ips_enable", False):
        cmds.append("ips enable")
    if sec.get("vpn_enable", False):
        cmds.append("vpn policy")
    if sec.get("content_filter_enable", False):
        cmds.append("content-filter enable")

    return cmds


def _extreme_exos_cmds(c: dict, device_type: str = "switch") -> list:
    """Extreme Networks EXOS commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"configure sysname {hostname}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"configure password {console_pw}")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"configure banner \"{banner}\"")

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"configure password {enable_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("enable ssh")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"create vlan {vname or 'vlan' + vid} tag {vid}")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            if iface:
                if mode == "access" and vlan:
                    cmds.append(f"configure {iface} tag {vlan}")
                elif mode == "tagged":
                    cmds.append(f"configure {iface} tag add {vlan or ''}")
                elif mode == "untagged":
                    cmds.append(f"configure {iface} untagged {vlan or ''}")

    return cmds


def _ubiquiti_cmds(c: dict, device_type: str = "switch") -> list:
    """Ubiquiti EdgeOS / UniFi CLI commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"set system host-name {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"set interfaces ethernet eth0 address {mgmt_ip}")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"set system name-server {dns}")
    ntp = sys_.get("ntp_server", "")
    if ntp:
        cmds.append(f"set system ntp server {ntp}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"set system login user admin authentication plaintext-password {console_pw}")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"set system login banner pre-login \"{banner}\"")
    timeout = term.get("exec_timeout", "10")
    if timeout and timeout != "0":
        cmds.append(f"set system login session-timeout {timeout}")

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"set system login user admin authentication plaintext-password {enable_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("set service ssh port 22")
    if sec.get("firewall_enable", False):
        cmds.append("set firewall name INBOUND rule 10 action drop")
    if sec.get("vpn_enable", False):
        cmds.append("set vpn ipsec")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"set interfaces vlan vif{vid} description {vname or 'vlan' + vid}")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            if iface:
                if desc:
                    cmds.append(f"set interfaces ethernet {iface} description \"{desc}\"")
                if mode == "access" and vlan:
                    cmds.append(f"set interfaces ethernet {iface} switch-port access vlan {vlan}")
                elif mode == "trunk":
                    cmds.append(f"set interfaces ethernet {iface} switch-port mode trunk")
    else:
        rt = c.get("Routage", {})
        static = rt.get("static_routes", "")
        if static:
            for route in static.strip().split("\n"):
                route = route.strip()
                if route:
                    cmds.append(f"set protocols static route {route}")
        if rt.get("ospf_enable", False):
            cmds.append("set protocols ospf area 0")
        if rt.get("dhcp_enable", False):
            cmds.append("set service dhcp-server shared-network-name")
        dhcp_range = rt.get("dhcp_range", "")
        if dhcp_range:
            cmds.append(f"set service dhcp-server shared-network-name LAN subnet start {dhcp_range}")

    return cmds


def _dlink_cmds(c: dict, device_type: str = "switch") -> list:
    """D-Link DGS/DES CLI commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"create system name {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"create ipif System1 ipaddress {mgmt_ip} state enable")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"create dns host serverip {dns}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"config account admin {console_pw}")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"create banner \"{banner}\"")

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"config account admin {enable_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("config sshd state enable")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"create vlan {vname or 'vlan' + vid} vlanid {vid} tag {vid}")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            if iface:
                if mode == "access" and vlan:
                    cmds.append(f"config vlan {vlan} add untagged {iface}")
                elif mode == "trunk":
                    cmds.append(f"config vlan 1 add tagged {iface}")

    return cmds


def _tplink_cmds(c: dict, device_type: str = "switch") -> list:
    """TP-Link JetStream CLI commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"system name {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"interface vlan 1 ip address {mgmt_ip} 255.255.255.0")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"ip name-server {dns}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"username admin password {console_pw}")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"banner motd \"{banner}\"")

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"enable password level 15 {enable_pw}")
    if sec.get("ssh_enable", False):
        cmds.append("ip ssh server enable")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"vlan {vid}")
                if vname:
                    cmds.append(f" name {vname}")
                cmds.append("exit")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            if iface:
                cmds.append(f"interface {iface}")
                if desc:
                    cmds.append(f" description {desc}")
                if mode == "access":
                    cmds.append(f" switchport access vlan {vlan or '1'}")
                elif mode == "trunk":
                    cmds.append(" switchport mode trunk")
                cmds.append("exit")

    return cmds


def _zyxel_cmds(c: dict, device_type: str = "switch") -> list:
    """ZyXEL ZLD/ELS CLI commands."""
    cmds = []
    sec = c.get("Sécurité", {})
    sys_ = c.get("Système", {})
    term = c.get("terminal", {})

    hostname = sys_.get("hostname", "")
    if hostname:
        cmds.append(f"system name {hostname}")
    mgmt_ip = sys_.get("mgmt_ip", "")
    if mgmt_ip:
        cmds.append(f"ip interface vlan 1 address {mgmt_ip} mask 255.255.255.0")
    dns = sys_.get("dns_server", "")
    if dns:
        cmds.append(f"ip dns server-address {dns}")

    console_pw = term.get("console_password", "")
    if console_pw:
        cmds.append(f"username admin password \"{console_pw}\"")
    banner = term.get("banner", "")
    if banner:
        cmds.append(f"banner motd \"{banner}\"")

    enable_pw = sec.get("enable_password", "")
    if enable_pw:
        cmds.append(f"enable password \"{enable_pw}\"")
    if sec.get("ssh_enable", False):
        cmds.append("ip ssh server enable")

    if device_type == "switch":
        vlans = c.get("vlans", [])
        for v in vlans:
            vid = v.get("vlan_id", "")
            vname = v.get("name", "")
            if vid:
                cmds.append(f"vlan {vname or 'vlan' + vid} vlan-id {vid}")
        ports = c.get("ports", [])
        for p in ports:
            iface = p.get("interface", "")
            mode = p.get("mode", "")
            vlan = p.get("vlan", "")
            desc = p.get("description", "")
            if iface:
                cmds.append(f"interface {iface}")
                if desc:
                    cmds.append(f" description {desc}")
                if mode == "access":
                    cmds.append(f" switchport pvid {vlan or '1'}")
                elif mode == "trunk":
                    cmds.append(" switchport mode trunk")
                cmds.append("exit")

    return cmds


# ═══════════════════════════════════════════════════════════════════
# Dispatch
# ═══════════════════════════════════════════════════════════════════

_GENERATORS = {
    "cisco":    _CiscoIOS_cmds,
    "arista":   _CiscoIOS_cmds,
    "aruba":    _CiscoIOS_cmds,
    "dell":     _CiscoIOS_cmds,
    "netgear":  _CiscoIOS_cmds,
    "mikrotik": _mikrotik_cmds,
    "huawei":   _huawei_vrp_cmds,
    "juniper":  _juniper_junos_cmds,
    "fortinet": _fortinet_fortios_cmds,
    "paloalto": _paloalto_cmds,
    "sonicwall": _sonicwall_cmds,
    "ubiquiti": _ubiquiti_cmds,
    "extreme":  _extreme_exos_cmds,
    "dlink":    _dlink_cmds,
    "tplink":   _tplink_cmds,
    "zyxel":    _zyxel_cmds,
}


def generate_commands(config: dict, device_type: str, brand: str) -> list:
    """Generate CLI command list from wizard config."""
    gen = _GENERATORS.get(brand)
    if not gen:
        return [f"# No generator for brand: {brand}"]
    cmds = gen(config, device_type)
    cmds.extend(_advanced_cmds(config, device_type, brand))
    return cmds


def _advanced_cmds(config: dict, device_type: str, brand: str) -> list:
    """Generate CLI commands for advanced configuration sections (shared across brands)."""
    cmds = []
    cisco_like = brand in ("cisco", "arista", "aruba", "dell", "netgear", "extreme")

    # ─── Switch: QoS ───
    qos = config.get("qos", {})
    if qos.get("bandwidth_limit"):
        if cisco_like:
            cmds.extend([
                f"policy-map QOS_POLICY",
                f" class class-default",
                f"  shape average {qos['bandwidth_limit']}000000",
                f"exit",
            ])
        elif brand == "mikrotik":
            cmds.append(f"/interface set [find] max-limit={qos['bandwidth_limit']}M")
        elif brand == "huawei":
            cmds.append(f"qos car outbound cir {qos['bandwidth_limit']}000")
    if qos.get("priority_queue") and qos["priority_queue"] != "normal":
        if cisco_like:
            cmds.append(f"priority-queue out")
    if qos.get("dscp_marking"):
        if cisco_like:
            cmds.extend(["class-map match-all DSCP_MARK", " match dscp af11", "exit",
                         "policy-map DSCP_POLICY", " class DSCP_MARK", "  set dscp af21", "exit"])

    # ─── Switch: Storm Control ───
    storm = config.get("storm_control", {})
    if storm.get("broadcast_threshold"):
        if cisco_like:
            cmds.append(f"storm-control broadcast level {storm['broadcast_threshold']}")
        elif brand == "huawei":
            cmds.append(f"storm suppression broadcast packets {storm['broadcast_threshold']}")
    if storm.get("multicast_threshold"):
        if cisco_like:
            cmds.append(f"storm-control multicast level {storm['multicast_threshold']}")
    if storm.get("unicast_threshold"):
        if cisco_like:
            cmds.append(f"storm-control unicast level {storm['unicast_threshold']}")

    # ─── Switch: Spanning Tree ───
    stp = config.get("spanning_tree", {})
    if stp.get("stp_mode"):
        mode_map = {"stp": "pvst", "rstp": "rapid-pvst", "mstp": "mst", "pvst": "pvst"}
        if cisco_like:
            cmds.append(f"spanning-tree mode {mode_map.get(stp['stp_mode'], 'rapid-pvst')}")
        elif brand == "huawei":
            cmds.append(f"stp mode {stp['stp_mode']}")
        elif brand == "mikrotik":
            cmds.append(f"/interface bridge set [find] protocol={stp['stp_mode']}")
    if stp.get("stp_priority") is not None:
        if cisco_like:
            cmds.append(f"spanning-tree vlan 1 priority {stp['stp_priority']}")
        elif brand == "huawei":
            cmds.append(f"stp priority {stp['stp_priority']}")
    if stp.get("portfast"):
        if cisco_like:
            cmds.append("spanning-tree portfast")
    if stp.get("bpduguard"):
        if cisco_like:
            cmds.append("spanning-tree bpduguard enable")

    # ─── Switch: SNMP / Monitoring ───
    snmp = config.get("snmp_monitoring", {})
    if snmp.get("snmp_enable"):
        if cisco_like:
            cmds.extend(["snmp-server community public RO", "snmp-server enable traps"])
        elif brand == "mikrotik":
            cmds.append("/snmp set enabled=yes")
        elif brand == "huawei":
            cmds.extend(["snmp-agent", "snmp-agent community read public"])
    if snmp.get("snmp_trap_server"):
        if cisco_like:
            cmds.append(f"snmp-server host {snmp['snmp_trap_server']} version 2c public")
    if snmp.get("syslog_server"):
        if cisco_like:
            cmds.append(f"logging host {snmp['syslog_server']}")
        elif brand == "mikrotik":
            cmds.append(f"/system logging action remote remote={snmp['syslog_server']}")
    if snmp.get("ntp_server"):
        if cisco_like:
            cmds.append(f"ntp server {snmp['ntp_server']}")
        elif brand == "mikrotik":
            cmds.append(f"/system ntp client set enabled=yes primary-ntp-server={snmp['ntp_server']}")
    if snmp.get("netflow_enable"):
        if cisco_like:
            cmds.extend(["flow exporter EXPORT", " destination 10.0.0.100", "exit",
                         "flow monitor MONITOR", " exporter EXPORT", "exit"])

    # ─── Switch: Link Aggregation (LACP) ───
    lag = config.get("link_aggregation", {})
    if lag.get("lag_enabled"):
        if cisco_like:
            cmds.extend(["interface Port-channel1", "exit"])
            for iface in (lag.get("lag_interfaces") or "").strip().split("\n"):
                iface = iface.strip()
                if iface:
                    cmds.extend([f"interface {iface}", " channel-group 1 mode active", "exit"])
        elif brand == "huawei":
            cmds.append("interface Eth-Trunk 1")
            for iface in (lag.get("lag_interfaces") or "").strip().split("\n"):
                iface = iface.strip()
                if iface:
                    cmds.append(f" trunkport {iface}")
            cmds.append("quit")
        elif brand == "mikrotik":
            cmds.extend(["/interface bridge add name=lag1", "/interface bridge port"])

    # ─── Router: VPN ───
    vpn = config.get("vpn", {})
    if vpn.get("vpn_enable"):
        peer = vpn.get("vpn_peer_ip", "")
        psk = vpn.get("vpn_pre_shared_key", "")
        enc = vpn.get("vpn_encryption", "aes-256")
        if cisco_like:
            cmds.extend([
                f"crypto isakmp policy 10",
                f" encryption {enc}",
                f" authentication pre-share",
                f"exit",
                f"crypto isakmp key {psk} address {peer}",
                f"crypto ipsec transform-set VPN_SET esp-{enc.replace('-','')}",
                f"exit",
                f"crypto map VPN_MAP 10 ipsec-isakmp",
                f" set peer {peer}",
                f" set transform-set VPN_SET",
                f"exit",
            ])
        elif brand == "mikrotik":
            cmds.extend([f"/ip ipsec proposal add name=vpn-proposal auth-algorithms=sha256 enc-algorithms={enc}"])
        elif brand == "huawei":
            cmds.extend([f"ike proposal 1", f" encryption-algorithm {enc}", f"exit"])
    if vpn.get("gre_enable") and vpn.get("tunnel_interface"):
        if cisco_like:
            tun = vpn["tunnel_interface"]
            cmds.extend([f"interface {tun}", " tunnel mode gre ip", "exit"])

    # ─── Router: BGP ───
    bgp = config.get("bgp", {})
    if bgp.get("bgp_enable"):
        asn = bgp.get("bgp_as", "")
        router_id = bgp.get("bgp_router_id", "")
        if asn:
            if cisco_like:
                cmds.extend([f"router bgp {asn}"])
                if router_id:
                    cmds.append(f" bgp router-id {router_id}")
                for n in (bgp.get("bgp_neighbors") or "").strip().split("\n"):
                    n = n.strip()
                    if n:
                        parts = n.split()
                        if len(parts) >= 2:
                            cmds.append(f" neighbor {parts[0]} remote-as {parts[1]}")
                for net in (bgp.get("bgp_networks") or "").strip().split("\n"):
                    net = net.strip()
                    if net:
                        cmds.append(f" network {net}")
                redist = bgp.get("bgp_redistribute", "none")
                if redist and redist != "none":
                    cmds.append(f" redistribute {redist}")
                cmds.append("exit")
            elif brand == "mikrotik":
                cmds.extend([f"/routing bgp instance set default as={asn} router-id={router_id}"])
            elif brand == "huawei":
                cmds.extend([f"bgp {asn}", f" router-id {router_id}", "quit"])

    # ─── Router: IPv6 ───
    ipv6 = config.get("ipv6", {})
    if ipv6.get("ipv6_enable"):
        if cisco_like:
            cmds.append("ipv6 unicast-routing")
        elif brand == "mikrotik":
            cmds.append("/ipv6 set disable=no")
        elif brand == "huawei":
            cmds.append("ipv6 enable")
    if ipv6.get("ipv6_address"):
        if cisco_like:
            iface = "GigabitEthernet0/0"
            cmds.extend([f"interface {iface}", f" ipv6 address {ipv6['ipv6_address']}", "exit"])
    if ipv6.get("ipv6_gateway"):
        if cisco_like:
            cmds.append(f"ipv6 route ::/0 {ipv6['ipv6_gateway']}")
    if ipv6.get("ospfv3_enable"):
        if cisco_like:
            cmds.extend(["ipv6 router ospf 1", "exit"])
    if ipv6.get("ipv6_dhcp_enable"):
        if cisco_like:
            cmds.extend(["ipv6 dhcp pool LAN_IPV6", "exit"])

    # ─── Router: QoS / Bandwidth ───
    qos_b = config.get("qos_bandwidth", {})
    if qos_b.get("bandwidth_up") or qos_b.get("bandwidth_down"):
        if cisco_like:
            if qos_b.get("bandwidth_up"):
                cmds.append(f"interface GigabitEthernet0/0")
                cmds.append(f"  bandwidth {qos_b['bandwidth_up'] * 1000}")
                cmds.append("exit")
        elif brand == "mikrotik":
            if qos_b.get("bandwidth_down"):
                cmds.append(f"/interface set [find] max-limit={qos_b['bandwidth_down']}M")
    if qos_b.get("traffic_shaping") and qos_b.get("policy_map"):
        if cisco_like:
            cmds.extend([f"policy-map {qos_b['policy_map']}", " class class-default", "  fair-queue", "exit"])

    # ─── Router: Load Balancing ───
    lb = config.get("load_balancing", {})
    if lb.get("lb_enable"):
        if cisco_like:
            cmds.extend(["! Load balancing configuration", f" ! Method: {lb.get('lb_method', 'round-robin')}"])
            for srv in (lb.get("lb_members") or "").strip().split("\n"):
                srv = srv.strip()
                if srv:
                    cmds.append(f" ! member: {srv}")
        elif brand == "mikrotik":
            cmds.append(f"/ip dns set allow-remote-requests=yes")

    return cmds
