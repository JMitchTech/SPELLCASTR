"""
utils/scanner.py
Network scanning module for Spellcastr.
Uses python-nmap to discover hosts, open ports, and services.

Requires: nmap installed on the system + python-nmap package
  sudo apt install nmap   (Linux)
  brew install nmap       (macOS)
"""

import nmap
import socket
from datetime import datetime

# Ports considered risky / high-value targets
RISKY_PORTS = {
    21:   ('FTP',        'Unencrypted file transfer — use SFTP instead'),
    23:   ('Telnet',     'Unencrypted remote shell — use SSH instead'),
    135:  ('MSRPC',      'Windows RPC — restrict with firewall'),
    139:  ('NetBIOS',    'Legacy Windows file sharing'),
    445:  ('SMB',        'File sharing — common ransomware vector'),
    3306: ('MySQL',      'Database port exposed — bind to localhost'),
    3389: ('RDP',        'Remote Desktop — restrict to VPN only'),
    5432: ('PostgreSQL', 'Database port exposed — bind to localhost'),
    5900: ('VNC',        'Unencrypted remote desktop'),
    6379: ('Redis',      'Often runs unauthenticated — firewall immediately'),
    27017:('MongoDB',    'Database often runs unauthenticated'),
}

PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 554: 'RTSP', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5000: 'Flask/Dev',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 9100: 'JetDirect', 27017: 'MongoDB',
}

# Scan argument profiles
SCAN_PROFILES = {
    'quick':    '-sn',                          # Ping sweep only
    'standard': '-sV --open -T4',              # Service detection, fast
    'deep':     '-sV -O --open -T3 -A',        # OS detection + scripts
    'stealth':  '-sS -T2 --open',              # SYN stealth scan
}


def assess_risk(open_ports: list) -> str:
    """Return HIGH / MEDIUM / LOW based on open ports."""
    risky = [p for p in open_ports if p in RISKY_PORTS]
    if any(p in [23, 3389, 445, 5900] for p in risky):
        return 'high'
    if len(risky) >= 2:
        return 'medium'
    if risky:
        return 'low'
    return 'low'


def get_risk_flags(open_ports: list) -> list:
    """Return list of risk flag dicts for risky open ports."""
    flags = []
    for port in open_ports:
        if port in RISKY_PORTS:
            service, reason = RISKY_PORTS[port]
            flags.append({
                'port': port,
                'service': service,
                'reason': reason,
            })
    return flags


def scan_network(target: str, port_range: str = '1-1024', profile: str = 'standard') -> dict:
    """
    Scan a target IP or CIDR range.

    Args:
        target:     IP address or CIDR range (e.g. '192.168.1.0/24')
        port_range: Port range string (e.g. '1-1024' or '22,80,443')
        profile:    Scan profile key from SCAN_PROFILES

    Returns:
        dict with scan metadata and list of discovered hosts
    """
    nm = nmap.PortScanner()
    args = SCAN_PROFILES.get(profile, SCAN_PROFILES['standard'])

    # Quick sweep doesn't scan ports
    if profile == 'quick':
        nm.scan(hosts=target, arguments=args)
    else:
        nm.scan(hosts=target, ports=port_range, arguments=args)

    hosts = []
    scan_time = nm.scanstats().get('elapsed', '0')

    for host_ip in nm.all_hosts():
        host_info = nm[host_ip]
        state = host_info.state()
        if state != 'up':
            continue

        # Hostname resolution
        hostnames = host_info.hostnames()
        hostname = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else _reverse_lookup(host_ip)

        # OS detection (only available with -O flag)
        os_name = 'Unknown'
        if 'osmatch' in host_info and host_info['osmatch']:
            os_name = host_info['osmatch'][0]['name']

        # Collect open ports
        open_ports = []
        port_details = []
        for proto in host_info.all_protocols():
            for port in sorted(host_info[proto].keys()):
                port_data = host_info[proto][port]
                if port_data['state'] == 'open':
                    open_ports.append(port)
                    port_details.append({
                        'port':    port,
                        'proto':   proto,
                        'service': port_data.get('name', PORT_SERVICES.get(port, 'unknown')),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', ''),
                        'risky':   port in RISKY_PORTS,
                    })

        risk_level = assess_risk(open_ports)
        risk_flags = get_risk_flags(open_ports)

        hosts.append({
            'ip':          host_ip,
            'hostname':    hostname or host_ip,
            'os':          os_name,
            'state':       state,
            'open_ports':  open_ports,
            'port_details': port_details,
            'risk':        risk_level,
            'risk_flags':  risk_flags,
        })

    return {
        'target':     target,
        'profile':    profile,
        'port_range': port_range,
        'scan_time':  scan_time,
        'host_count': len(hosts),
        'hosts':      hosts,
        'timestamp':  datetime.now().isoformat(),
    }


def _reverse_lookup(ip: str) -> str:
    """Attempt reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''
