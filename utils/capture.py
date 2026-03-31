"""
utils/capture.py
Live packet capture module for Spellcastr.
Uses Scapy to sniff packets and analyse traffic in real time.

Requires root/admin privileges.
  Linux:  sudo python app.py
  macOS:  sudo python app.py
  Windows: Run as Administrator (limited Scapy support)
"""

import time
import socket
from datetime import datetime

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, DNS, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Ports that map to known services
SERVICE_MAP = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
}

# Ports that should trigger alerts
ALERT_PORTS = {23, 21, 3389, 445, 5900, 4444, 1337, 6667}

# Thresholds for anomaly detection
SYN_FLOOD_THRESHOLD   = 50   # SYN packets/src in 10s window
PORT_SCAN_THRESHOLD   = 15   # Unique dst ports/src in 10s window
ARP_SPOOF_THRESHOLD   = 5    # ARP replies from same MAC with different IPs

# Per-source tracking for anomaly detection
_syn_counts  = {}   # {src_ip: count}
_port_counts = {}   # {src_ip: set(dst_ports)}
_arp_table   = {}   # {ip: mac}
_window_start = time.time()


def get_network_interfaces() -> list:
    """Return list of available network interface names with friendly labels."""
    if SCAPY_AVAILABLE:
        from scapy.all import get_if_list, get_if_hwaddr
        ifaces = get_if_list()
        # Put the default interface first
        try:
            from scapy.all import conf
            default = str(conf.iface)
            if default in ifaces:
                ifaces.remove(default)
                ifaces.insert(0, default)
        except Exception:
            pass
        return ifaces
    return ['eth0', 'wlan0', 'lo']


def _reset_window():
    """Reset anomaly detection counters every 10 seconds."""
    global _syn_counts, _port_counts, _window_start
    _syn_counts  = {}
    _port_counts = {}
    _window_start = time.time()


def _classify_packet(pkt) -> dict:
    """
    Inspect a Scapy packet and return a structured dict.
    Returns None if the packet is not interesting.
    """
    now = datetime.now().strftime('%H:%M:%S')
    result = {
        'timestamp': now,
        'proto':     'OTHER',
        'src':       '',
        'dst':       '',
        'sport':     None,
        'dport':     None,
        'size':      len(pkt),
        'info':      '',
        'alert':     False,
        'alert_msg': '',
        'flags':     '',
    }

    if not pkt.haslayer(IP):
        # Check for ARP
        if pkt.haslayer(ARP):
            return _handle_arp(pkt, result)
        return None

    result['src'] = pkt[IP].src
    result['dst'] = pkt[IP].dst

    # ── TCP ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        result['proto']  = 'TCP'
        result['sport']  = tcp.sport
        result['dport']  = tcp.dport
        result['flags']  = str(tcp.flags)

        service = SERVICE_MAP.get(tcp.dport) or SERVICE_MAP.get(tcp.sport, '')
        flags_str = _tcp_flags(tcp.flags)
        result['info'] = f'{flags_str} {service}'.strip()

        # SYN flood detection
        if 'S' in str(tcp.flags) and 'A' not in str(tcp.flags):
            src = result['src']
            _syn_counts[src] = _syn_counts.get(src, 0) + 1
            if _syn_counts[src] > SYN_FLOOD_THRESHOLD:
                result['alert'] = True
                result['alert_msg'] = f'SYN flood detected from {src} ({_syn_counts[src]} SYNs)'

        # Alert on dangerous destination ports
        if tcp.dport in ALERT_PORTS:
            result['alert'] = True
            svc = SERVICE_MAP.get(tcp.dport, f'port {tcp.dport}')
            result['alert_msg'] = f'Connection attempt to {svc} ({tcp.dport}) from {result["src"]}'

        # Port scan detection
        src = result['src']
        if src not in _port_counts:
            _port_counts[src] = set()
        _port_counts[src].add(tcp.dport)
        if len(_port_counts[src]) > PORT_SCAN_THRESHOLD:
            result['alert'] = True
            result['alert_msg'] = f'Port scan detected from {src} ({len(_port_counts[src])} ports)'

    # ── UDP ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        result['proto'] = 'UDP'
        result['sport'] = udp.sport
        result['dport'] = udp.dport

        if pkt.haslayer(DNS):
            result['proto'] = 'DNS'
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:
                qname = dns.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                result['info'] = f'Query: {qname}'
            elif dns.qr == 1:
                result['info'] = f'Response: {dns.ancount} answer(s)'
        else:
            service = SERVICE_MAP.get(udp.dport) or SERVICE_MAP.get(udp.sport, '')
            result['info'] = f'UDP {service}'.strip()

    # ── ICMP ─────────────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        result['proto'] = 'ICMP'
        icmp_types = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'TTL Exceeded'}
        result['info'] = icmp_types.get(icmp.type, f'Type {icmp.type}')

    else:
        result['proto'] = 'IP'
        result['info']  = f'Protocol {pkt[IP].proto}'

    return result


def _handle_arp(pkt, result: dict) -> dict:
    """Handle ARP packets and detect spoofing."""
    arp = pkt[ARP]
    result['proto'] = 'ARP'
    result['src']   = arp.psrc
    result['dst']   = arp.pdst

    if arp.op == 2:  # ARP reply
        result['info'] = f'{arp.psrc} is at {arp.hwsrc}'
        known_mac = _arp_table.get(arp.psrc)
        if known_mac and known_mac != arp.hwsrc:
            result['alert'] = True
            result['alert_msg'] = f'ARP spoofing detected! {arp.psrc}: was {known_mac}, now {arp.hwsrc}'
        _arp_table[arp.psrc] = arp.hwsrc
    else:
        result['info'] = f'Who has {arp.pdst}? Tell {arp.psrc}'

    return result


def _tcp_flags(flags) -> str:
    """Convert Scapy TCP flags to readable string."""
    flag_map = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 'P': 'PSH', 'U': 'URG'}
    active = [v for k, v in flag_map.items() if k in str(flags)]
    return ' '.join(active) if active else str(flags)


def start_packet_capture(iface: str, socketio, stop_flag):
    """
    Start sniffing packets on `iface` and emit each one via SocketIO.

    Args:
        iface:     Network interface name (e.g. 'eth0')
        socketio:  Flask-SocketIO instance
        stop_flag: Callable that returns True when capture should stop
    """
    if not SCAPY_AVAILABLE:
        socketio.emit('capture_error', {'message': 'Scapy not installed. Run: pip install scapy'})
        return

    global _window_start
    _reset_window()

    def packet_handler(pkt):
        
        # Reset anomaly detection window every 10 seconds
        if time.time() - _window_start > 10:
            _reset_window()

        data = _classify_packet(pkt)
        if data:
            if data.get('alert'):
                data['proto'] = 'ALERT'
            socketio.emit('packet', data)

    sniff(
        iface=iface,
        prn=packet_handler,
        store=False,
        stop_filter=lambda _: stop_flag(),
    )
