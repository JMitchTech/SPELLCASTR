"""
Spellcastr - Network Recon & Traffic Analysis Suite
By WizardWerks Enterprise Labs

A Flask + SocketIO web application for network scanning and packet capture.
Requires root/admin privileges for live packet capture via Scapy.

Usage:
    sudo python app.py
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spellcastr-wizardwerks-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── Global state ─────────────────────────────────────────────────────────────
capture_thread = None
capture_active = False
capture_lock = threading.Lock()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Kick off a network scan via python-nmap."""
    from utils.scanner import scan_network
    data = request.get_json()
    target = data.get('target', '192.168.1.0/24')
    port_range = data.get('ports', '1-1024')
    profile = data.get('profile', 'standard')
    try:
        results = scan_network(target, port_range, profile)
        return jsonify({'status': 'ok', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Return available network interfaces."""
    from utils.capture import get_network_interfaces
    try:
        ifaces = get_network_interfaces()
        return jsonify({'status': 'ok', 'interfaces': ifaces})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ── SocketIO events ───────────────────────────────────────────────────────────

@socketio.on('start_capture')
def handle_start_capture(data):
    """Begin live packet capture on the selected interface."""
    global capture_thread, capture_active
    from utils.capture import start_packet_capture

    iface = data.get('interface', 'eth0')

    with capture_lock:
        if capture_active:
            emit('capture_error', {'message': 'Capture already running'})
            return
        capture_active = True

    def capture_loop():
        global capture_active
        try:
            start_packet_capture(
                iface=iface,
                socketio=socketio,
                stop_flag=lambda: not capture_active
            )
        except Exception as e:
            socketio.emit('capture_error', {'message': str(e)})
        finally:
            with capture_lock:
                capture_active = False

    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()
    emit('capture_started', {'interface': iface})


@socketio.on('stop_capture')
def handle_stop_capture():
    """Stop the active packet capture."""
    global capture_active
    with capture_lock:
        capture_active = False
    emit('capture_stopped', {})


@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to Spellcastr'})


@socketio.on('disconnect')
def handle_disconnect():
    global capture_active
    with capture_lock:
        capture_active = False


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("""
  ╔══════════════════════════════════════════╗
  ║   SPELLCASTR — WizardWerks Ent. Labs    ║
  ║   Network Recon & Traffic Suite          ║
  ║   http://127.0.0.1:5000                  ║
  ╚══════════════════════════════════════════╝
    """)
    # NOTE: Packet capture requires root/admin privileges
    # Run with: sudo python app.py
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
