from flask import Flask, render_template, request, jsonify, redirect, session, url_for, abort
from datetime import datetime
import json
import os
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.secret_key = 'Hr857#hcj@9-_tuhbku@54'

# ===== Load keys and sessions =====
if os.path.exists('data.json'):
    with open('data.json', 'r') as f:
        data = json.load(f)
    KEYS = data.get("keys", {})
else:
    KEYS = {}

SESSION_FILE = 'sessions.json'
if os.path.exists(SESSION_FILE):
    with open(SESSION_FILE, 'r') as f:
        session_data = json.load(f)
    active_sessions = session_data.get('active_sessions', [])
    blocked_devices = session_data.get('blocked_devices', [])
else:
    active_sessions = []
    blocked_devices = []

def save_sessions():
    with open(SESSION_FILE, 'w') as f:
        json.dump({
            'active_sessions': active_sessions,
            'blocked_devices': blocked_devices
        }, f, indent=2)

# ========== Admin credentials ==========
ADMIN_USERNAME = "adminv2"
ADMIN_PASSWORD = "myp@ssword"

# ========== ROUTES ==========
def get_real_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/app-opened', methods=['POST'])
def app_opened():
    data = request.get_json()
    device_id = data.get("device_id")
    ip = get_real_ip()
    country = data.get('country')
    phone = data.get('phone')
    os_info = data.get('os')

    if device_id in blocked_devices:
        return jsonify({'error': 'Blocked'}), 403

    if not any(s['device_id'] == device_id for s in active_sessions):
        active_sessions.append({
            'key': None,
            'device_id': device_id,
            'ip': ip,
            'country': country,
            'phone': phone,
            'os': os_info,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'App Opened'
        })
        save_sessions()
    return jsonify({'message': 'App accessed'})

@app.route('/login-direct', methods=['POST'])
def login_direct_key():
    data = request.get_json()
    key = data.get("key")
    device_id = data.get("device_id")
    ip = get_real_ip()

    if not key or key not in KEYS:
        return jsonify({'error': 'Invalid key'}), 400

    key_data = KEYS[key]
    if key_data.get('blocked') or device_id in blocked_devices:
        return jsonify({'error': 'Blocked'}), 403

    if device_id not in key_data['used_devices']:
        if len(key_data['used_devices']) < key_data['devices']:
            key_data['used_devices'].append(device_id)
        else:
            return jsonify({'error': 'Device limit reached'}), 403

    active_sessions.append({
        'key': key,
        'device_id': device_id,
        'ip': ip,
        'country': data.get('country'),
        'phone': data.get('phone'),
        'os': data.get('os'),
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'Online'
    })
    save_sessions()
    return jsonify({'message': 'Key activated successfully'})

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        if data['username'] == ADMIN_USERNAME and data['password'] == ADMIN_PASSWORD:
            session['logged_in'] = True
            return jsonify({"success": True, "redirect": url_for('index')})
        return jsonify({"success": False, "error": "Invalid credentials"})
    return render_template("login.html")

@app.route('/dashboard')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template("dashboard.html", sessions=active_sessions, blocked_devices=blocked_devices)

@app.route('/status')
def status():
    active = sum(1 for s in active_sessions)
    activated = len({s['key'] for s in active_sessions if s['key']})
    return jsonify({"active_users": active, "activated_keys": activated})

@app.route('/user-details')
def user_details():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    detailed_sessions = []

    for s in active_sessions:
        days_left = "N/A"
        if s.get("key") and s["key"] in KEYS:
            try:
                expires = datetime.fromisoformat(KEYS[s["key"]]["expires"])
                days_left = max((expires - datetime.now()).days, 0)
            except:
                pass
        status = 'Blocked' if s['device_id'] in blocked_devices else s.get('status', 'Active')
        detailed_sessions.append({
            "key": s.get("key"),
            "device_id": s.get("device_id"),
            "ip": s.get("ip"),
            "country": s.get("country"),
            "phone": s.get("phone"),
            "os": s.get("os"),
            "time": s.get("time"),
            "status": status,
            "days_left": days_left
        })

    for blocked_id in blocked_devices:
        if not any(s['device_id'] == blocked_id for s in detailed_sessions):
            detailed_sessions.append({
                "key": None,
                "device_id": blocked_id,
                "ip": "Unknown",
                "country": "Unknown",
                "phone": "Unknown",
                "os": "Unknown",
                "time": "Unknown",
                "status": "Blocked",
                "days_left": "N/A"
            })

    return jsonify(detailed_sessions)

@app.route('/blocked-devices')
def get_blocked():
    return jsonify({'blocked': blocked_devices})

@app.route('/disconnect', methods=['POST'])
def disconnect():
    data = request.get_json()
    device_id = data['device_id']
    global active_sessions
    key_to_remove = None

    new_sessions = []
    for s in active_sessions:
        if s['device_id'] == device_id:
            key_to_remove = s['key']
        else:
            new_sessions.append(s)
    active_sessions = new_sessions

    if key_to_remove and device_id in KEYS.get(key_to_remove, {}).get('used_devices', []):
        KEYS[key_to_remove]['used_devices'].remove(device_id)

    save_sessions()
    return jsonify({'message': f'Device {device_id} disconnected'})

@app.route('/block-device', methods=['POST'])
def block_device():
    data = request.get_json()
    device_id = data['device_id']
    key_to_block = None

    for s in active_sessions:
        if s['device_id'] == device_id:
            s['status'] = 'Blocked'
            key_to_block = s['key']

    if device_id not in blocked_devices:
        blocked_devices.append(device_id)

    if key_to_block and key_to_block in KEYS:
        del KEYS[key_to_block]

    save_sessions()
    return jsonify({'message': f'Device {device_id} blocked'})

@app.route('/unblock-device', methods=['POST'])
def unblock_device():
    data = request.get_json()
    device_id = data['device_id']
    if device_id in blocked_devices:
        blocked_devices.remove(device_id)
        for s in active_sessions:
            if s['device_id'] == device_id:
                s['status'] = 'Online'
        save_sessions()
        return jsonify({'message': f'Device {device_id} unblocked'})
    return jsonify({'message': f'Device {device_id} was not blocked'})

@app.route('/block-device/<device_id>', methods=['POST'])
def block_device_direct(device_id):
    key_to_block = None

    for s in active_sessions:
        if s['device_id'] == device_id:
            s['status'] = 'Blocked'
            key_to_block = s['key']

    if device_id not in blocked_devices:
        blocked_devices.append(device_id)

    if key_to_block and key_to_block in KEYS:
        del KEYS[key_to_block]

    save_sessions()
    return jsonify({'success': True, 'message': f'Device {device_id} blocked'})

@app.route('/unblock-device/<device_id>', methods=['POST'])
def unblock_device_direct(device_id):
    if device_id in blocked_devices:
        blocked_devices.remove(device_id)
        for s in active_sessions:
            if s['device_id'] == device_id:
                s['status'] = 'Online'
        save_sessions()
        return jsonify({'success': True, 'message': f'Device {device_id} unblocked'})
    return jsonify({'success': False, 'message': f'Device {device_id} was not blocked'})

@app.route('/disconnect-device/<device_id>', methods=['POST'])
def disconnect_device_direct(device_id):
    global active_sessions
    active_sessions = [s for s in active_sessions if s['device_id'] != device_id]
    save_sessions()
    return jsonify({'success': True, 'message': f'Device {device_id} disconnected'})

# ========== MAIN ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
