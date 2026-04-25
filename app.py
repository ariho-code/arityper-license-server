#!/usr/bin/env python3
"""
AriTyper License Management Server
Web-based licensing system for AriTyper application
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import hashlib
import hmac
import struct
import base64
import time
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///arityper_licenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# License secret (must match client)
LICENSE_SECRET = "ArihoForge_HmacSecret_2026_v3_CHANGEME"

# ══════════════════════════════════════════════════════════════════════════════
#  Database Models
# ══════════════════════════════════════════════════════════════════════════════
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(100), unique=True, nullable=False)
    whatsapp_number = db.Column(db.String(20), nullable=True)
    transaction_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.String(80), nullable=True)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(100), unique=True, nullable=False)
    license_key = db.Column(db.String(200), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(80), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

# ══════════════════════════════════════════════════════════════════════════════
#  License Generator (reuse existing logic)
# ══════════════════════════════════════════════════════════════════════════════
class LicenseGenerator:
    def __init__(self, secret: str = LICENSE_SECRET):
        self.secret = secret

    def _device_hash(self, device_id: str) -> bytes:
        return hashlib.sha256(device_id.encode()).digest()[:8]

    def _make_mac(self, dev_hash: bytes, expiry_b: bytes) -> bytes:
        return hmac.new(self.secret.encode(), dev_hash + expiry_b, hashlib.sha256).digest()[:8]

    def generate(self, device_id: str, months: int = 3) -> str:
        device_id = device_id.strip().upper()
        dev_hash = self._device_hash(device_id)
        expiry = int(time.time()) + months * 30 * 24 * 3600
        expiry_b = struct.pack(">Q", expiry)
        mac = self._make_mac(dev_hash, expiry_b)

        payload = base64.b32encode(dev_hash + expiry_b + mac).decode().rstrip("=")
        chunks = [payload[i:i+5] for i in range(0, len(payload), 5)]
        key = "ARI3-" + "-".join(chunks)
        return key, datetime.fromtimestamp(expiry)

    def validate(self, key: str, device_id: str):
        device_id = device_id.strip().upper()
        try:
            clean = (key.upper()
                        .replace("ARI3-", "")
                        .replace("ARI-",  "")
                        .replace("-",     "")
                        .replace(" ",     ""))
            pad = (8 - len(clean) % 8) % 8
            payload = base64.b32decode(clean + "=" * pad)

            if len(payload) < 24:
                return False, "Key too short", None

            stored_dev = payload[:8]
            expiry_b = payload[8:16]
            stored_mac = payload[16:24]

            # Device check
            dev_hash = self._device_hash(device_id)
            if stored_dev != dev_hash:
                return False, "Device ID mismatch", None

            # Expiry check
            expiry = struct.unpack(">Q", expiry_b)[0]
            expiry_dt = datetime.fromtimestamp(expiry)
            if time.time() > expiry:
                return False, f"EXPIRED on {expiry_dt.strftime('%Y-%m-%d')}", expiry_dt

            # HMAC check
            expected = self._make_mac(stored_dev, expiry_b)
            if not hmac.compare_digest(stored_mac, expected):
                return False, "HMAC invalid", None

            days_left = (expiry_dt - datetime.now()).days
            return True, f"VALID — {days_left} days left", expiry_dt

        except Exception as e:
            return False, f"Parse error: {e}", None

# ══════════════════════════════════════════════════════════════════════════════
#  Routes
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_request', methods=['POST'])
def submit_request():
    device_id = request.form.get('device_id', '').strip()
    whatsapp_number = request.form.get('whatsapp_number', '').strip()
    transaction_id = request.form.get('transaction_id', '').strip()

    if not device_id:
        return jsonify({'success': False, 'message': 'Device ID is required'})

    # Check if device already has a request
    existing = DeviceRequest.query.filter_by(device_id=device_id).first()
    if existing:
        if existing.status == 'pending':
            return jsonify({'success': False, 'message': 'Request already submitted and pending approval'})
        elif existing.status == 'approved':
            return jsonify({'success': False, 'message': 'Device already licensed'})

    # Create new request
    req = DeviceRequest(
        device_id=device_id,
        whatsapp_number=whatsapp_number,
        transaction_id=transaction_id
    )
    db.session.add(req)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Request submitted successfully! You will receive your license key via WhatsApp once approved.'})

@app.route('/admin')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == 'admin' and password == '#Sh@nn3l@m3??':
        session['admin_logged_in'] = True
        session['admin_username'] = username
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid credentials', 'error')
        return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    pending_requests = DeviceRequest.query.filter_by(status='pending').order_by(DeviceRequest.created_at.desc()).all()
    approved_requests = DeviceRequest.query.filter_by(status='approved').order_by(DeviceRequest.approved_at.desc()).limit(20).all()
    rejected_requests = DeviceRequest.query.filter_by(status='rejected').order_by(DeviceRequest.created_at.desc()).limit(20).all()
    
    return render_template('admin_dashboard.html', 
                         pending=pending_requests,
                         approved=approved_requests,
                         rejected=rejected_requests)

@app.route('/admin/approve/<int:request_id>')
def approve_request(request_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    req = DeviceRequest.query.get_or_404(request_id)
    if req.status != 'pending':
        return jsonify({'success': False, 'message': 'Request already processed'})
    
    # Generate license
    generator = LicenseGenerator()
    license_key, expiry_date = generator.generate(req.device_id, months=3)
    
    # Save license
    license_record = License(
        device_id=req.device_id,
        license_key=license_key,
        expiry_date=expiry_date,
        created_by=session.get('admin_username')
    )
    db.session.add(license_record)
    
    # Update request
    req.status = 'approved'
    req.approved_at = datetime.utcnow()
    req.approved_by = session.get('admin_username')
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'license_key': license_key,
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'message': 'License generated successfully!'
    })

@app.route('/admin/reject/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    req = DeviceRequest.query.get_or_404(request_id)
    if req.status != 'pending':
        return jsonify({'success': False, 'message': 'Request already processed'})
    
    req.status = 'rejected'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Request rejected'})

@app.route('/admin/licenses')
def admin_licenses():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    licenses = License.query.order_by(License.created_at.desc()).all()
    return render_template('admin_licenses.html', licenses=licenses)

@app.route('/admin/revoke/<int:license_id>', methods=['POST'])
def revoke_license(license_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    license_record = License.query.get_or_404(license_id)
    license_record.is_active = False
    license_record.revoked_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'License revoked'})

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# API endpoints for the desktop app
@app.route('/api/device/validate_license', methods=['POST'])
def validate_license():
    data = request.get_json()
    device_id = data.get('device_id')
    license_key = data.get('license_key')
    
    if not device_id or not license_key:
        return jsonify({'valid': False, 'message': 'Missing device_id or license_key'})
    
    # Check in database
    license_record = License.query.filter_by(device_id=device_id, license_key=license_key, is_active=True).first()
    if not license_record:
        return jsonify({'valid': False, 'message': 'License not found or revoked'})
    
    # Validate with generator
    generator = LicenseGenerator()
    valid, message, expiry = generator.validate(license_key, device_id)
    
    return jsonify({
        'valid': valid,
        'message': message,
        'expiry': expiry.isoformat() if expiry else None
    })

@app.route('/api/device/revoke', methods=['POST'])
def revoke_device():
    data = request.get_json()
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'success': False, 'message': 'Missing device_id'})
    
    license_record = License.query.filter_by(device_id=device_id).first()
    if license_record:
        license_record.is_active = False
        license_record.revoked_at = datetime.utcnow()
        db.session.commit()
    
    return jsonify({'success': True, 'message': 'Device revoked'})

# ══════════════════════════════════════════════════════════════════════════════
#  Initialize Database
# ══════════════════════════════════════════════════════════════════════════════
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create default admin if not exists
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        admin = Admin(
            username='admin',
            password_hash=generate_password_hash('#Sh@nn3l@m3??')
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            admin = Admin(
                username='admin',
                password_hash=generate_password_hash('#Sh@nn3l@m3??')
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
