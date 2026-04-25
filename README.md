# AriTyper License Management Server

A web-based licensing system for AriTyper application that allows users to submit license requests and administrators to approve them.

## Features

- **User Portal**: Submit license requests with device ID and WhatsApp number
- **Admin Dashboard**: Approve/reject license requests with one-click license generation
- **License Management**: View all licenses, revoke active licenses
- **API Endpoints**: For desktop app license validation
- **WhatsApp Integration**: Easy device ID submission via WhatsApp
- **Secure Authentication**: Admin login with password protection

## Quick Start

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python app.py
```

3. Access the application:
   - User Portal: http://localhost:5000
   - Admin Dashboard: http://localhost:5000/admin

### Admin Login
- Username: `admin`
- Password: `#Sh@nn3l@m3??`

## Deployment to Render

1. Push this code to GitHub
2. Connect your GitHub repository to Render
3. Render will automatically detect the `render.yaml` configuration
4. Your app will be deployed and available at your Render URL

## How It Works

### For Users
1. Open AriTyper app → Help → "My Device ID"
2. Copy the Device ID (format: ARI3-XXXXXXXXXXXXXXXX)
3. Visit the web portal and submit the license request
4. Optionally add WhatsApp number for direct contact
5. Wait for admin approval (usually within minutes)
6. Receive license key via WhatsApp or email

### For Admins
1. Login to admin dashboard
2. Review pending requests
3. Click "Approve" to automatically generate 3-month license
4. Copy the generated license key
5. Send it to the user via WhatsApp

### API Endpoints

#### Validate License
```
POST /api/device/validate_license
Content-Type: application/json

{
  "device_id": "ARI3-XXXXXXXXXXXXXXXX",
  "license_key": "ARI3-XXXXX-XXXXX-XXXXX-XXXXX"
}
```

#### Revoke Device
```
POST /api/device/revoke
Content-Type: application/json

{
  "device_id": "ARI3-XXXXXXXXXXXXXXXX"
}
```

## Database Schema

### DeviceRequest
- device_id (unique)
- whatsapp_number
- transaction_id
- status (pending/approved/rejected)
- created_at
- approved_at
- approved_by

### License
- device_id (unique)
- license_key
- expiry_date
- created_at
- created_by
- is_active
- revoked_at

### Admin
- username
- password_hash
- created_at

## Security Features

- HMAC-signed license keys (same as desktop app)
- Device-bound licenses
- Admin authentication with secure password hashing
- SQL injection protection via SQLAlchemy ORM
- CSRF protection via Flask session

## Customization

### Change Admin Password
Edit the password in `app.py`:
```python
if username == 'admin' and password == '#Sh@nn3l@m3??':
```

### Change License Duration
Edit the approval function in `app.py`:
```python
license_key, expiry_date = generator.generate(req.device_id, months=3)
```

### Update License Secret
Make sure `LICENSE_SECRET` in `app.py` matches the one in your desktop app.

## File Structure

```
typer2/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── render.yaml              # Render deployment config
├── templates/
│   ├── index.html           # User portal
│   ├── admin_login.html     # Admin login page
│   ├── admin_dashboard.html # Admin dashboard
│   └── admin_licenses.html  # License management
└── README.md               # This file
```

## Support

For issues or questions:
- WhatsApp: +256 760 730 254
- Email: support@arityper.com

---

*Powered by ArihoForge © 2026*
