#!/usr/bin/env python3
"""
AriTyper v3.0 — Professional Auto-Typing Tool
Powered by ArihoForge
© 2026 ArihoForge. All rights reserved.

License system:
  - Keys are HMAC-signed, device-bound, and carry an embedded expiry timestamp
  - Stored locally in an XOR-encrypted file under %USERPROFILE%/.arityper/
  - Validated against the API server on every launch; works offline if server is down
  - Keys auto-expire 3 months after issue; app shows countdown and blocks when expired
  - Admin can remotely revoke any device via the heartbeat endpoint
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
import threading
import time
import json
import os
import socket
import hashlib
import hmac as hmac_lib
import struct
import base64
import platform
import ctypes
import ctypes.wintypes as wt
from ctypes import Structure, Union, POINTER, pointer, sizeof
from datetime import datetime

# ─── Optional imports ──────────────────────────────────────────────────────────
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import win32gui
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# ─── App constants ─────────────────────────────────────────────────────────────
APP_VERSION  = "3.0.0"
SERVER_URL   = "https://arityper-api.onrender.com"
LICENSE_DIR  = os.path.join(os.path.expanduser("~"), ".arityper")
LICENSE_FILE = os.path.join(LICENSE_DIR, "license.dat")

# ⚠  Change this secret!  Keep it the same on your server's generate_license.py
#    Never share it publicly.
LICENSE_SECRET = "ArihoForge_HmacSecret_2026_v3_CHANGEME"


# ══════════════════════════════════════════════════════════════════════════════
#  Windows SendInput structures
# ══════════════════════════════════════════════════════════════════════════════
PUL              = POINTER(ctypes.c_ulong)
KEYEVENTF_UNICODE = 0x0004
KEYEVENTF_KEYUP   = 0x0002
INPUT_KEYBOARD    = 1

class KeyBdInput(Structure):
    _fields_ = [
        ("wVk",         wt.WORD),
        ("wScan",       wt.WORD),
        ("dwFlags",     wt.DWORD),
        ("time",        wt.DWORD),
        ("dwExtraInfo", PUL),
    ]

class MouseInput(Structure):
    _fields_ = [
        ("dx",          ctypes.c_long),
        ("dy",          ctypes.c_long),
        ("mouseData",   wt.DWORD),
        ("dwFlags",     wt.DWORD),
        ("time",        wt.DWORD),
        ("dwExtraInfo", PUL),
    ]

class HardwareInput(Structure):
    _fields_ = [
        ("uMsg",    wt.DWORD),
        ("wParamL", wt.WORD),
        ("wParamH", wt.WORD),
    ]

class Input_I(Union):
    _fields_ = [("ki", KeyBdInput), ("mi", MouseInput), ("hi", HardwareInput)]

class Input(Structure):
    _fields_ = [("type", wt.DWORD), ("ii", Input_I)]


# ══════════════════════════════════════════════════════════════════════════════
#  License Manager
# ══════════════════════════════════════════════════════════════════════════════
class LicenseManager:
    """
    License key format
    ──────────────────
    Raw payload  = device_hash(8 B) + expiry_unix_be(8 B) + hmac_sha256_trunc(8 B)
    Encoded key  = "ARI3-" + base32(payload), formatted in groups of 5
    Example      : ARI3-ABCDE-FGHIJ-KLMNO-PQRST-UVWXY

    Security
    ────────
    • Key is useless on any machine whose SHA-256 does not match device_hash
    • HMAC prevents forgery even if someone reverse-engineers the format
    • Local file is XOR-encrypted with a key derived from device_id; the first
      8 bytes are a SHA-256 checksum so any tampering is detected
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        os.makedirs(LICENSE_DIR, exist_ok=True)

    # ── Crypto helpers ────────────────────────────────────────────────────────

    def _device_hash(self) -> bytes:
        return hashlib.sha256(self.device_id.encode()).digest()[:8]

    def _make_mac(self, device_h: bytes, expiry_b: bytes) -> bytes:
        return hmac_lib.new(LICENSE_SECRET.encode(),
                            device_h + expiry_b,
                            hashlib.sha256).digest()[:8]

    # ── Key validation ────────────────────────────────────────────────────────

    def validate_key(self, key: str):
        """
        Returns (valid: bool, message: str, expiry_unix: int)
        """
        try:
            clean = (key.upper()
                       .replace("ARI3-", "")
                       .replace("ARI-",  "")
                       .replace("-",     "")
                       .replace(" ",     ""))
            # Base32 requires padding to multiple of 8
            pad     = (8 - len(clean) % 8) % 8
            payload = base64.b32decode(clean + "=" * pad)

            if len(payload) < 24:
                return False, "Key too short — invalid format", 0

            stored_dev_hash = payload[:8]
            expiry_b        = payload[8:16]
            stored_mac      = payload[16:24]

            # 1. Device match
            if stored_dev_hash != self._device_hash():
                return False, "This license belongs to a different device", 0

            # 2. Expiry
            expiry = struct.unpack(">Q", expiry_b)[0]
            if time.time() > expiry:
                days_ago = int((time.time() - expiry) / 86400)
                return False, f"License expired {days_ago} day(s) ago — please renew", expiry

            # 3. HMAC integrity
            expected_mac = self._make_mac(stored_dev_hash, expiry_b)
            if not hmac_lib.compare_digest(stored_mac, expected_mac):
                return False, "License key is invalid or has been tampered with", 0

            days_left = int((expiry - time.time()) / 86400)
            return True, f"Valid — {days_left} day(s) remaining", expiry

        except Exception as exc:
            return False, f"Could not parse key: {exc}", 0

    # ── Local encrypted storage ───────────────────────────────────────────────

    def _file_key(self) -> bytes:
        """Derive a 32-byte XOR key from device_id."""
        return hashlib.sha256((self.device_id + "_ari_file").encode()).digest()

    def _xor(self, data: bytes) -> bytes:
        k = self._file_key()
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

    def save_license(self, key: str, expiry: int, transaction_id: str = ""):
        data = json.dumps({
            "key":            key,
            "expiry":         expiry,
            "device_id":      self.device_id,
            "transaction_id": transaction_id,
            "saved_at":       int(time.time()),
            "app_version":    APP_VERSION,
        }).encode()

        checksum  = hashlib.sha256(data).digest()[:8]
        encrypted = self._xor(data)

        with open(LICENSE_FILE, "wb") as f:
            f.write(checksum + encrypted)

    def load_license(self):
        """Returns dict or None if missing / tampered."""
        try:
            with open(LICENSE_FILE, "rb") as f:
                raw = f.read()

            checksum  = raw[:8]
            encrypted = raw[8:]
            data      = self._xor(encrypted)

            if hashlib.sha256(data).digest()[:8] != checksum:
                return None  # Tampered

            return json.loads(data.decode())
        except Exception:
            return None

    def delete_license(self):
        if os.path.exists(LICENSE_FILE):
            try:
                os.remove(LICENSE_FILE)
            except Exception:
                pass

    # ── Display helpers ───────────────────────────────────────────────────────

    def expiry_display(self, expiry: int) -> str:
        dt        = datetime.fromtimestamp(expiry)
        days_left = (dt - datetime.now()).days
        if days_left > 30:
            return f"Expires {dt.strftime('%b %d, %Y')}  ({days_left}d left)"
        elif days_left > 0:
            return f"⚠  Expires in {days_left} day(s) — renew soon!"
        else:
            return "❌ Expired"


# ══════════════════════════════════════════════════════════════════════════════
#  Typing Engine  (SendInput + KEYEVENTF_UNICODE)
# ══════════════════════════════════════════════════════════════════════════════
class TypingEngine:
    """
    Uses Windows SendInput with KEYEVENTF_UNICODE so every character —
    including full Unicode (emoji, accented letters, symbols) — arrives in
    the target window exactly as intended.

    Alignment markers in the text:
        [CENTER]  → Ctrl+E before line, Ctrl+L after
        [RIGHT]   → Ctrl+R before line, Ctrl+L after
        [JUSTIFY] → Ctrl+J before line, Ctrl+L after
        (no marker) → left-aligned, no shortcut sent
    """

    # Virtual key codes
    VK_CTRL   = 0x11
    VK_RETURN = 0x0D
    VK_TAB    = 0x09
    VK_E      = 0x45   # center
    VK_L      = 0x4C   # left
    VK_R      = 0x52   # right
    VK_J      = 0x4A   # justify (LibreOffice / some apps)

    ALIGN_VK = {
        "center":  0x45,
        "right":   0x52,
        "justify": 0x4A,
        "left":    0x4C,
    }

    def __init__(self):
        self.user32 = ctypes.windll.user32

    # ── Low-level send helpers ────────────────────────────────────────────────

    def _input(self, vk=0, scan=0, flags=0) -> Input:
        extra = ctypes.c_ulong(0)
        ii    = Input_I()
        ii.ki = KeyBdInput(vk, scan, flags, 0, pointer(extra))
        return Input(INPUT_KEYBOARD, ii)

    def _send(self, *inputs):
        n    = len(inputs)
        LPINPUT = Input * n
        self.user32.SendInput(n, LPINPUT(*inputs), sizeof(Input))

    # ── Public API ────────────────────────────────────────────────────────────

    def send_unicode(self, char: str):
        """Type one Unicode character. Handles chars outside the BMP (> U+FFFF)."""
        code = ord(char)
        if code > 0xFFFF:
            # Surrogate pair
            code  -= 0x10000
            high   = 0xD800 + (code >> 10)
            low    = 0xDC00 + (code & 0x3FF)
            self._send(
                self._input(0, high, KEYEVENTF_UNICODE),
                self._input(0, high, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
                self._input(0, low,  KEYEVENTF_UNICODE),
                self._input(0, low,  KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
            )
        else:
            self._send(
                self._input(0, code, KEYEVENTF_UNICODE),
                self._input(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
            )

    def send_vk(self, vk: int):
        self._send(self._input(vk, 0, 0), self._input(vk, 0, KEYEVENTF_KEYUP))

    def send_ctrl(self, vk: int):
        self._send(
            self._input(self.VK_CTRL, 0, 0),
            self._input(vk,           0, 0),
            self._input(vk,           0, KEYEVENTF_KEYUP),
            self._input(self.VK_CTRL, 0, KEYEVENTF_KEYUP),
        )

    def set_alignment(self, alignment: str):
        vk = self.ALIGN_VK.get(alignment, self.VK_L)
        time.sleep(0.04)
        self.send_ctrl(vk)
        time.sleep(0.04)

    def type_text(self, text: str, char_delay: float,
                  progress_cb=None, stop_flag=None):
        """
        Type `text` character by character.
        Lines starting with [CENTER] / [RIGHT] / [JUSTIFY] trigger alignment
        keyboard shortcuts before typing that line, then reset to left after.
        """
        lines = text.split("\n")
        total = max(len(lines), 1)

        for line_idx, raw_line in enumerate(lines):
            if stop_flag and stop_flag():
                break

            # Parse alignment marker
            alignment = "left"
            line      = raw_line

            for marker, align in (("[CENTER]", "center"), ("[RIGHT]", "right"), ("[JUSTIFY]", "justify")):
                if raw_line.startswith(marker):
                    alignment = align
                    line      = raw_line[len(marker):]
                    break

            # Apply alignment shortcut BEFORE typing the line
            if alignment != "left":
                self.set_alignment(alignment)

            # Type each character
            for char in line:
                if stop_flag and stop_flag():
                    break
                if char == "\t":
                    self.send_vk(self.VK_TAB)
                else:
                    self.send_unicode(char)
                time.sleep(char_delay)

            # Reset to left alignment AFTER line
            if alignment != "left":
                self.set_alignment("left")

            # Newline between lines (not after the last one)
            if line_idx < len(lines) - 1:
                self.send_vk(self.VK_RETURN)
                time.sleep(char_delay * 2)

            # Progress callback
            if progress_cb:
                progress_cb(int((line_idx + 1) / total * 100))


# ══════════════════════════════════════════════════════════════════════════════
#  Main Application
# ══════════════════════════════════════════════════════════════════════════════
class AriTyper:

    def __init__(self, root: tk.Tk):
        self.root          = root
        self.device_id     = self._make_device_id()
        self.lic_mgr       = LicenseManager(self.device_id)
        self.typer         = TypingEngine()
        self.target_hwnd   = None
        self.is_typing     = False
        self._stop         = False
        self.is_licensed   = False
        self.license_expiry= 0
        self.sessions_today= 0

        self._build_window()
        self._build_menu()
        self._build_ui()
        self._start_license_check()

    # ─── Device ID ───────────────────────────────────────────────────────────
    def _make_device_id(self) -> str:
        import uuid
        parts = [
            socket.gethostname(),
            platform.system(),
            platform.machine(),
            str(uuid.getnode()),
        ]
        h = hashlib.sha256("|".join(parts).encode()).hexdigest()
        return f"ARI3-{h[:16].upper()}"

    # ─── Window & menu ───────────────────────────────────────────────────────
    def _build_window(self):
        self.root.title("AriTyper v3.0 — Powered by ArihoForge")
        self.root.geometry("980x660")
        self.root.configure(bg="#0d0d0d")
        self.root.minsize(820, 560)

    def _build_menu(self):
        import webbrowser
        bar = tk.Menu(self.root)
        self.root.config(menu=bar)

        h = tk.Menu(bar, tearoff=0)
        bar.add_cascade(label="Help", menu=h)
        h.add_command(label="💰 How to Pay (MTN / Airtel)", command=self._dlg_payment)
        h.add_command(label="🔑 My Device ID",               command=self._dlg_device_id)
        h.add_command(label="🔄 Re-check License",           command=self._start_license_check)
        h.add_separator()
        h.add_command(label="Terms & Conditions",
                      command=lambda: webbrowser.open("https://arityper-website.vercel.app/terms"))
        h.add_command(label="Official Website",
                      command=lambda: webbrowser.open("https://arityper-website.vercel.app"))
        h.add_separator()
        h.add_command(label="About AriTyper", command=self._dlg_about)

    # ─── UI ──────────────────────────────────────────────────────────────────
    def _build_ui(self):
        C = {
            "bg":     "#0d0d0d",
            "panel":  "#141414",
            "border": "#242424",
            "green":  "#00e676",
            "blue":   "#2979ff",
            "red":    "#f44336",
            "orange": "#ff9100",
            "text":   "#e0e0e0",
            "muted":  "#616161",
        }
        self.C = C

        # ── Top bar
        top = tk.Frame(self.root, bg="#111111", height=54)
        top.pack(fill="x")
        top.pack_propagate(False)

        tk.Label(top, text="⚡ AriTyper", font=("Segoe UI", 16, "bold"),
                 bg="#111111", fg=C["green"]).pack(side="left", padx=18, pady=14)
        tk.Label(top, text="v3.0  ·  Powered by ArihoForge",
                 font=("Segoe UI", 9), bg="#111111", fg=C["muted"]).pack(side="left")

        # ── License bar
        self.lic_bar = tk.Frame(self.root, bg="#1a1400", height=30)
        self.lic_bar.pack(fill="x")
        self.lic_bar.pack_propagate(False)

        self.lic_lbl = tk.Label(self.lic_bar, text="🔒 Checking license...",
                                font=("Segoe UI", 9), bg="#1a1400", fg=C["orange"])
        self.lic_lbl.pack(side="left", padx=14, pady=5)

        self.expiry_lbl = tk.Label(self.lic_bar, text="",
                                   font=("Segoe UI", 9), bg="#1a1400", fg=C["muted"])
        self.expiry_lbl.pack(side="right", padx=14)

        # ── Body
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=14, pady=10)

        # Left — text panel
        left = tk.Frame(body, bg=C["panel"],
                        highlightbackground=C["border"], highlightthickness=1)
        left.pack(side="left", fill="both", expand=True)

        hdr = tk.Frame(left, bg="#1c1c1c")
        hdr.pack(fill="x")
        tk.Label(hdr, text="📄 Text Content", font=("Segoe UI", 11, "bold"),
                 bg="#1c1c1c", fg=C["blue"]).pack(side="left", padx=12, pady=8)
        self.char_lbl = tk.Label(hdr, text="0 chars", font=("Segoe UI", 8),
                                  bg="#1c1c1c", fg=C["muted"])
        self.char_lbl.pack(side="right", padx=12)

        self.txt = scrolledtext.ScrolledText(
            left, font=("Consolas", 11), bg="#0e0e0e", fg="#e0e0e0",
            wrap=tk.WORD, relief="flat", bd=0, padx=12, pady=10,
            insertbackground=C["green"], selectbackground="#2979ff",
        )
        self.txt.pack(fill="both", expand=True)
        self.txt.bind("<KeyRelease>", lambda e: self._refresh_chars())

        btn_row = tk.Frame(left, bg="#111111")
        btn_row.pack(fill="x", padx=10, pady=8)
        for label, color, cmd in [
            ("📋 Paste",     "#e65100", self._paste),
            ("📂 Load File", "#1565c0", self._load_file),
            ("🗑 Clear",     "#b71c1c", self._clear),
        ]:
            tk.Button(btn_row, text=label, bg=color, fg="white",
                      font=("Segoe UI", 9), relief="flat", padx=12, pady=5,
                      cursor="hand2", command=cmd).pack(side="left", padx=3)

        # Right — controls
        right = tk.Frame(body, bg=C["panel"], width=230,
                         highlightbackground=C["border"], highlightthickness=1)
        right.pack(side="right", fill="y", padx=(12, 0))
        right.pack_propagate(False)

        tk.Frame(right, bg="#1c1c1c", height=38).pack(fill="x")
        tk.Label(right, text="⚙  Controls", font=("Segoe UI", 11, "bold"),
                 bg="#1c1c1c", fg=C["blue"]).place(x=12, y=8)

        def section(text):
            tk.Label(right, text=text, font=("Segoe UI", 9, "bold"),
                     bg=C["panel"], fg=C["text"]).pack(anchor="w", padx=14, pady=(12, 3))

        section("Target Window")
        tk.Button(right, text="🪟 Select Window", bg="#1565c0", fg="white",
                  font=("Segoe UI", 9), relief="flat", padx=8, pady=5,
                  cursor="hand2", command=self._dlg_windows).pack(fill="x", padx=14, pady=2)
        self.win_lbl = tk.Label(right, text="No window selected",
                                font=("Segoe UI", 8), bg=C["panel"], fg=C["muted"],
                                wraplength=190)
        self.win_lbl.pack(anchor="w", padx=14)

        section("Typing Speed")
        self.speed_var = tk.DoubleVar(value=60)
        ttk.Scale(right, from_=1, to=100, variable=self.speed_var,
                  orient="horizontal").pack(fill="x", padx=14, pady=2)
        self.speed_lbl = tk.Label(right, text="60%", font=("Segoe UI", 9),
                                   bg=C["panel"], fg=C["green"])
        self.speed_lbl.pack(anchor="w", padx=14)
        self.speed_var.trace("w", lambda *_: self.speed_lbl.config(
            text=f"{int(self.speed_var.get())}%"))

        section("Delay Before Start")
        self.delay_var = tk.IntVar(value=3)
        delay_row = tk.Frame(right, bg=C["panel"])
        delay_row.pack(anchor="w", padx=14)
        ttk.Spinbox(delay_row, from_=0, to=60, textvariable=self.delay_var,
                    width=5, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(delay_row, text=" seconds", font=("Segoe UI", 8),
                 bg=C["panel"], fg=C["muted"]).pack(side="left")

        section("Progress")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("G.Horizontal.TProgressbar",
                         troughcolor="#1a1a1a", background="#00e676", thickness=10)
        self.prog_var = tk.DoubleVar(value=0)
        ttk.Progressbar(right, variable=self.prog_var, maximum=100,
                         style="G.Horizontal.TProgressbar").pack(fill="x", padx=14, pady=2)
        self.prog_lbl = tk.Label(right, text="0%", font=("Segoe UI", 9),
                                  bg=C["panel"], fg=C["green"])
        self.prog_lbl.pack(anchor="w", padx=14)

        # Divider
        tk.Frame(right, bg=C["border"], height=1).pack(fill="x", padx=14, pady=14)

        self.start_btn = tk.Button(right, text="▶  Start Typing", bg="#004d40", fg="white",
                                    font=("Segoe UI", 11, "bold"), relief="flat", pady=9,
                                    cursor="hand2", command=self._start_typing)
        self.start_btn.pack(fill="x", padx=14, pady=2)

        self.stop_btn = tk.Button(right, text="⏹  Stop", bg="#b71c1c", fg="white",
                                   font=("Segoe UI", 11, "bold"), relief="flat", pady=9,
                                   state="disabled", cursor="hand2", command=self._stop_typing)
        self.stop_btn.pack(fill="x", padx=14, pady=2)

        tk.Frame(right, bg=C["border"], height=1).pack(fill="x", padx=14, pady=10)
        self.usage_lbl = tk.Label(right, text="Sessions today: 0",
                                   font=("Segoe UI", 8), bg=C["panel"], fg=C["muted"])
        self.usage_lbl.pack(anchor="w", padx=14)

        # ── Status bar
        sb = tk.Frame(self.root, bg="#0a0a0a", height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self.status_lbl = tk.Label(sb, text="Ready", font=("Segoe UI", 9),
                                    bg="#0a0a0a", fg=C["muted"])
        self.status_lbl.pack(side="left", padx=14, pady=4)
        self.conn_dot = tk.Label(sb, text="●", font=("Segoe UI", 10),
                                  bg="#0a0a0a", fg=C["muted"])
        self.conn_dot.pack(side="right", padx=14)

    # ─── License flow ─────────────────────────────────────────────────────────
    def _start_license_check(self):
        self.is_licensed = False
        self._set_lic_status("🔒 Checking license...", self.C["orange"], "#1a1400")
        threading.Thread(target=self._check_thread, daemon=True).start()

    def _check_thread(self):
        local = self.lic_mgr.load_license()
        if local:
            valid, msg, expiry = self.lic_mgr.validate_key(local["key"])
            if valid:
                # Server confirm
                try:
                    r = requests.post(f"{SERVER_URL}/api/device/validate_license", json={
                        "device_id":   self.device_id,
                        "license_key": local["key"],
                        "app_version": APP_VERSION,
                    }, timeout=10)
                    if r.status_code == 200:
                        j = r.json()
                        if j.get("valid"):
                            self.root.after(0, lambda e=expiry: self._unlock(e, offline=False))
                            return
                        if j.get("revoked"):
                            self.lic_mgr.delete_license()
                            self.root.after(0, lambda: self._show_activation("License revoked by administrator"))
                            return
                        # Server says invalid but local says valid — trust server
                        self.root.after(0, lambda: self._show_activation("Server rejected license"))
                        return
                except Exception:
                    # Server unreachable — trust local
                    self.root.after(0, lambda e=expiry: self._unlock(e, offline=True))
                    return
            else:
                if "expired" in msg.lower():
                    self.lic_mgr.delete_license()

        self.root.after(0, lambda: self._show_activation())

    def _unlock(self, expiry: int, offline: bool = False):
        self.is_licensed    = True
        self.license_expiry = expiry
        exp_text            = self.lic_mgr.expiry_display(expiry)
        days_left           = (datetime.fromtimestamp(expiry) - datetime.now()).days
        exp_color           = self.C["orange"] if days_left < 30 else self.C["muted"]
        suffix              = "  (offline)" if offline else ""

        self._set_lic_status(f"✅ Licensed{suffix}", self.C["green"], "#0a1f0a")
        self.expiry_lbl.config(text=exp_text, bg="#0a1f0a", fg=exp_color)
        self._status("Ready to type", self.C["green"])

        self._start_heartbeat()
        self._start_expiry_watch()

    def _set_lic_status(self, text: str, fg: str, bar_bg: str):
        self.lic_bar.config(bg=bar_bg)
        self.lic_lbl.config(text=text, fg=fg, bg=bar_bg)

    def _show_activation(self, reason: str = ""):
        def _build():
            dlg = tk.Toplevel(self.root)
            dlg.title("AriTyper — Activation Required")
            dlg.geometry("530x660")
            dlg.configure(bg="#0d0d0d")
            dlg.transient(self.root)
            dlg.grab_set()
            dlg.resizable(False, False)

            # Center on screen
            dlg.update_idletasks()
            sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
            dlg.geometry(f"530x660+{(sw-530)//2}+{(sh-660)//2}")

            tk.Label(dlg, text="🔐 Activate AriTyper",
                     font=("Segoe UI", 18, "bold"), bg="#0d0d0d", fg="#00e676").pack(pady=(24, 4))

            if reason:
                tk.Label(dlg, text=reason, font=("Segoe UI", 9),
                         bg="#0d0d0d", fg="#f44336").pack(pady=(0, 6))

            # Device ID display
            id_frame = tk.Frame(dlg, bg="#161616",
                                highlightbackground="#2979ff", highlightthickness=1)
            id_frame.pack(padx=30, pady=6, fill="x")
            tk.Label(id_frame, text="Your Device ID (send this to admin):",
                     font=("Segoe UI", 8), bg="#161616", fg="#9e9e9e").pack(padx=8, pady=(6, 1), anchor="w")
            tk.Label(id_frame, text=self.device_id, font=("Courier", 10, "bold"),
                     bg="#161616", fg="#90caf9").pack(padx=8, pady=(0, 8), anchor="w")

            def copy_id():
                dlg.clipboard_clear()
                dlg.clipboard_append(self.device_id)
                messagebox.showinfo("Copied", "Device ID copied!", parent=dlg)

            tk.Button(id_frame, text="📋 Copy", bg="#1a237e", fg="white", font=("Segoe UI", 8),
                      relief="flat", padx=8, pady=3, command=copy_id).pack(padx=8, pady=(0, 8), anchor="e")

            # Payment box
            pay = tk.Frame(dlg, bg="#0f2010",
                           highlightbackground="#1b5e20", highlightthickness=1)
            pay.pack(padx=30, pady=8, fill="x")
            tk.Label(pay, text="💰 Purchase License — UGX 10,000",
                     font=("Segoe UI", 10, "bold"), bg="#0f2010", fg="#69f0ae").pack(pady=(10, 4))

            instructions = (
                "📱 MTN Mobile Money\n"
                "   Dial *165#  →  Pay a Bill\n"
                "   Merchant ID : 7074948\n"
                "   Amount      : UGX 10,000\n\n"
                "📱 Airtel Money\n"
                "   Dial *185#  →  Make Payments\n"
                "   Merchant ID : 66562536\n"
                "   Amount      : UGX 10,000\n\n"
                "After payment:\n"
                "  Send your Transaction ID + Device ID\n"
                "  to WhatsApp: +256 760 730 254\n"
                "  License key delivered within minutes."
            )
            tk.Label(pay, text=instructions, font=("Courier", 9),
                     bg="#0f2010", fg="#b9f6ca", justify="left").pack(padx=14, pady=(0, 12))

            # License key entry
            tk.Label(dlg, text="License Key:", font=("Segoe UI", 10, "bold"),
                     bg="#0d0d0d", fg="#e0e0e0").pack(pady=(10, 3))
            key_e = tk.Entry(dlg, font=("Courier", 11), width=38, bg="#1a1a1a", fg="#e0e0e0",
                             insertbackground="#00e676", relief="flat",
                             highlightbackground="#2979ff", highlightthickness=1)
            key_e.pack(ipady=7)
            key_e.focus()

            # Transaction ID (optional)
            tk.Label(dlg, text="Transaction ID (optional):", font=("Segoe UI", 8),
                     bg="#0d0d0d", fg="#616161").pack(pady=(6, 2))
            tx_e = tk.Entry(dlg, font=("Segoe UI", 10), width=38, bg="#1a1a1a", fg="#e0e0e0",
                            insertbackground="#00e676", relief="flat",
                            highlightbackground="#424242", highlightthickness=1)
            tx_e.pack(ipady=5)

            act_msg = tk.Label(dlg, text="", font=("Segoe UI", 9), bg="#0d0d0d", fg="#f44336")
            act_msg.pack(pady=4)

            # ── Activate action
            def activate():
                key = key_e.get().strip()
                tx  = tx_e.get().strip()
                if not key:
                    act_msg.config(text="Please enter your license key.", fg="#f44336")
                    return

                act_msg.config(text="Validating locally...", fg="#ff9100")
                dlg.update()

                valid, msg_text, expiry = self.lic_mgr.validate_key(key)
                if not valid:
                    act_msg.config(text=f"❌ {msg_text}", fg="#f44336")
                    return

                act_msg.config(text="Confirming with server...", fg="#ff9100")
                dlg.update()

                try:
                    r = requests.post(f"{SERVER_URL}/api/device/validate_license", json={
                        "device_id":      self.device_id,
                        "license_key":    key,
                        "transaction_id": tx,
                        "app_version":    APP_VERSION,
                    }, timeout=15)

                    if r.status_code == 200:
                        j = r.json()
                        if j.get("valid"):
                            self.lic_mgr.save_license(key, expiry, tx)
                            dlg.destroy()
                            self._unlock(expiry)
                            messagebox.showinfo("Activated!",
                                "🎉 AriTyper is now active!\n"
                                f"License valid for {int((expiry - time.time()) / 86400)} days.")
                        elif j.get("pending"):
                            act_msg.config(text="⏳ Pending admin approval — try again soon.", fg="#ff9100")
                        else:
                            act_msg.config(text=f"❌ {j.get('message', 'Server rejected key.')}", fg="#f44336")
                    else:
                        act_msg.config(text=f"Server error {r.status_code} — try again.", fg="#f44336")

                except Exception:
                    # Server unreachable — trust local validation
                    self.lic_mgr.save_license(key, expiry, tx)
                    dlg.destroy()
                    self._unlock(expiry, offline=True)

            def whatsapp():
                import webbrowser, urllib.parse
                tx  = tx_e.get().strip()
                msg = (f"Hello! I paid UGX 10,000 for AriTyper.\n"
                       f"Transaction ID: {tx or 'N/A'}\n"
                       f"Device ID: {self.device_id}")
                webbrowser.open(f"https://wa.me/256760730254?text={urllib.parse.quote(msg)}")

            btn_row = tk.Frame(dlg, bg="#0d0d0d")
            btn_row.pack(pady=10)
            for label, color, cmd in [
                ("🔑 Activate",       "#00695c", activate),
                ("💬 WhatsApp Admin", "#1565c0", whatsapp),
                ("✕ Close",           "#b71c1c", dlg.destroy),
            ]:
                tk.Button(btn_row, text=label, bg=color, fg="white",
                          font=("Segoe UI", 10, "bold"), relief="flat",
                          padx=12, pady=7, cursor="hand2", command=cmd).pack(side="left", padx=4)

            key_e.bind("<Return>", lambda _: activate())

        self.root.after(0, _build)

    # ─── Background threads ───────────────────────────────────────────────────
    def _start_heartbeat(self):
        def loop():
            while True:
                try:
                    r = requests.post(f"{SERVER_URL}/api/device_heartbeat", json={
                        "device_id":   self.device_id,
                        "hostname":    socket.gethostname(),
                        "os_info":     f"{platform.system()} {platform.release()}",
                        "app_version": APP_VERSION,
                        "status":      "active",
                    }, timeout=10)

                    if r.status_code == 200:
                        self.root.after(0, lambda: self.conn_dot.config(fg=self.C["green"]))
                        j = r.json()
                        if j.get("command") == "deactivate":
                            reason = j.get("reason", "Deactivated by admin")
                            self.root.after(0, lambda re=reason: self._force_deactivate(re))
                        if j.get("update_available"):
                            self.root.after(0, lambda ji=j: self._notify_update(ji))
                    else:
                        self.root.after(0, lambda: self.conn_dot.config(fg=self.C["orange"]))
                except Exception:
                    self.root.after(0, lambda: self.conn_dot.config(fg=self.C["muted"]))

                time.sleep(60)

        threading.Thread(target=loop, daemon=True).start()

    def _start_expiry_watch(self):
        def loop():
            while True:
                time.sleep(1800)  # check every 30 min
                if self.license_expiry > 0 and time.time() > self.license_expiry:
                    self.root.after(0, self._on_expired)
                    break

        threading.Thread(target=loop, daemon=True).start()

    def _on_expired(self):
        self.is_licensed = False
        self.lic_mgr.delete_license()
        messagebox.showwarning("License Expired",
            "Your AriTyper license has expired.\n\n"
            "Please purchase a renewal to continue.\n"
            "Contact: +256 760 730 254")
        self._show_activation("License expired — please renew")

    def _force_deactivate(self, reason: str):
        self.is_licensed = False
        self.lic_mgr.delete_license()
        messagebox.showerror("Deactivated", f"Your license was deactivated.\n\nReason: {reason}")
        self._show_activation(f"Deactivated: {reason}")

    def _notify_update(self, info: dict):
        import webbrowser
        if messagebox.askyesno("Update Available",
                               f"Version {info.get('latest_version')} is out! Download now?"):
            webbrowser.open(info.get("download_url", "https://arityper-website.vercel.app"))

    # ─── Text actions ─────────────────────────────────────────────────────────
    def _paste(self):
        try:
            t = self.root.clipboard_get()
            self.txt.delete("1.0", tk.END)
            self.txt.insert("1.0", t)
            self._refresh_chars()
            self._status(f"Pasted {len(t):,} chars", self.C["green"])
        except Exception as e:
            messagebox.showerror("Paste Error", str(e))

    def _clear(self):
        self.txt.delete("1.0", tk.END)
        self._refresh_chars()
        self._status("Cleared", self.C["muted"])

    def _refresh_chars(self):
        n = len(self.txt.get("1.0", tk.END)) - 1
        self.char_lbl.config(text=f"{n:,} chars")

    def _load_file(self):
        path = filedialog.askopenfilename(filetypes=[
            ("All supported", "*.txt *.docx *.pdf"),
            ("Text files",    "*.txt"),
            ("Word docs",     "*.docx"),
            ("PDF files",     "*.pdf"),
        ])
        if not path:
            return

        try:
            ext     = os.path.splitext(path)[1].lower()
            content = ""

            if ext == ".txt":
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

            elif ext == ".docx":
                if not DOCX_AVAILABLE:
                    messagebox.showerror("Missing Library",
                        "python-docx is not installed.\nRun: pip install python-docx")
                    return
                doc   = Document(path)
                lines = []
                for para in doc.paragraphs:
                    text  = para.text
                    align = self._docx_align(para)
                    prefix = {
                        "center":  "[CENTER]",
                        "right":   "[RIGHT]",
                        "justify": "[JUSTIFY]",
                    }.get(align, "")
                    lines.append(prefix + text)
                content = "\n".join(lines)

            elif ext == ".pdf":
                if not PDF_AVAILABLE:
                    messagebox.showerror("Missing Library",
                        "PyPDF2 is not installed.\nRun: pip install PyPDF2")
                    return
                with open(path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    pages  = [p.extract_text() or "" for p in reader.pages]
                content = "\n\n".join(pages)

            self.txt.delete("1.0", tk.END)
            self.txt.insert("1.0", content)
            self._refresh_chars()
            self._status(f"Loaded: {os.path.basename(path)}", self.C["green"])

        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load:\n{e}")

    def _docx_align(self, paragraph) -> str:
        try:
            a = paragraph.paragraph_format.alignment
            if a == WD_ALIGN_PARAGRAPH.CENTER:  return "center"
            if a == WD_ALIGN_PARAGRAPH.RIGHT:   return "right"
            if a == WD_ALIGN_PARAGRAPH.JUSTIFY: return "justify"
        except Exception:
            pass
        return "left"

    # ─── Window selection ─────────────────────────────────────────────────────
    def _dlg_windows(self):
        if not WIN32_AVAILABLE:
            messagebox.showinfo("Windows Only",
                "Window selection requires Windows with pywin32.\n"
                "Install: pip install pywin32")
            return

        wins = []

        def cb(hwnd, _):
            try:
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title.strip():
                        rect = win32gui.GetWindowRect(hwnd)
                        w, h = rect[2] - rect[0], rect[3] - rect[1]
                        if w > 200 and h > 100 and "AriTyper" not in title:
                            wins.append((hwnd, title, w, h))
            except Exception:
                pass
            return True

        win32gui.EnumWindows(cb, None)
        wins.sort(key=lambda x: x[1].lower())

        if not wins:
            messagebox.showinfo("No Windows", "No suitable windows found.")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Select Target Window")
        dlg.geometry("600x400")
        dlg.configure(bg="#0d0d0d")
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="🪟 Select window to type into",
                 font=("Segoe UI", 12, "bold"), bg="#0d0d0d", fg="#e0e0e0").pack(pady=12)

        frm = tk.Frame(dlg, bg="#161616")
        frm.pack(fill="both", expand=True, padx=20)
        sb  = tk.Scrollbar(frm)
        sb.pack(side="right", fill="y")
        lb  = tk.Listbox(frm, font=("Consolas", 9), bg="#111111", fg="#e0e0e0",
                          selectmode="single", yscrollcommand=sb.set,
                          relief="flat", highlightthickness=0, selectbackground="#2979ff")
        lb.pack(side="left", fill="both", expand=True)
        sb.config(command=lb.yview)

        for _, title, w, h in wins:
            lb.insert(tk.END, f"  {title[:58]}  [{w}×{h}]")

        if wins:
            lb.selection_set(0)

        def select():
            sel = lb.curselection()
            if sel:
                hwnd, title, w, h = wins[sel[0]]
                self.target_hwnd = hwnd
                self.win_lbl.config(text=f"→ {title[:30]}", fg=self.C["green"])
                dlg.destroy()

        br = tk.Frame(dlg, bg="#0d0d0d")
        br.pack(pady=10)
        tk.Button(br, text="✓ Select", bg="#00695c", fg="white",
                  font=("Segoe UI", 10), relief="flat", padx=14, pady=6,
                  cursor="hand2", command=select).pack(side="left", padx=5)
        tk.Button(br, text="✕ Cancel", bg="#b71c1c", fg="white",
                  font=("Segoe UI", 10), relief="flat", padx=14, pady=6,
                  cursor="hand2", command=dlg.destroy).pack(side="left", padx=5)

        lb.bind("<Double-Button-1>", lambda _: select())

    # ─── Typing ───────────────────────────────────────────────────────────────
    def _start_typing(self):
        if not self.is_licensed:
            messagebox.showwarning("Not Licensed", "Please activate AriTyper first.")
            self._show_activation()
            return

        text = self.txt.get("1.0", tk.END).rstrip("\n")
        if not text.strip():
            messagebox.showwarning("No Text", "Please enter or load text first.")
            return

        if not self.target_hwnd:
            messagebox.showwarning("No Window", "Please select a target window first.")
            return

        if not self._check_daily_limit():
            return

        self._stop    = False
        self.is_typing= True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.prog_var.set(0)
        self.prog_lbl.config(text="0%")

        delay_secs = self.delay_var.get()
        speed_pct  = self.speed_var.get()
        # Map 1–100 % → 0.20 s–0.01 s per character
        char_delay = 0.01 + (1 - speed_pct / 100) * 0.19

        def run():
            # Countdown
            for i in range(delay_secs, 0, -1):
                self.root.after(0, lambda x=i:
                    self._status(f"Starting in {x}s — switch to target window!", self.C["orange"]))
                time.sleep(1)

            # Focus target window
            try:
                win32gui.ShowWindow(self.target_hwnd, win32con.SW_RESTORE)
                time.sleep(0.25)
                win32gui.SetForegroundWindow(self.target_hwnd)
                time.sleep(0.4)
            except Exception as e:
                self.root.after(0, lambda:
                    self._status(f"Window focus failed: {e}", self.C["orange"]))

            self.root.after(0, lambda: self._status("⌨  Typing...", self.C["orange"]))

            self.typer.type_text(
                text, char_delay,
                progress_cb=self._update_prog,
                stop_flag=lambda: self._stop,
            )

            if self._stop:
                self.root.after(0, self._on_stopped)
            else:
                self.root.after(0, self._on_complete)

            self._record_session()

        threading.Thread(target=run, daemon=True).start()

    def _stop_typing(self):
        self._stop = True

    def _on_complete(self):
        self.is_typing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._status("✅ Typing complete!", self.C["green"])
        self._bump_sessions()

    def _on_stopped(self):
        self.is_typing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._status("Stopped by user", self.C["muted"])
        self._bump_sessions()

    def _update_prog(self, v: int):
        self.root.after(0, lambda: self.prog_var.set(v))
        self.root.after(0, lambda: self.prog_lbl.config(text=f"{v}%"))

    def _bump_sessions(self):
        self.sessions_today += 1
        self.usage_lbl.config(text=f"Sessions today: {self.sessions_today}")

    def _check_daily_limit(self) -> bool:
        try:
            r = requests.post(f"{SERVER_URL}/api/check_typing_limit",
                              json={"device_id": self.device_id}, timeout=8)
            if r.status_code == 200:
                j = r.json()
                if not j.get("allowed", True):
                    messagebox.showwarning("Daily Limit Reached",
                        f"You have used {j.get('used_today')} of "
                        f"{j.get('daily_limit')} sessions today.\n"
                        "Limit resets at midnight.")
                    return False
        except Exception:
            pass
        return True

    def _record_session(self):
        try:
            requests.post(f"{SERVER_URL}/api/record_typing_session",
                         json={"device_id": self.device_id, "windows_typed": 1},
                         timeout=5)
        except Exception:
            pass

    # ─── Helper dialogs ───────────────────────────────────────────────────────
    def _status(self, text: str, color: str = None):
        self.status_lbl.config(text=text, fg=color or self.C["muted"])

    def _dlg_device_id(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("My Device ID")
        dlg.geometry("440x170")
        dlg.configure(bg="#0d0d0d")
        dlg.transient(self.root)

        tk.Label(dlg, text="Your Device ID (share with admin to get a license key):",
                 font=("Segoe UI", 9), bg="#0d0d0d", fg="#9e9e9e").pack(pady=(20, 5))

        v = tk.StringVar(value=self.device_id)
        e = tk.Entry(dlg, textvariable=v, font=("Courier", 11), width=35,
                     state="readonly", bg="#161616", fg="#00e676",
                     readonlybackground="#161616", relief="flat")
        e.pack(ipady=8)

        def copy():
            dlg.clipboard_clear()
            dlg.clipboard_append(self.device_id)
            messagebox.showinfo("Copied", "Device ID copied to clipboard!", parent=dlg)

        tk.Button(dlg, text="📋 Copy Device ID", bg="#1565c0", fg="white",
                  font=("Segoe UI", 10), relief="flat", padx=12, pady=6,
                  cursor="hand2", command=copy).pack(pady=14)

    def _dlg_payment(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("How to Pay — AriTyper")
        dlg.geometry("480x500")
        dlg.configure(bg="#0d0d0d")
        dlg.transient(self.root)

        tk.Label(dlg, text="💰 How to Purchase AriTyper",
                 font=("Segoe UI", 14, "bold"), bg="#0d0d0d", fg="#00e676").pack(pady=(20, 12))

        guide = (
            "🟡 MTN Mobile Money\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  1. Dial *165#\n"
            "  2. Select  →  Pay a Bill\n"
            "  3. Merchant ID : 7074948\n"
            "  4. Amount      : UGX 10,000\n"
            "  5. Enter PIN  →  Confirm\n"
            "  6. Save the Transaction ID  ✓\n\n"
            "🔴 Airtel Money\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  1. Dial *185#\n"
            "  2. Select  →  Make Payments\n"
            "  3. Merchant ID : 66562536\n"
            "  4. Amount      : UGX 10,000\n"
            "  5. Enter PIN  →  Confirm\n"
            "  6. Save the Transaction ID  ✓\n\n"
            "📲 After Payment\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  Send Transaction ID + Device ID\n"
            "  to WhatsApp: +256 760 730 254\n"
            "  → License key delivered in minutes!"
        )
        tk.Label(dlg, text=guide, font=("Courier", 9), bg="#0d0d0d",
                 fg="#b9f6ca", justify="left").pack(padx=24)

        import webbrowser
        tk.Button(dlg, text="💬 Open WhatsApp", bg="#1565c0", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=7,
                  cursor="hand2",
                  command=lambda: webbrowser.open(
                      "https://wa.me/256760730254?text=I%20want%20to%20buy%20AriTyper"
                  )).pack(pady=16)

    def _dlg_about(self):
        messagebox.showinfo("About AriTyper",
            "AriTyper v3.0\n"
            "Professional Auto-Typing Tool\n\n"
            "Powered by ArihoForge\n"
            "© 2026 ArihoForge. All rights reserved.\n\n"
            "Contact : +256 760 730 254\n"
            "Website : arityper-website.vercel.app")


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════
def main():
    root = tk.Tk()
    AriTyper(root)
    root.mainloop()

if __name__ == "__main__":
    main()
