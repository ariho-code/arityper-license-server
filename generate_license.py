#!/usr/bin/env python3
"""
AriTyper License Key Generator — SERVER SIDE TOOL
Powered by ArihoForge

Run this on YOUR machine (never distribute it to customers).
Give the output key to the customer after they pay.

Usage:
    python generate_license.py                  # interactive mode
    python generate_license.py --device ARI3-XXXX --months 3
    python generate_license.py --validate ARI3-XXXX-XXXXX-XXXXX-XXXXX-XXXXX --device ARI3-XXXX

Requirements:
    pip install colorama   (optional, for colored output)
"""

import hashlib
import hmac
import struct
import base64
import time
import sys
import argparse
from datetime import datetime, timedelta

# ══════════════════════════════════════════════════════════════════════════════
#  ⚠  MUST match the constant in arityper_v3.py  ⚠
# ══════════════════════════════════════════════════════════════════════════════
LICENSE_SECRET = "ArihoForge_HmacSecret_2026_v3_CHANGEME"


class KeyGen:

    def __init__(self, secret: str = LICENSE_SECRET):
        self.secret = secret

    def _device_hash(self, device_id: str) -> bytes:
        return hashlib.sha256(device_id.encode()).digest()[:8]

    def _make_mac(self, dev_hash: bytes, expiry_b: bytes) -> bytes:
        return hmac.new(self.secret.encode(), dev_hash + expiry_b, hashlib.sha256).digest()[:8]

    # ── Generate ──────────────────────────────────────────────────────────────
    def generate(self, device_id: str, months: int = 3) -> str:
        """
        Create a license key bound to device_id, valid for `months` months.
        """
        device_id = device_id.strip().upper()
        dev_hash  = self._device_hash(device_id)
        expiry    = int(time.time()) + months * 30 * 24 * 3600
        expiry_b  = struct.pack(">Q", expiry)
        mac       = self._make_mac(dev_hash, expiry_b)

        payload   = base64.b32encode(dev_hash + expiry_b + mac).decode().rstrip("=")

        # Format: ARI3-XXXXX-XXXXX-XXXXX-XXXXX
        chunks = [payload[i:i+5] for i in range(0, len(payload), 5)]
        key    = "ARI3-" + "-".join(chunks)
        return key

    # ── Validate ──────────────────────────────────────────────────────────────
    def validate(self, key: str, device_id: str):
        """
        Returns (valid: bool, message: str, expiry_datetime or None)
        """
        device_id = device_id.strip().upper()
        try:
            clean   = (key.upper()
                         .replace("ARI3-", "")
                         .replace("ARI-",  "")
                         .replace("-",     "")
                         .replace(" ",     ""))
            pad     = (8 - len(clean) % 8) % 8
            payload = base64.b32decode(clean + "=" * pad)

            if len(payload) < 24:
                return False, "Key too short", None

            stored_dev = payload[:8]
            expiry_b   = payload[8:16]
            stored_mac = payload[16:24]

            # Device check
            dev_hash = self._device_hash(device_id)
            if stored_dev != dev_hash:
                return False, "Device ID mismatch", None

            # Expiry check
            expiry     = struct.unpack(">Q", expiry_b)[0]
            expiry_dt  = datetime.fromtimestamp(expiry)
            if time.time() > expiry:
                return False, f"EXPIRED on {expiry_dt.strftime('%Y-%m-%d')}", expiry_dt

            # HMAC check
            expected = self._make_mac(stored_dev, expiry_b)
            if not hmac.compare_digest(stored_mac, expected):
                return False, "HMAC invalid — key tampered or wrong secret", None

            days_left = (expiry_dt - datetime.now()).days
            return True, f"VALID — {days_left} days left, expires {expiry_dt.strftime('%Y-%m-%d')}", expiry_dt

        except Exception as e:
            return False, f"Parse error: {e}", None

    # ── Revoke helper (you call the server API manually) ──────────────────────
    def print_revoke_instructions(self, device_id: str):
        print("\nTo revoke this license via your server API, send:")
        print(f"  POST {'{SERVER_URL}'}/api/device/revoke")
        print(f"  Body: {{ \"device_id\": \"{device_id}\" }}")


def _banner():
    print("=" * 60)
    print("  AriTyper License Key Generator  —  ArihoForge")
    print("=" * 60)


def _interactive(kg: KeyGen):
    _banner()
    print()
    print("1. Generate new key")
    print("2. Validate existing key")
    print("3. Quit")
    choice = input("\nChoice [1/2/3]: ").strip()

    if choice == "1":
        device_id = input("\nEnter customer Device ID (ARI3-...): ").strip()
        if not device_id:
            print("ERROR: Device ID cannot be empty.")
            return

        months_str = input("Valid for how many months? [default 3]: ").strip()
        months     = int(months_str) if months_str.isdigit() else 3

        key    = kg.generate(device_id, months)
        expiry = datetime.now() + timedelta(days=months * 30)

        print("\n" + "─" * 60)
        print(f"  Customer Device ID : {device_id}")
        print(f"  Validity           : {months} month(s)")
        print(f"  Expires            : {expiry.strftime('%Y-%m-%d')}")
        print(f"\n  LICENSE KEY ↓")
        print(f"\n  {key}\n")
        print("─" * 60)
        print("Send this key to the customer via WhatsApp/SMS.")

    elif choice == "2":
        key       = input("\nEnter license key: ").strip()
        device_id = input("Enter device ID  : ").strip()
        valid, msg, _ = kg.validate(key, device_id)
        icon = "✅" if valid else "❌"
        print(f"\n{icon}  {msg}")

    elif choice == "3":
        sys.exit(0)
    else:
        print("Invalid choice.")


def main():
    kg = KeyGen()

    if len(sys.argv) == 1:
        # Interactive mode
        _interactive(kg)
        return

    parser = argparse.ArgumentParser(description="AriTyper License Key Generator")
    parser.add_argument("--device",   help="Customer device ID")
    parser.add_argument("--months",   type=int, default=3, help="License duration in months")
    parser.add_argument("--validate", help="License key to validate")
    args = parser.parse_args()

    if args.validate:
        if not args.device:
            print("ERROR: --device is required when using --validate")
            sys.exit(1)
        valid, msg, _ = kg.validate(args.validate, args.device)
        print(f"{'VALID' if valid else 'INVALID'}: {msg}")
        sys.exit(0 if valid else 1)

    if args.device:
        key    = kg.generate(args.device, args.months)
        expiry = datetime.now() + timedelta(days=args.months * 30)
        print(f"\nDevice   : {args.device.upper()}")
        print(f"Duration : {args.months} month(s)  (expires {expiry.strftime('%Y-%m-%d')})")
        print(f"Key      : {key}\n")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
