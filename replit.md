# Keylogger Detection Platform

## Overview
An educational ethical hacking platform for analyzing and detecting keylogger malware using YARA rules, Python static analysis, and PowerShell scripts. This project demonstrates defensive cybersecurity techniques in a controlled, safe environment.

**Academic Project**: B.Tech CSE Semester VII - Ethical Hacking and Prevention  
**Team**: Lavanya Bhati, Bhavya Mantoo, Shivaprasad Arunkumar Farale, Aarush Gupta  
**Supervisor**: Dr. Shobit Tyagi

## Current State
The platform is fully functional with the following features:
- Educational keylogger code viewer with syntax highlighting
- YARA rule editor and pattern scanner
- Python static analysis tool for import inspection
- PowerShell script generator for Windows detection
- IoC (Indicators of Compromise) dashboard
- Dark-themed cybersecurity UI with terminal-style design

## Recent Changes (November 13, 2025)
- Initial project setup with Flask backend
- Implemented all detection tools and analysis features
- Created responsive web interface with Tailwind CSS
- Added sample keylogger code for educational purposes
- Integrated YARA-Python for pattern matching
- Built static analysis using pefile library
- Generated PowerShell scripts for persistence detection

## Project Architecture

### Technology Stack
- **Backend**: Python 3.11, Flask
- **Detection Tools**: yara-python, pefile, Pygments
- **Frontend**: Tailwind CSS, Vanilla JavaScript
- **Environment**: Replit with isolated development setup

### Directory Structure
```
.
├── app.py                    # Main Flask application
├── templates/                # HTML templates
│   ├── base.html            # Base template with navigation
│   ├── index.html           # Home page
│   ├── code_viewer.html     # Code viewer with syntax highlighting
│   ├── yara_scanner.html    # YARA rule editor and scanner
│   ├── static_analysis.html # Python import analyzer
│   ├── powershell_generator.html # PowerShell script generator
│   └── ioc_dashboard.html   # Indicators of Compromise dashboard
├── static/                   # Static assets
│   ├── css/
│   ├── js/
│   └── images/
├── detection_tools/          # Detection utilities
└── sample_code/             # Educational samples
```

### Key Features

#### 1. Code Viewer
- View educational keylogger samples with syntax highlighting
- Analyze Python-based keylogger structure
- Identify suspicious imports and behaviors
- Support for custom code analysis

#### 2. YARA Scanner
- Create and test YARA rules
- Pattern-based malware detection
- Real-time scanning of code samples
- Pre-loaded detection rules for common keylogger patterns

#### 3. Static Analysis
- **Source Code Analysis**: Python import inspection, file operation detection, network activity identification
- **Binary Analysis (PE Files)**: Using pefile library to extract and analyze Windows executables (.exe, .dll)
  - Import table extraction and DLL dependency mapping
  - Suspicious Windows API detection (GetAsyncKeyState, SetWindowsHookEx, etc.)
  - PE section analysis with entropy calculation
  - Detection of packed/encrypted sections
- Risk scoring algorithm for both source and binary analysis
- SHA-256 and MD5 hash generation

#### 4. PowerShell Generator
- Process monitoring scripts
- Persistence mechanism detection
- File scanning utilities
- Registry and startup folder checks

#### 5. IoC Dashboard
- Comprehensive indicator documentation
- File hashes and signatures
- Defensive measures and mitigations
- Network and behavioral indicators

## Ethical Guidelines

### Critical Constraints
1. **Educational Purpose Only**: All content is for defensive research and learning
2. **No Code Execution**: Static analysis only - no malicious code is run
3. **Isolated Environment**: All analysis in sandboxed VM with no network access
4. **No Real Data**: No user data captured or transmitted
5. **Legal Compliance**: Uses publicly available educational resources

### Warning Banner
Every page displays: "⚠️ EDUCATIONAL PURPOSE ONLY - All analysis performed in controlled lab environment for defensive research"

## API Endpoints

### `/api/scan-with-yara` (POST)
Scans code using custom YARA rules
- Input: `{ "rule": "...", "code": "..." }`
- Output: Match results with rule names and strings

### `/api/analyze-imports` (POST)
Analyzes Python source code for suspicious patterns
- Input: `{ "code": "..." }`
- Output: Suspicious imports, file ops, network ops, risk score

### `/api/analyze-binary` (POST)
Analyzes PE (Portable Executable) binaries using pefile library
- Input: Form data with 'binary' file (max 10MB)
- Output: Import table, DLL dependencies, suspicious Windows APIs, PE sections with entropy, binary metadata, risk score
- Detects: Keylogger-related Windows API calls (keyboard hooks, input capture, clipboard access)

### `/api/get-sample-code/<type>` (GET)
Retrieves educational code samples
- Types: `keylogger`, `persistence`
- Output: Code with syntax highlighting

### `/api/generate-powershell` (POST)
Generates PowerShell detection scripts
- Input: `{ "type": "process_monitor|persistence_check|file_monitor" }`
- Output: PowerShell script with highlighting

## Development Notes

### Running the Application
```bash
python app.py
# Accessible at http://0.0.0.0:5000
```

### Environment Variables
- `SESSION_SECRET`: Flask session secret (auto-configured)

### Dependencies
- Flask (web framework)
- yara-python (pattern matching)
- pefile (PE file analysis)
- Pygments (syntax highlighting)
- Jinja2 (templating)

## Security Considerations
- No actual malware execution
- All samples are educational/synthetic
- Static analysis methods only
- Proper input validation on all endpoints
- Session secrets properly managed

## Future Enhancements
- PDF/DOCX report generation
- Real-time YARA scanning with file upload
- Interactive system architecture visualizer
- Educational modules on detection techniques
- Detection history tracking and comparison
- Machine learning-based detection models

## References
- YARA Documentation: https://yara.readthedocs.io/
- pefile Library: https://github.com/erocarrera/pefile
- Keylogger Detection Research: Academic literature on malware analysis
- Windows Sysinternals: Process and persistence analysis tools

## License
Educational project for academic purposes only. Not for commercial use or malicious intent.
