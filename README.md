# Keylogger Detection and Analysis Platform

An educational ethical hacking platform for analyzing and detecting keylogger malware using YARA rules, Python static analysis, and PowerShell scripts.

## 🎓 Academic Project
- **Course**: B.Tech CSE Semester VII - Ethical Hacking and Prevention
- **Team**: Lavanya Bhati, Bhavya Mantoo, Shivaprasad Arunkumar Farale, Aarush Gupta
- **Supervisor**: Dr. Shobit Tyagi

## 🔒 Disclaimer
This project is created for **educational purposes only** to demonstrate defensive cybersecurity techniques. All code samples and detection methods are meant to be used in controlled, authorized environments for learning about malware detection and prevention.

## ✨ Features
- **Code Viewer**: Educational keylogger code viewer with syntax highlighting
- **YARA Scanner**: Rule editor and pattern matching for malware detection
- **Static Analysis**: Python import analyzer using pefile library
- **Modern UI**: Dark-themed cybersecurity interface with terminal-style design

## 🛠️ Technology Stack
- **Backend**: Python 3.11, Flask
- **Detection Tools**: yara-python, pefile, Pygments
- **Frontend**: Tailwind CSS, Vanilla JavaScript

## 📋 Prerequisites
- Python 3.11 or higher
- pip (Python package installer)

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<yourusername>/KeyLoggerDetectionAndAnalysis.git
   cd KeyLoggerDetectionAndAnalysis
   ```

2. **Install dependencies**:
   ```bash
   pip install flask jinja2 pefile pygments yara-python
   ```
   
   Or using the pyproject.toml:
   ```bash
   pip install -e .
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the platform**:
   - Open your browser and navigate to: `http://localhost:5000`

## 📁 Project Structure
```
.
├── app.py                    # Main Flask application
├── templates/                # HTML templates
│   ├── base.html            # Base template with navigation
│   ├── index.html           # Home page
│   ├── code_viewer.html     # Code viewer
│   ├── yara_scanner.html    # YARA rule editor
│   ├── static_analysis.html # Static analyzer
│   └── ...
├── static/                   # Static assets (CSS, JS, images)
├── detection_tools/          # Detection utilities
├── sample_code/              # Educational code samples
└── pyproject.toml           # Project dependencies

```

## 🔧 Usage

### YARA Scanner
1. Navigate to the YARA Scanner page
2. Write or paste YARA rules in the editor
3. Input code to scan for malicious patterns
4. View detailed match results

### Static Analysis
1. Go to the Static Analysis page
2. Paste Python code to analyze
3. View imported modules and suspicious patterns
4. Check PE file analysis results

## 🤝 Contributing
This is an academic project. If you'd like to contribute improvements or suggestions, feel free to open an issue or pull request.

## 📝 License
This project is created for educational purposes. Please ensure you have proper authorization before using any detection techniques in production environments.

## ⚠️ Ethical Use
- Only use these tools in authorized, controlled environments
- Obtain proper permissions before analyzing any systems
- Respect privacy and legal boundaries
- Use for defensive security and educational purposes only

## 👥 Team Members
- Lavanya Bhati
- Aarush Gupta
- Shivaprasad Arunkumar Farale
- Bhavya Mantoo

## 📧 Contact
For questions or concerns about this educational project, please contact the team through the university channels.

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
