# APK Risk Analyzer

A lightweight desktop application to analyze Android APK files and provide security risk assessments. Get instant verdicts on whether an APK is **safe to use**, **potentially dangerous**, or **dangerous/malware suspected**.

## Features

✅ **Static APK Analysis** — Extracts and analyzes APK metadata without executing code  
✅ **Risk Scoring** — Heuristic-based scoring system that evaluates multiple risk factors  
✅ **Detailed Reports** — Get reasons behind each verdict, including suspicious permissions, missing signatures, and more  
✅ **Beautiful UI** — Modern dark-themed Tkinter interface with color-coded verdicts  
✅ **Fast Analysis** — Analyzes most APKs in seconds  
✅ **No Dependencies** — Uses only Python standard library (zipfile, tkinter, os, re, math)  

## Risk Factors Analyzed

The analyzer checks for:
- **Missing AndroidManifest.xml** — indicates invalid or obfuscated APK
- **Missing META-INF signatures** — no signature verification possible
- **Suspicious permissions** — SMS, contacts, call logs, accessibility service, etc.
- **Multiple DEX files** — often indicates code obfuscation or payload injection
- **Native libraries (.so files)** — native code execution capability
- **Suspicious file names** — "payload", "trojan", "malware", "inject", etc.
- **File count and assets** — excessive files may indicate dropper/loader malware

## Installation

### Requirements
- Python 3.7+
- No external packages needed (uses only standard library)

### Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/apk-risk-analyzer.git
cd apk-risk-analyzer
```

2. Verify Python is installed:
```bash
python --version
```

## Usage

### Running the GUI

From the project folder, run:

```bash
python app.py
```

Or without generating `__pycache__`:
```bash
python -B app.py
```

### GUI Workflow

1. **Select APK** — Click "Choose APK File" and pick an APK from your system
2. **Analyze** — Click "Analyze APK" to run the static analysis
3. **View Results** — See the verdict, confidence score, and detailed reasons

### Verdict Types

| Verdict | Meaning | Confidence |
|---------|---------|-----------|
| 🟢 **Safe to use** | No strong risk indicators detected | < 50% |
| 🟡 **Potentially dangerous** | Some suspicious features found | 50-75% |
| 🔴 **Dangerous / malware suspected** | Multiple high-risk indicators | ≥ 75% |


## Project Structure

```
apk-risk-analyzer/
├── app.py                 # GUI frontend (Tkinter)
├── apk_analyzer.py        # Backend analysis engine
├── README.md             # This file
└── .gitignore            # Git ignore rules
```

## How It Works

### Backend Logic (`apk_analyzer.py`)

1. **Extract APK contents** — APK is a ZIP archive, so we read its file structure
2. **Parse AndroidManifest.xml** — Extract permission strings and metadata
3. **Calculate risk score** — Weight various features and sum them into a heuristic score
4. **Apply sigmoid function** — Convert raw score to confidence percentage
5. **Generate verdict** — Classify as Safe, Suspicious, or Dangerous

## Disclaimer

This tool is provided for educational and research purposes. Users are responsible for ensuring they have permission to analyze APKs they test. The creators are not responsible for misuse or any damage caused by this tool.
