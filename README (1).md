# HIDHunter

A lightweight background tool that detects files silently downloaded from the internet — the pattern used by drive-by downloads and malware droppers — before you notice them yourself.

**Platform:** Windows only (uses the Windows NTFS Mark-of-the-Web / Zone.Identifier feature)

## What it does

HIDHunter watches three common "landing zones" for internet-sourced files:
- `Downloads`
- `AppData\Roaming`
- `AppData\Local\Temp`

For every new or changed file, it checks two things:
1. Does the file carry Windows' hidden "Mark of the Web" tag (proof it came from the internet)?
2. Does it have a risky, code-executing extension (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.scr`, `.js`, `.jar`)?

If both are true, it raises an alert — a desktop notification, a red system tray icon, and a logged entry with a SHA256 hash of the file.

## Why this matters

Malicious websites can silently write files to disk without any visible download bar or user action. HIDHunter surfaces these events so they don't go unnoticed.

## Installation

```bash
git clone https://github.com/<your-username>/HIDHunter.git
cd HIDHunter
pip install -r requirements.txt
```

## Usage

```bash
python hidhunter.py
```

A green tray icon will appear near your system clock — HIDHunter is now monitoring in the background.

To run with no visible console window:
```bash
pythonw hidhunter.py
```

## What you'll see

- **Idle:** green tray icon, no popups
- **Detection:** tray icon turns red, a notification appears, and the event is logged to `hidhunter_alerts.txt`
- **Full activity log:** every file event (flagged or not) is recorded in `hidhunter_log.txt`

Right-click the tray icon for options: **Open Alerts Log**, **Exit**.

## Limitations

- Windows-only (Mark-of-the-Web is an NTFS/Windows feature)
- Does not scan file contents — detection is based on file origin + extension, not signatures
- Does not inspect inside archive files (`.zip`, `.rar`)
- Legitimate internet downloads with risky extensions will also be flagged — this is expected; the tool surfaces origin, not intent
- No auto-remediation by design — HIDHunter only informs, it never deletes or moves files

## Future Improvements

HIDHunter currently focuses on a specific, narrow detection method (Mark-of-the-Web + risky file extensions), by design, to keep the tool lightweight and easy to reason about. Planned or possible extensions include:

- VirusTotal API integration for hash-based reputation checks on flagged files
- Running as a proper Windows Service instead of Task Scheduler, for better persistence and tamper-resistance
- Basic content inspection of archive files (`.zip`, `.rar`)
- Configurable watch folders and extensions via a config file, instead of editing source code
- Log rotation to prevent unbounded log file growth over long runtimes
- Cross-platform support for non-Windows systems

## License

MIT
