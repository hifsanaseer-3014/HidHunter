# HIDHunter

A lightweight background tool that detects files silently downloaded from the internet — the pattern used by drive-by downloads and malware droppers — before you notice them yourself. Suspicious files are automatically checked against VirusTotal, and confirmed threats are isolated so they can't be accidentally run.

**Platform:** Windows only (uses the Windows NTFS Mark-of-the-Web / Zone.Identifier feature)

## What it does

HIDHunter watches five common "landing zones" for internet-sourced files (recursively, including subfolders):

- `Downloads`
- `AppData\Roaming`
- `AppData\Local\Temp`
- `Desktop`
- `Documents`

For every new or changed file, it checks two things:

1. Does the file carry Windows' hidden "Mark of the Web" tag (proof it came from the internet)?
2. Does it have a risky, code-executing extension (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.scr`, `.js`, `.jar`, `.msi`, `.lnk`, `.hta`, `.cmd`, `.com`, `.iso`, `.img`, `.reg`, `.pif`, `.cpl`, `.wsf`, `.jse`, `.vbe`)?

If both are true, HIDHunter:

- Hashes the file (SHA256) and checks it against **VirusTotal's 70+ antivirus engines**
- Raises a desktop notification with a clear verdict — ✅ Safe, ⚠ Low Risk, or 🚨 Malicious — along with the engine count and a link to the full VT report
- Plays a sound alert (repeats for real threats) so it isn't missed even during fullscreen video, when Windows normally suppresses notifications
- Logs the event with its hash to `hidhunter_alerts.txt`, and turns the tray icon red

**Archives are scanned too** — `.zip` and `.rar` files are opened, and every risky-extension file inside is individually extracted and VirusTotal-checked, not just flagged by filename.

**Confirmed threats are auto-quarantined** — files where VirusTotal flags 4 or more engines are automatically moved into an isolated `Quarantine` folder so they can't be run by accident. Lower-confidence flags (1–3 engines, often false positives from lesser-known engines) are only reported, never quarantined — this keeps the tool from disrupting legitimate software over noise.

## Why this matters

Malicious websites can silently write files to disk without any visible download bar or user action — a common tactic on ad-heavy streaming/piracy sites where a stray popup click can trigger a hidden download. HIDHunter surfaces these events immediately and tells you whether the file is actually dangerous, instead of leaving you to guess.

## Installation

### Option A: Easy install (no Python required) — recommended for most people

1. Go to the [Releases page](https://github.com/<your-username>/HIDHunter/releases) and download `HIDHunter.exe`
2. Double-click it to run — no install, no setup steps
3. The first time it runs, a small window will pop up asking for a free VirusTotal API key. Click "Get a free API key", sign up (takes a minute), copy your key, and paste it into the window.
4. That's it — a tray icon appears and HIDHunter is monitoring in the background.

> Some antivirus/SmartScreen warnings may appear for unsigned `.exe` files downloaded from GitHub — this is expected for small open-source tools without a paid code-signing certificate. You can review the source code yourself, or build it from source (Option B) if you'd rather not run a downloaded binary.

### Option B: Run from source (for developers)

```bash
git clone https://github.com/<your-username>/HIDHunter.git
cd HIDHunter
pip install -r requirements.txt
```

Set up your VirusTotal API key (free):

1. Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us) (free tier is fine)
2. Go to your profile → API Key, and copy it
3. Copy `.env.example` to a new file named `.env`
4. Open `.env` and paste your key:
   ```
   VT_API_KEY=your_actual_key_here
   ```
   (Alternatively, just run the script and paste your key into the first-run popup — same as Option A.)

## Usage

```bash
python hidhunter.py
```

A green tray icon will appear near your system clock — HIDHunter is now monitoring in the background. On startup it also runs a quick check to confirm your VirusTotal API key is working, and will notify you if something's wrong with it.

To run with no visible console window:

```bash
pythonw hidhunter.py
```

### Building your own .exe

If you want to build the standalone `.exe` yourself instead of downloading a release:

```bash
build.bat
```

This installs PyInstaller and packages everything into `dist\HIDHunter.exe`.

## What you'll see

- **Idle:** green tray icon, no popups
- **Safe file detected:** brief notification confirming it, no action taken
- **Suspicious/malicious detection:** tray icon turns red, a notification appears with the VirusTotal verdict, a sound alert plays, and the event is logged to `hidhunter_alerts.txt`
- **Confirmed malicious:** file is automatically moved to the `Quarantine` folder
- **Full activity log:** flagged/relevant file events are recorded in `hidhunter_log.txt` (harmless background noise like `.tmp` files is filtered out to keep this readable, and the log auto-rotates once it reaches 5MB)

Right-click the tray icon for options: **Open Alerts Log**, **Open Quarantine Folder**, **Enable/Disable Auto Startup**, **Exit**.

## Configuration

On first run, HIDHunter creates `hidhunter_config.json` in its folder. Edit it any time (no code editing required, just restart the app after saving) to change:

```json
{
  "watch_folders": [...],
  "suspicious_extensions": [".exe", ".dll", ...],
  "low_risk_max_engines": 3,
  "whitelist_filenames": ["some_trusted_app.exe"],
  "whitelist_hashes": []
}
```

Use `whitelist_filenames` or `whitelist_hashes` to permanently trust specific files (e.g. software you use regularly that occasionally gets a false-positive low-risk flag) — whitelisted files are skipped entirely, no scan, no notification.

## Limitations

- Windows-only (Mark-of-the-Web is an NTFS/Windows feature)
- Detection depends on Windows tagging files with Mark-of-the-Web; files dropped by an already-running process without this tag may not be flagged as internet-sourced
- Relies on VirusTotal's **free tier** (4 requests/minute) — the tool automatically paces requests to respect this, so scanning archives with many files can take a little while
- Detection is signature/reputation-based via VirusTotal, not a full antivirus engine — it complements Windows Defender/your AV, it doesn't replace it
- No kernel-level interception — files are checked after they land on disk, not before, though quarantine happens quickly (verdict typically arrives within seconds for a single file)

## Future Improvements

- Packaged as a standalone `.exe` (PyInstaller) so it can run without a Python install
- Zero-day handling — upload-scan unknown files not yet in VirusTotal's database, instead of reporting "unknown"
- Running as a proper Windows Service instead of Task Scheduler, for better persistence and tamper-resistance
- GUI settings panel instead of editing `hidhunter_config.json` directly
- Log rotation to prevent unbounded log file growth over long runtimes
- Cross-platform support for non-Windows systems

## License

MIT — see [LICENSE](LICENSE)
