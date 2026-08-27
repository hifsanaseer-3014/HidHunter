import os
import time
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import threading
import zipfile
import rarfile
import requests
import winreg
import winsound
import tempfile
import shutil
import json
import subprocess
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification
import pystray
from PIL import Image, ImageDraw
from dotenv import load_dotenv

SELF_DIR = str(Path(__file__).resolve().parent)
ENV_PATH = Path(SELF_DIR) / ".env"


def first_run_setup_if_needed():
    """If no .env / API key exists yet, show a simple popup asking for it —
    instead of requiring the user to manually create/edit a .env file."""
    load_dotenv(ENV_PATH)
    existing_key = os.getenv("VT_API_KEY")
    if existing_key:
        return existing_key

    result = {"key": None}

    def submit():
        key = entry.get().strip()
        if not key:
            messagebox.showwarning("HIDHunter Setup", "Please paste a valid API key.")
            return
        result["key"] = key
        root.destroy()

    def open_signup():
        import webbrowser
        webbrowser.open("https://www.virustotal.com/gui/join-us")

    root = tk.Tk()
    root.title("HIDHunter — First-time Setup")
    root.geometry("420x220")
    root.resizable(False, False)

    tk.Label(root, text="Welcome to HIDHunter!", font=("Segoe UI", 12, "bold")).pack(pady=(15, 5))
    tk.Label(
        root,
        text="To scan files, HIDHunter needs a free VirusTotal API key.",
        wraplength=380, justify="center"
    ).pack(pady=(0, 10))

    tk.Button(root, text="Get a free API key", command=open_signup, fg="blue").pack()

    tk.Label(root, text="Paste your API key below:").pack(pady=(15, 2))
    entry = tk.Entry(root, width=45, show="*")
    entry.pack()

    tk.Button(root, text="Save & Continue", command=submit, bg="#2e7d32", fg="white",
              padx=10, pady=5).pack(pady=15)

    root.mainloop()

    if result["key"]:
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.write(f"VT_API_KEY={result['key']}\n")
        return result["key"]
    return None


# First-run setup: ask for API key via popup if not already configured
VT_API_KEY = first_run_setup_if_needed()
CONFIG_PATH = Path(SELF_DIR) / "hidhunter_config.json"

DEFAULT_CONFIG = {
    "watch_folders": [
        str(Path.home() / "Downloads"),
        str(Path.home() / "AppData" / "Roaming"),
        str(Path.home() / "AppData" / "Local" / "Temp"),
        str(Path.home() / "Desktop"),
        str(Path.home() / "Documents"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
    ],
    "suspicious_extensions": [
        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".js", ".jar",
        ".msi", ".lnk", ".hta", ".cmd", ".com", ".iso", ".img",
        ".reg", ".pif", ".cpl", ".wsf", ".jse", ".vbe"
    ],
    "low_risk_max_engines": 3,
    "whitelist_filenames": [],
    "whitelist_hashes": []
}


def load_config():
    if not CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
        except Exception as e:
            logging.error(f"Could not create config file: {e}")
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        for key, value in DEFAULT_CONFIG.items():
            cfg.setdefault(key, value)
        return cfg
    except Exception as e:
        logging.error(f"Config file invalid, using defaults: {e}")
        return dict(DEFAULT_CONFIG)


CONFIG = load_config()
WATCH_FOLDERS = CONFIG["watch_folders"]
SUSPICIOUS_EXT = set(CONFIG["suspicious_extensions"])
LOW_RISK_MAX_ENGINES = CONFIG["low_risk_max_engines"]
WHITELIST_FILENAMES = set(name.lower() for name in CONFIG.get("whitelist_filenames", []))
WHITELIST_HASHES = set(CONFIG.get("whitelist_hashes", []))

LOG_FILE = "hidhunter_log.txt"
ALERTS_FILE = "hidhunter_alerts.txt"
QUARANTINE_DIR = Path(SELF_DIR) / "Quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)
SCAN_CACHE_PATH = Path(SELF_DIR) / "hidhunter_scan_cache.json"

_log_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
logging.getLogger().addHandler(_log_handler)
logging.getLogger().setLevel(logging.INFO)

tray_icon = None
alert_count = 0
alert_lock = threading.Lock()
_recent_events = {}
DEBOUNCE_SECONDS = 6

HASH_DEDUPE_SECONDS = 86400  # don't re-alert on the same file content within 24 hours
_hash_lock = threading.Lock()

# Rate limiter for VirusTotal free tier (4 requests/minute).
# All VT calls go through this lock, which also naturally queues
# simultaneous downloads instead of firing requests all at once.
_vt_lock = threading.Lock()
_last_vt_call_time = [0.0]
MIN_VT_INTERVAL = 16  # seconds between VT calls — keeps us under the 4 req/min free tier limit


def load_scan_cache():
    """Load previously-scanned file hashes from disk so dedup survives
    the tool being restarted (e.g. next day) instead of resetting to empty."""
    if not SCAN_CACHE_PATH.exists():
        return {}
    try:
        with open(SCAN_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        now = time.time()
        return {h: ts for h, ts in data.items() if (now - ts) < HASH_DEDUPE_SECONDS}
    except Exception as e:
        logging.error(f"Could not load scan cache: {e}")
        return {}


def save_scan_cache():
    try:
        with open(SCAN_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_scanned_hashes, f)
    except Exception as e:
        logging.error(f"Could not save scan cache: {e}")


_scanned_hashes = load_scan_cache()


def already_scanned_recently(h):
    """Return True if this exact file content was already scanned/alerted recently."""
    if h == "N/A":
        return False
    with _hash_lock:
        last = _scanned_hashes.get(h)
        now = time.time()
        if last and (now - last) < HASH_DEDUPE_SECONDS:
            return True
        _scanned_hashes[h] = now
        save_scan_cache()
        return False


def check_virustotal(full_hash):
    if not VT_API_KEY:
        logging.error("No VT API key found!")
        return None, None, None, None
    with _vt_lock:
        elapsed = time.time() - _last_vt_call_time[0]
        if elapsed < MIN_VT_INTERVAL:
            time.sleep(MIN_VT_INTERVAL - elapsed)
        try:
            url = f"https://www.virustotal.com/api/v3/files/{full_hash}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            _last_vt_call_time[0] = time.time()
            logging.info(f"VT Response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                detected = stats.get("malicious", 0)
                total = sum(stats.values())
                link = f"https://www.virustotal.com/gui/file/{full_hash}"
                return detected, total, link, response.status_code
            elif response.status_code == 404:
                logging.info("VT: File not in database")
                return 0, 0, None, response.status_code
            elif response.status_code == 429:
                logging.error("VT Error: Rate limit hit, waiting longer next time")
            else:
                logging.error(f"VT Error: {response.text[:200]}")
            return None, None, None, response.status_code
        except Exception as e:
            logging.error(f"VirusTotal check failed: {e}")
    return None, None, None, None


def upload_to_virustotal(path):
    """For files not yet in VT's hash database (zero-day / brand-new files),
    upload the actual file content for a fresh scan instead of reporting UNKNOWN.
    This is slower (upload + wait for analysis) so it's only used as a fallback."""
    if not VT_API_KEY:
        return None, None, None
    with _vt_lock:
        elapsed = time.time() - _last_vt_call_time[0]
        if elapsed < MIN_VT_INTERVAL:
            time.sleep(MIN_VT_INTERVAL - elapsed)
        try:
            with open(path, "rb") as f:
                files = {"file": (Path(path).name, f)}
                headers = {"x-apikey": VT_API_KEY}
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers, files=files, timeout=60
                )
            _last_vt_call_time[0] = time.time()
            if response.status_code not in (200, 201):
                logging.error(f"VT upload failed: {response.status_code} {response.text[:200]}")
                return None, None, None
            analysis_id = response.json()["data"]["id"]
        except Exception as e:
            logging.error(f"VT upload error: {e}")
            return None, None, None

    poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    for _ in range(5):
        with _vt_lock:
            elapsed = time.time() - _last_vt_call_time[0]
            if elapsed < MIN_VT_INTERVAL:
                time.sleep(MIN_VT_INTERVAL - elapsed)
            try:
                r = requests.get(poll_url, headers=headers, timeout=15)
                _last_vt_call_time[0] = time.time()
            except Exception as e:
                logging.error(f"VT poll error: {e}")
                return None, None, None
        if r.status_code == 200:
            data = r.json()
            if data["data"]["attributes"]["status"] == "completed":
                stats = data["data"]["attributes"]["stats"]
                detected = stats.get("malicious", 0)
                total = sum(stats.values())
                link = f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
                logging.info(f"VT upload-scan completed: {detected}/{total}")
                return detected, total, link
        time.sleep(5)
    logging.info("VT upload-scan timed out waiting for analysis")
    return None, None, None


def get_vt_verdict_for_file(path, h):
    """Full verdict pipeline: hash lookup first (fast), and if the file is
    unknown to VT, automatically fall back to uploading it for a fresh scan
    so brand-new/zero-day files don't just get reported as UNKNOWN."""
    detected, total, vt_link, status = check_virustotal(h)
    if status == 404:
        up_detected, up_total, up_link = upload_to_virustotal(path)
        if up_detected is not None:
            return build_verdict(up_detected, up_total, up_link)
    return build_verdict(detected, total, vt_link)


def build_verdict(detected, total, vt_link):
    if detected is not None and total:
        if detected == 0:
            verdict = "✅ SAFE"
        elif detected <= LOW_RISK_MAX_ENGINES:
            verdict = "⚠ LOW RISK"
        else:
            verdict = "🚨 MALICIOUS"
        info = f"\n{verdict} — VirusTotal: {detected}/{total} engines flagged"
        if vt_link:
            info += f"\n{vt_link}"
        return verdict, info
    elif detected == 0 and total == 0:
        return "❓ UNKNOWN", "\n❓ UNKNOWN — File not in VirusTotal database yet"
    else:
        return "❌ CHECK FAILED", "\n❌ CHECK FAILED — Could not reach VirusTotal"


def scan_zip(path):
    """Extract suspicious files from a ZIP into a temp dir and return their real paths."""
    suspicious_paths = []
    try:
        tmp_dir = tempfile.mkdtemp(prefix="hidhunter_zip_")
        with zipfile.ZipFile(path, 'r') as z:
            for name in z.namelist():
                ext = Path(name).suffix.lower()
                if ext in SUSPICIOUS_EXT:
                    try:
                        extracted = z.extract(name, tmp_dir)
                        suspicious_paths.append((name, extracted))
                    except Exception as e:
                        logging.error(f"ZIP extract error {name}: {e}")
    except Exception as e:
        logging.error(f"ZIP scan error {path}: {e}")
    return suspicious_paths


def scan_rar(path):
    """Extract suspicious files from a RAR into a temp dir and return their real paths."""
    suspicious_paths = []
    try:
        tmp_dir = tempfile.mkdtemp(prefix="hidhunter_rar_")
        with rarfile.RarFile(path, 'r') as r:
            for name in r.namelist():
                ext = Path(name).suffix.lower()
                if ext in SUSPICIOUS_EXT:
                    try:
                        extracted = r.extract(name, tmp_dir)
                        suspicious_paths.append((name, os.path.join(tmp_dir, name)))
                    except Exception as e:
                        logging.error(f"RAR extract error {name}: {e}")
    except Exception as e:
        logging.error(f"RAR scan error {path}: {e}")
    return suspicious_paths


def add_to_startup():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        script_path = str(Path(__file__).resolve())
        winreg.SetValueEx(key, "HidHunter", 0, winreg.REG_SZ,
                          f'pythonw "{script_path}"')
        winreg.CloseKey(key)
        logging.info("HidHunter added to startup (registry)!")
    except Exception as e:
        logging.error(f"Startup registration failed: {e}")

    # Backup mechanism #1: scheduled task at logon (survives if the registry
    # key alone is deleted/tampered with)
    try:
        script_path = str(Path(__file__).resolve())
        subprocess.run(
            ["schtasks", "/create", "/tn", "HIDHunterStartup", "/tr",
             f'pythonw "{script_path}"', "/sc", "onlogon", "/rl", "highest", "/f"],
            capture_output=True, timeout=15
        )
        logging.info("HidHunter added to startup (scheduled task)!")
    except Exception as e:
        logging.error(f"Scheduled task startup registration failed: {e}")

    # Backup mechanism #2: a watchdog task that checks every few minutes and
    # restarts HIDHunter if it's not running (e.g. if the process was killed).
    # This is not a security guarantee against a determined attacker with
    # equal privileges, but it recovers from accidental/incidental termination.
    try:
        script_path = str(Path(__file__).resolve())
        watchdog_cmd = (
            f'pythonw -c "import subprocess,sys; '
            f'r=subprocess.run([\'tasklist\'],capture_output=True,text=True); '
            f'sys.exit(0) if \'pythonw.exe\' in r.stdout or \'python.exe\' in r.stdout '
            f'else subprocess.Popen([\'pythonw\',r\'{script_path}\'])"'
        )
        subprocess.run(
            ["schtasks", "/create", "/tn", "HIDHunterWatchdog", "/tr", watchdog_cmd,
             "/sc", "minute", "/mo", "5", "/rl", "highest", "/f"],
            capture_output=True, timeout=15
        )
        logging.info("HidHunter watchdog task created!")
    except Exception as e:
        logging.error(f"Watchdog task registration failed: {e}")


def remove_from_startup():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, "HidHunter")
        winreg.CloseKey(key)
        logging.info("HidHunter removed from startup (registry)!")
    except Exception as e:
        logging.error(f"Startup removal failed: {e}")

    for task_name in ("HIDHunterStartup", "HIDHunterWatchdog"):
        try:
            subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"],
                            capture_output=True, timeout=15)
        except Exception as e:
            logging.error(f"Could not remove scheduled task {task_name}: {e}")


def file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "N/A"


def has_mark_of_the_web(path):
    zone_file = str(path) + ":Zone.Identifier"
    try:
        with open(zone_file, "r") as f:
            content = f.read()
            return "ZoneId=3" in content or "ZoneTransfer" in content
    except (FileNotFoundError, OSError):
        return False


def play_alert_sound(is_dangerous=False):
    try:
        if is_dangerous:
            # Louder / repeated for real threats, cuts through fullscreen video
            for _ in range(3):
                winsound.MessageBeep(winsound.MB_ICONHAND)
                time.sleep(0.3)
        else:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception as e:
        logging.error(f"Sound alert failed: {e}")


def quarantine_file(path, display_name=None):
    """Move a confirmed-malicious file into the isolated Quarantine folder.
    Only ever called for MALICIOUS verdicts (4+ VT engines), never for LOW RISK/UNKNOWN,
    to avoid false-alarm disruption of legitimate files."""
    try:
        name = display_name or path.name
        dest = QUARANTINE_DIR / name
        counter = 1
        stem = Path(name).stem
        suffix = Path(name).suffix
        while dest.exists():
            dest = QUARANTINE_DIR / f"{stem}_{counter}{suffix}"
            counter += 1
        shutil.move(str(path), str(dest))
        logging.warning(f"QUARANTINED: {path} -> {dest}")
        return str(dest)
    except Exception as e:
        logging.error(f"Quarantine failed for {path}: {e}")
        return None


def lock_file(path):
    """Immediately rename a suspicious file so it can't be double-clicked and
    run while we wait for the VT verdict — closes the execution-risk window
    during the (rate-limited) scan delay. Returns the locked Path, or the
    original path if locking failed (e.g. file in use)."""
    try:
        locked = path.with_name(path.name + ".hhlock")
        path.rename(locked)
        return locked
    except Exception as e:
        logging.error(f"Could not lock {path} for scanning: {e}")
        return path


def unlock_file(locked_path, original_name):
    """Restore a locked file's original name once it's been cleared as safe."""
    try:
        restored = locked_path.with_name(original_name)
        locked_path.rename(restored)
        return restored
    except Exception as e:
        logging.error(f"Could not restore {locked_path}: {e}")
        return locked_path


def is_whitelisted(path, h):
    """Check if a file is explicitly trusted via the config's whitelist."""
    if h in WHITELIST_HASHES:
        return True
    if path.name.lower() in WHITELIST_FILENAMES:
        return True
    return False


def make_icon(color):
    img = Image.new("RGB", (64, 64), color)
    draw = ImageDraw.Draw(img)
    draw.ellipse((16, 16, 48, 48), fill="white")
    return img


def set_tray_alert_state():
    if tray_icon:
        tray_icon.icon = make_icon("red")
        tray_icon.title = f"HIDHunter - {alert_count} alert(s)!"


def log_alert(path, h, extra=""):
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.ctime()} | {path.name} | {path.parent} | SHA256:{h} {extra}\n")


class DropHandler(FileSystemEventHandler):
    def _check(self, event):
        global alert_count
        if event.is_directory:
            return

        path = Path(event.src_path)
        if not path.exists():
            return

        # Ignore the tool's own folder (its own log/alert/quarantine files, script, etc.)
        if str(path.resolve()).startswith(SELF_DIR):
            return

        # Ignore files created by our own archive-extraction temp dirs
        if "hidhunter_zip_" in str(path) or "hidhunter_rar_" in str(path):
            return

        now = time.time()
        last_seen = _recent_events.get(str(path))
        if last_seen and (now - last_seen) < DEBOUNCE_SECONDS:
            return
        _recent_events[str(path)] = now

        ext = path.suffix.lower()

        if ext in (".zip", ".rar"):
            extracted_items = scan_zip(path) if ext == ".zip" else scan_rar(path)
            if not extracted_items:
                return

            results = []
            any_malicious = False

            for idx, (inner_name, extracted_path) in enumerate(extracted_items, start=1):
                h = file_hash(Path(extracted_path))
                if is_whitelisted(Path(inner_name), h):
                    logging.info(f"WHITELISTED (skipped): {path.name} -> {inner_name}")
                    continue
                if already_scanned_recently(h):
                    continue
                verdict, info = get_vt_verdict_for_file(extracted_path, h)
                if "MALICIOUS" in verdict or "LOW RISK" in verdict:
                    any_malicious = True
                results.append(f"{idx}. {inner_name}: {verdict}")
                logging.warning(f"ARCHIVE ITEM {idx}: {path.name} -> {inner_name} SHA256:{h}{info}")

            if not results:
                return

            summary = "\n".join(results)
            overall = "🚨 MALICIOUS CONTENT FOUND" if any_malicious else "✅ Archive contents checked — no threats"
            msg = f"{overall}\n{summary}"

            logging.warning(f"ARCHIVE ALERT: {path.name} — {msg}")
            with alert_lock:
                alert_count += 1
            log_alert(path, "N/A", extra=f"| {msg}")

            archive_quarantined = None
            if any_malicious:
                archive_quarantined = quarantine_file(path)

            location_line = "⛔ Archive isolated to Quarantine folder" if archive_quarantined else f"{path.parent}"
            notification.notify(
                title=f"HIDHunter: {overall}",
                message=f"{path.name}\n{location_line}\n{summary}"[:250],
                timeout=10
            )
            play_alert_sound(is_dangerous=any_malicious)
            set_tray_alert_state()

            # Clean up extracted temp files now that scanning is done
            for _, extracted_path in extracted_items:
                try:
                    parent_dir = Path(extracted_path)
                    while parent_dir.parent.name and not parent_dir.name.startswith("hidhunter_"):
                        parent_dir = parent_dir.parent
                    if parent_dir.exists() and parent_dir.name.startswith("hidhunter_"):
                        shutil.rmtree(parent_dir, ignore_errors=True)
                except Exception:
                    pass
            return

        from_internet = has_mark_of_the_web(path)

        # Only log events for extensions we actually care about — avoid flooding
        # the log with harmless .tmp/.crdownload/browser-internal file noise.
        if ext in SUSPICIOUS_EXT:
            logging.info(f"File event: {path} | From internet: {from_internet}")

        # NOTE: we intentionally do NOT require from_internet to be True here.
        # Mark-of-the-Web isn't always set (e.g. PowerShell downloads, some
        # installers, files dropped by other processes) — requiring it let
        # real downloads slip through unscanned. Any new suspicious-extension
        # file in a watched folder gets scanned; from_internet is only kept
        # as informational context in the logs.
        if ext in SUSPICIOUS_EXT:
            h = file_hash(path)

            if is_whitelisted(path, h):
                logging.info(f"WHITELISTED (skipped): {path.name}")
                return

            if already_scanned_recently(h):
                return

            logging.info(f"Full SHA256: {h}")

            # Lock the file immediately so it can't be double-clicked and run
            # while we wait on the (rate-limited) VT verdict.
            original_name = path.name
            locked_path = lock_file(path)

            verdict, vt_info = get_vt_verdict_for_file(locked_path, h)

            with alert_lock:
                alert_count += 1

            log_alert(locked_path, h, extra=vt_info.replace("\n", " | "))
            logging.warning(f"FLAGGED: {original_name} SHA256:{h}{vt_info}")

            quarantined_path = None
            if "🚨 MALICIOUS" in verdict:
                quarantined_path = quarantine_file(locked_path, display_name=original_name)
            else:
                unlock_file(locked_path, original_name)

            location_line = f"Location: {path.parent}"
            if quarantined_path:
                location_line = f"⛔ Isolated to Quarantine folder"

            notification.notify(
                title=f"HIDHunter: {verdict}",
                message=f"{original_name}\n{location_line}{vt_info}",
                timeout=10
            )
            play_alert_sound(is_dangerous=("MALICIOUS" in verdict or "LOW RISK" in verdict))
            set_tray_alert_state()

    def on_created(self, event):
        self._check(event)

    def on_modified(self, event):
        self._check(event)

    def on_moved(self, event):
        class FakeEvent:
            is_directory = event.is_directory
            src_path = event.dest_path
        self._check(FakeEvent())


def open_alerts_log(icon, item):
    os.startfile(ALERTS_FILE) if Path(ALERTS_FILE).exists() else None


def open_quarantine_folder(icon, item):
    os.startfile(str(QUARANTINE_DIR))


def enable_startup(icon, item):
    add_to_startup()
    notification.notify(
        title="HIDHunter",
        message="HIDHunter will now start automatically with Windows!",
        timeout=5
    )


def disable_startup(icon, item):
    remove_from_startup()
    notification.notify(
        title="HIDHunter",
        message="HIDHunter removed from startup.",
        timeout=5
    )


def exit_app(icon, item):
    icon.stop()
    os._exit(0)


def validate_setup():
    """Run once at startup to confirm the VT API key is present and working,
    so setup problems surface immediately instead of failing silently later."""
    if not VT_API_KEY:
        logging.error("STARTUP: No VT_API_KEY found in .env file!")
        notification.notify(
            title="HIDHunter: ⚠ Setup Issue",
            message="No VirusTotal API key found in .env file. Add VT_API_KEY=your_key to .env, then restart.",
            timeout=15
        )
        return

    # Well-known EICAR test-file hash — a standard, harmless value used to
    # smoke-test that the API key and connection actually work.
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0a"
    detected, total, _, status = check_virustotal(test_hash)

    if status == 401:
        notification.notify(
            title="HIDHunter: ⚠ Setup Issue",
            message="Your VirusTotal API key was rejected (unauthorized). Check the key in .env.",
            timeout=15
        )
        logging.error("STARTUP: VT API key validation failed — 401 Unauthorized.")
    elif status in (200, 404, 400):
        # Any of these mean the request reached VT and the key was accepted —
        # 400/404 just mean the test hash itself wasn't a perfect match, which is fine.
        logging.info(f"STARTUP: VirusTotal API key validated successfully (status {status}).")
    elif status is None:
        notification.notify(
            title="HIDHunter: ⚠ Setup Issue",
            message="Could not reach VirusTotal. Check your internet connection.",
            timeout=15
        )
        logging.error("STARTUP: VT validation — no response (network issue?).")
    else:
        logging.info(f"STARTUP: VT responded with status {status} — key appears valid.")


def run_monitor():
    observer = Observer()
    handler = DropHandler()
    for folder in WATCH_FOLDERS:
        if Path(folder).exists():
            try:
                observer.schedule(handler, folder, recursive=True)
            except (PermissionError, OSError) as e:
                logging.error(f"Could not watch {folder}: {e}")

    try:
        observer.start()
    except Exception as e:
        logging.error(f"Observer failed to start: {e}")
        return

    while True:
        time.sleep(1)


def main():
    global tray_icon
    threading.Thread(target=validate_setup, daemon=True).start()
    threading.Thread(target=run_monitor, daemon=True).start()

    menu = pystray.Menu(
        pystray.MenuItem("Open Alerts Log", open_alerts_log),
        pystray.MenuItem("Open Quarantine Folder", open_quarantine_folder),
        pystray.MenuItem("Enable Auto Startup", enable_startup),
        pystray.MenuItem("Disable Auto Startup", disable_startup),
        pystray.MenuItem("Exit", exit_app)
    )
    tray_icon = pystray.Icon("HIDHunter", make_icon("green"), "HIDHunter - Monitoring", menu)
    tray_icon.run()


if __name__ == "__main__":
    main()
