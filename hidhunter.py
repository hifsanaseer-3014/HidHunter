import os
import time
import hashlib
import logging
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification
import pystray
from PIL import Image, ImageDraw

WATCH_FOLDERS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "AppData" / "Roaming"),
    str(Path.home() / "AppData" / "Local" / "Temp"),
]

SUSPICIOUS_EXT = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".js", ".jar"}

LOG_FILE = "hidhunter_log.txt"
ALERTS_FILE = "hidhunter_alerts.txt"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

tray_icon = None
alert_count = 0
_recent_events = {}  # path -> last processed timestamp, for debouncing
DEBOUNCE_SECONDS = 3


def file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except Exception:
        return "N/A"


def has_mark_of_the_web(path):
    """Windows tags any internet-downloaded file with a hidden
    Zone.Identifier stream. Locally created files don't have it."""
    zone_file = str(path) + ":Zone.Identifier"
    try:
        with open(zone_file, "r") as f:
            content = f.read()
            return "ZoneId=3" in content or "ZoneTransfer" in content
    except (FileNotFoundError, OSError):
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


def log_alert(path, h):
    with open(ALERTS_FILE, "a") as f:
        f.write(f"{time.ctime()} | {path.name} | {path.parent} | SHA256:{h}\n")


class DropHandler(FileSystemEventHandler):
    def _check(self, event):
        global alert_count
        if event.is_directory:
            return

        path = Path(event.src_path)
        if not path.exists():
            return

        # Debounce: skip if we just processed this exact path recently
        now = time.time()
        last_seen = _recent_events.get(str(path))
        if last_seen and (now - last_seen) < DEBOUNCE_SECONDS:
            return
        _recent_events[str(path)] = now

        ext = path.suffix.lower()
        from_internet = has_mark_of_the_web(path)

        if not from_internet and ext in SUSPICIOUS_EXT:
            time.sleep(1.5)
            if path.exists():
                from_internet = has_mark_of_the_web(path)
        logging.info(f"File event: {path} | From internet: {from_internet}")

        if from_internet and ext in SUSPICIOUS_EXT:
            h = file_hash(path)
            alert_count += 1
            log_alert(path, h)
            logging.warning(f"FLAGGED: {path.name} SHA256:{h}")

            notification.notify(
                title="⚠ HIDHunter: Suspicious Download Detected",
                message=f"{path.name}\nLocation: {path.parent}\nCheck {ALERTS_FILE} for details.",
                timeout=10
            )
            set_tray_alert_state()

    def on_created(self, event):
        self._check(event)

    def on_modified(self, event):
        self._check(event)

    def on_moved(self, event):
        event.src_path = event.dest_path
        self._check(event)

    def on_moved(self, event):
        class FakeEvent:
            is_directory = event.is_directory
            src_path = event.dest_path
        self._check(FakeEvent())


def open_alerts_log(icon, item):
    os.startfile(ALERTS_FILE) if Path(ALERTS_FILE).exists() else None


def exit_app(icon, item):
    icon.stop()
    os._exit(0)


def run_monitor():
    observer = Observer()
    handler = DropHandler()
    for folder in WATCH_FOLDERS:
        if Path(folder).exists():
            try:
                observer.schedule(handler, folder, recursive=False)
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
    threading.Thread(target=run_monitor, daemon=True).start()

    menu = pystray.Menu(
        pystray.MenuItem("Open Alerts Log", open_alerts_log),
        pystray.MenuItem("Exit", exit_app)
    )
    tray_icon = pystray.Icon("HIDHunter", make_icon("green"), "HIDHunter - Monitoring", menu)
    tray_icon.run()


if __name__ == "__main__":
    main()