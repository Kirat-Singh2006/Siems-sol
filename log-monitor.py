import os
import time
import re
import subprocess
import sys # For checking admin privileges
import json # For saving/loading blocked/unblocked IPs, and now settings
import argparse # Still useful for initial setup or hidden CLI options
from collections import defaultdict, namedtuple # namedtuple is needed for LogEntry
from datetime import datetime, timedelta
from colorama import init, Fore, Style # Still useful for console output in background thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- NEW IMPORTS FOR EMAIL NOTIFICATIONS ---
import smtplib
from email.mime.text import MIMEText
import ssl
# --- END NEW IMPORTS ---

# PyQt5 Imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QListWidget, QLineEdit, QLabel, QMessageBox,
    QStatusBar, QTabWidget, QFormLayout, QSpinBox, QCheckBox, QFileDialog
)
from PyQt5.QtCore import (
    QThread, pyqtSignal, pyqtSlot, QTimer, QObject, Qt
)
from PyQt5.QtGui import QTextCursor, QColor

# --- Configuration (Moved to SettingsManager, but defaults kept here for clarity) ---
DEFAULT_LOG_FILE_PATH = "test.log"
DEFAULT_BLOCKED_IPS_FILE = "blocked_ips.json"
DEFAULT_UNBLOCKED_IPS_FILE = "unblocked.json"
DEFAULT_SETTINGS_FILE = "settings.json" # New file for settings
DEFAULT_FAILED_ATTEMPT_LIMIT = 3
DEFAULT_TIME_WINDOW_MINUTES = 5
DEFAULT_ENABLE_IP_BLOCKING = True
FIREWALL_RULE_PREFIX = "LogMonitor_Blocked_IP_" # This remains a constant prefix

# --- NEW DEFAULT SETTINGS FOR EMAIL ---
DEFAULT_ENABLE_EMAIL_NOTIFICATIONS = False
DEFAULT_SMTP_SERVER = "smtp.example.com"
DEFAULT_SMTP_PORT = 465 # Changed to 465, common for SMTPS. Use 587 with STARTTLS.
DEFAULT_SENDER_EMAIL = "your_email@example.com"
DEFAULT_SENDER_PASSWORD = "your_email_password" # Consider using environment variables or more secure storage
DEFAULT_RECIPIENT_EMAIL = "recipient_email@example.com"
# --- END NEW DEFAULT SETTINGS ---

# Initialize Colorama (for console output from background worker)
init(autoreset=True)

# --- Banner ---
banner = (
    "\033[38;5;205m"  # Start bright pink
    r"""
       _____                _____        ______  _____   ______         _____    ____   ____ 
 |\    \   _____   ___|\    \   ___|\     \|\    \ |\     \    ___|\    \  |    | |    |
 | |    | /    /| |    |\    \ |     \     \\\    \| \     \  /    /\    \ |    | |    |
 \/     / |    || |    | |    ||     ,_____/|\|    \  \     ||    |  |    ||    |_|    |
 /     /_  \   \/ |    |/____/ |     \--'\_|/ |     \  |    ||    |  |____||    .-.    |
|     // \  \   \ |    |\    \ |     /___/|   |      \ |    ||    |   ____ |    | |    |
|    |/   \ |    ||    | |    ||     \____|\  |    |\ \|    ||    |  |    ||    | |    |
|\ ___/\   \|   /||____| |____||____ '     /| |____||\_____/||\ ___\/    /||____| |____|
| |   | \______/ ||    | |    ||    /_____/ | |    |/ \|   ||| |   /____/ ||    | |    |
 \|___|/\ |    | ||____| |____||____|     | / |____|   |___|/ \|___|    | /|____| |____|
    \(   \|____|/   \(     )/    \( |_____|/    \(       )/     \( |____|/   \(     )/  
     '      )/       '     '      '    )/        '       '       '   )/       '     '
"""
    "\033[0m"  # Reset color
)

def print_app_header():
    """Prints the application banner and header information."""
    print(banner)
    print(Fore.WHITE + "\n****************************************************************")
    print("* Copyright of wrench , 2025                                 *")
    print(f"* Loaded at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                 *")
    print("****************************************************************" + Style.RESET_ALL)

# --- Helper function for Admin Check (reused from original script) ---
def is_admin():
    """
    Checks if the script is running with Administrator privileges (Windows only).
    Returns True if admin, False otherwise. Returns True on non-Windows for simplicity.
    """
    if sys.platform == "win32":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # On non-Windows, check if running as root
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else True

# Define a namedtuple for structured log entry parsing
LogEntry = namedtuple('LogEntry', ['timestamp', 'user', 'ip', 'message'])

# --- Settings Manager Class ---
class SettingsManager(QObject):
    """Manages application settings, loading from and saving to a JSON file."""
    settings_updated = pyqtSignal() # Signal emitted when settings are loaded/saved

    def __init__(self, settings_file=DEFAULT_SETTINGS_FILE):
        super().__init__()
        self.settings_file = settings_file
        self._settings = {}
        self._load_settings()

    def _load_settings(self):
        """Loads settings from the JSON file or uses defaults."""
        default_settings = {
            "log_file_path": DEFAULT_LOG_FILE_PATH,
            "failed_attempt_limit": DEFAULT_FAILED_ATTEMPT_LIMIT,
            "time_window_minutes": DEFAULT_TIME_WINDOW_MINUTES,
            "enable_ip_blocking": DEFAULT_ENABLE_IP_BLOCKING,
            # --- NEW DEFAULT SETTINGS LOAD ---
            "enable_email_notifications": DEFAULT_ENABLE_EMAIL_NOTIFICATIONS,
            "smtp_server": DEFAULT_SMTP_SERVER,
            "smtp_port": DEFAULT_SMTP_PORT,
            "sender_email": DEFAULT_SENDER_EMAIL,
            "sender_password": DEFAULT_SENDER_PASSWORD,
            "recipient_email": DEFAULT_RECIPIENT_EMAIL
            # --- END NEW DEFAULT SETTINGS LOAD ---
        }
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    # Merge loaded settings with defaults to handle new settings
                    self._settings = {**default_settings, **loaded_settings}
                print(f"[INFO] Settings loaded from {self.settings_file}.")
            except json.JSONDecodeError as e:
                print(f"[ERROR] Failed to decode settings file {self.settings_file}: {e}. Using default settings.")
                self._settings = default_settings
            except Exception as e:
                print(f"[ERROR] An error occurred loading settings from {self.settings_file}: {e}. Using default settings.")
                self._settings = default_settings
        else:
            print(f"[INFO] No settings file '{self.settings_file}' found. Using default settings.")
            self._settings = default_settings
        self.settings_updated.emit() # Notify UI that settings are ready

    def save_settings(self):
        """Saves current settings to the JSON file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self._settings, f, indent=4)
            print(f"[INFO] Settings saved to {self.settings_file}.")
            self.settings_updated.emit() # Notify UI that settings were saved
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save settings to {self.settings_file}: {e}")
            return False

    def get_setting(self, key):
        """Retrieves a setting value."""
        return self._settings.get(key)

    def set_setting(self, key, value):
        """Sets a setting value."""
        if key in self._settings:
            self._settings[key] = value
        else:
            print(f"[WARNING] Attempted to set unknown setting: {key}")


# --- Log Monitor Worker (runs in a separate thread) ---
class LogMonitorWorker(QObject):
    """
    Worker class to run the LogMonitor logic in a separate thread.
    Emits signals to update the GUI.
    """
    log_message = pyqtSignal(str, str) # message, color (e.g., 'red', 'green')
    blocked_ip_added = pyqtSignal(str) # ip_address
    blocked_ip_removed = pyqtSignal(str) # ip_address
    status_update = pyqtSignal(str) # status message for status bar

    def __init__(self, settings: SettingsManager):
        super().__init__()
        self.settings = settings
        # Pass 'self' (the worker) as the worker for LogMonitorCore when running in the thread
        self.log_monitor = LogMonitorCore(self.settings, self)
        self._running = False
        self.observer = None

    def run(self):
        """Starts the log monitoring process."""
        self._running = True
        log_file_path = self.settings.get_setting("log_file_path")
        attempt_limit = self.settings.get_setting("failed_attempt_limit")
        time_window_minutes = self.settings.get_setting("time_window_minutes")

        self.status_update.emit(f"Monitoring '{log_file_path}'...")
        
        # Initialize watchdog observer
        self.observer = Observer()
        event_handler = LogFileEventHandler(self.log_monitor, self)
        self.observer.schedule(event_handler, os.path.dirname(os.path.abspath(log_file_path)), recursive=False)
        
        self.observer.start()
        self.status_update.emit("Watchdog observer started.")
        self.log_message.emit(f"Starting to monitor log file: {log_file_path}", "green")
        self.log_message.emit(f"Alerting on {attempt_limit} failed attempts within {time_window_minutes:.0f} minutes.", "green")

        # Keep the thread alive while observer runs
        try:
            while self._running:
                time.sleep(1)
        except Exception as e:
            self.log_message.emit(f"Monitor thread error: {e}", "red")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.status_update.emit("Watchdog observer stopped.")
                self.log_message.emit("Log monitoring stopped.", "green")

    def stop(self):
        """Stops the log monitoring process."""
        self._running = False
        self.status_update.emit("Stopping monitor...")

# --- Original LogMonitor logic (renamed to LogMonitorCore to avoid conflict) ---
class LogMonitorCore:
    """
    Monitors a specified log file for suspicious activities like failed login attempts.
    Manages IP blocking and unblocking via Windows Firewall.
    This class now interacts with a 'worker' to emit signals for GUI updates.
    """
    def __init__(self, settings: SettingsManager, worker=None):
        super().__init__()
        self.settings = settings
        self.log_file_path = self.settings.get_setting("log_file_path")
        self.blocked_ips_file = DEFAULT_BLOCKED_IPS_FILE # These are fixed file names
        self.unblocked_ips_file = DEFAULT_UNBLOCKED_IPS_FILE # These are fixed file names
        self.attempt_limit = self.settings.get_setting("failed_attempt_limit")
        self.time_window = timedelta(minutes=self.settings.get_setting("time_window_minutes"))
        self.enable_ip_blocking = self.settings.get_setting("enable_ip_blocking") # Controlled by settings
        
        self.last_read_position = 0
        self.last_inode = None
        self.last_file_size = 0
        self.failed_logins = defaultdict(list)
        self.blocked_ips = set()
        self.worker = worker # Reference to the worker (LogMonitorWorker or None for direct calls)
        self._load_blocked_ips()

    def _log_message(self, msg, color_name="white"):
        """Helper to send messages either to worker signal or print to console."""
        if self.worker and hasattr(self.worker, 'log_message'):
            self.worker.log_message.emit(msg, color_name)
        else:
            # Fallback to console print if no worker or worker doesn't have log_message
            # Use colorama for console output
            color_map = {
                "white": Style.RESET_ALL,
                "red": Fore.RED,
                "green": Fore.GREEN,
                "yellow": Fore.YELLOW,
                "blue": Fore.BLUE,
                "cyan": Fore.CYAN,
                "magenta": Fore.MAGENTA,
                "reset": Style.RESET_ALL
            }
            color_code = color_map.get(color_name.lower(), Style.RESET_ALL)
            print(f"{color_code}{msg}{Style.RESET_ALL}")

    # --- NEW EMAIL SENDING FUNCTION ---
    def _send_email_notification(self, subject, message):
        if not self.settings.get_setting("enable_email_notifications"):
            return

        smtp_server = self.settings.get_setting("smtp_server")
        smtp_port = self.settings.get_setting("smtp_port")
        sender_email = self.settings.get_setting("sender_email")
        sender_password = self.settings.get_setting("sender_password")
        recipient_email = self.settings.get_setting("recipient_email")

        if not all([smtp_server, smtp_port, sender_email, sender_password, recipient_email]):
            self._log_message("[ERROR] Email settings are incomplete. Cannot send email notification.", "red")
            return

        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email

        try:
            self._log_message(f"[INFO] Attempting to send email to {recipient_email}...", "blue")
            # Create a secure SSL context
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            # For STARTTLS on port 587: with smtplib.SMTP(smtp_server, smtp_port) as server: server.starttls(context=context)
                server.login(sender_email, sender_password)
                server.send_message(msg)
            self._log_message(f"[SUCCESS] Email notification sent to {recipient_email}.", "green")
        except smtplib.SMTPAuthenticationError as e:
            self._log_message(f"[ERROR] SMTP Authentication Error: {e}. Check sender email and password.", "red")
        except smtplib.SMTPConnectError as e:
            self._log_message(f"[ERROR] SMTP Connection Error: {e}. Check server address and port.", "red")
        except Exception as e:
            self._log_message(f"[ERROR] Failed to send email notification: {e}", "red")
    # --- END NEW EMAIL SENDING FUNCTION ---

    def _load_blocked_ips(self):
        """Loads previously blocked IPs from a JSON file."""
        if os.path.exists(self.blocked_ips_file):
            try:
                with open(self.blocked_ips_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked_ips', []))
                msg = f"Loaded {len(self.blocked_ips)} previously blocked IPs from {self.blocked_ips_file}."
                self._log_message(msg, "green")
            except json.JSONDecodeError as e:
                msg = f"Failed to decode {self.blocked_ips_file}: {e}. Starting with empty blocked IPs list."
                self._log_message(msg, "red")
                self.blocked_ips = set()
            except Exception as e:
                msg = f"An error occurred loading {self.blocked_ips_file}: {e}. Starting with empty blocked IPs list."
                self._log_message(msg, "red")
                self.blocked_ips = set()
        else:
            msg = f"No '{self.blocked_ips_file}' found. Starting with empty blocked IPs list."
            self._log_message(msg, "yellow")

    def _save_blocked_ips(self):
        """Saves the current set of blocked IPs to a JSON file."""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                json.dump({'blocked_ips': list(self.blocked_ips)}, f, indent=4)
            msg = f"Saved {len(self.blocked_ips)} blocked IPs to {self.blocked_ips_file}."
            self._log_message(msg, "green")
        except Exception as e:
            msg = f"Failed to save blocked IPs to {self.blocked_ips_file}: {e}"
            self._log_message(msg, "red")

    def _record_unblock_event(self, ip_address):
        """Records an unblock event to the unblocked_ips.json file."""
        unblock_history = []
        if os.path.exists(self.unblocked_ips_file):
            try:
                with open(self.unblocked_ips_file, 'r') as f:
                    unblock_history = json.load(f)
                if not isinstance(unblock_history, list):
                    unblock_history = []
            except json.JSONDecodeError as e:
                msg = f"Failed to decode {self.unblocked_ips_file}: {e}. Starting new unblock history."
                self._log_message(msg, "red")
                unblock_history = []
            except Exception as e:
                msg = f"An error occurred reading {self.unblocked_ips_file}: {e}. Starting new unblock history."
                self._log_message(msg, "red")
                unblock_history = []
        
        unblock_history.append({
            'ip': ip_address,
            'unblocked_at': datetime.now().isoformat()
        })

        try:
            with open(self.unblocked_ips_file, 'w') as f:
                json.dump(unblock_history, f, indent=4)
            msg = f"Recorded unblock event for {ip_address} to {self.unblocked_ips_file}."
            self._log_message(msg, "green")
        except Exception as e:
            msg = f"Failed to record unblock event to {self.unblocked_ips_file}: {e}"
            self._log_message(msg, "red")

    def _get_file_info(self):
        """Helper to get file size and inode for log rotation detection."""
        try:
            stat_info = os.stat(self.log_file_path)
            return stat_info.st_size, stat_info.st_ino
        except FileNotFoundError:
            return 0, None
        except Exception as e:
            msg = f"Could not get file info for {self.log_file_path}: {e}"
            self._log_message(msg, "red")
            return 0, None

    def _handle_log_rotation(self):
        """
        Checks for log file rotation or truncation.
        Resets read position if the file has changed significantly.
        Returns True if rotation/truncation detected, False otherwise.
        """
        current_size, current_inode = self._get_file_info()

        if current_inode is not None and self.last_inode is None:
            self.last_inode = current_inode
            self.last_file_size = current_size
            return False

        if current_inode != self.last_inode or current_size < self.last_file_size:
            msg = f"Log file '{self.log_file_path}' appears to have been rotated or truncated."
            self._log_message(msg, "yellow")
            self.last_read_position = 0
            self.last_inode = current_inode
            self.last_file_size = current_size
            return True
        
        self.last_file_size = current_size
        return False

    def parse_log_line(self, line):
        """
        Parses a single log line for failed login attempts.
        Expected format: "YYYY-MM-DD HH:MM:SS Failed password for (invalid user )?([^\s]+) from ([0-9.]+)"
        """
        line = line.strip().replace('\r', '')
        match = re.search(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
            r"Failed password for (invalid user )?(?P<user>[^\s]+) from (?P<ip>[0-9.]+)",
            line
        )
       
        if match:
            try:
                timestamp_str = match.group('timestamp')
                log_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                user = match.group('user')
                ip = match.group('ip')
            
                self._log_message(f"[DEBUG] Parsed: Time={log_timestamp}, User={user}, IP={ip}", "cyan")
                return LogEntry(log_timestamp, user, ip, line)
            except ValueError as ve:
                msg = f"[ERROR] Failed to parse timestamp in line: {line} - {ve}"
                self._log_message(msg, "red")
                return None
        else:
            return None

    def _block_ip(self, ip_address):
        """
        Adds a Windows Firewall rule to block inbound traffic from the specified IP address.
        Requires Administrator privileges.
        """
        if not is_admin():
            msg = "[ERROR] Cannot block IP: Script is not running with Administrator privileges."
            self._log_message(msg, "red")
            return False

        if ip_address in self.blocked_ips:
            msg = f"[INFO] IP {ip_address} is already blocked. Skipping."
            self._log_message(msg, "yellow")
            return True

        rule_name = f"{FIREWALL_RULE_PREFIX}{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes",
            f"description=Blocked by LogMonitor for brute-force attempts from {ip_address}"
        ]
        
        try:
            msg = f"[ACTION] Attempting to block IP: {ip_address} with rule '{rule_name}'..."
            self._log_message(msg, "yellow")
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
            msg = f"[SUCCESS] IP {ip_address} blocked successfully. Output:\n{result.stdout.strip()}"
            self._log_message(msg, "green")
            self.blocked_ips.add(ip_address)
            self._save_blocked_ips()
            if self.worker and hasattr(self.worker, 'blocked_ip_added'): self.worker.blocked_ip_added.emit(ip_address) # Signal GUI
            return True
        except subprocess.CalledProcessError as e:
            if "already exists" in e.stderr:
                msg = f"[INFO] Firewall rule for {ip_address} already exists. Marking as blocked."
                self._log_message(msg, "yellow")
                self.blocked_ips.add(ip_address)
                self._save_blocked_ips()
                if self.worker and hasattr(self.worker, 'blocked_ip_added'): self.worker.blocked_ip_added.emit(ip_address) # Signal GUI
                return True
            else:
                msg = f"[ERROR] Failed to block IP {ip_address}. Command failed with exit code {e.returncode}.\nStderr: {e.stderr.strip()}\nStdout: {e.stdout.strip()}"
                self._log_message(msg, "red")
                return False
        except FileNotFoundError:
            msg = "[ERROR] 'netsh' command not found. Ensure it's in your system PATH."
            self._log_message(msg, "red")
            return False
        except Exception as e:
            msg = f"[ERROR] An unexpected error occurred while blocking IP {ip_address}: {e}"
            self._log_message(msg, "red")
            return False

    def _unblock_ip(self, ip_address):
        """
        Deletes a Windows Firewall rule to unblock inbound traffic from the specified IP address.
        Requires Administrator privileges.
        """
        if not is_admin():
            msg = "[ERROR] Cannot unblock IP: Script is not running with Administrator privileges."
            self._log_message(msg, "red")
            return False

        if ip_address not in self.blocked_ips:
            msg = f"[INFO] IP {ip_address} is not in our tracked blocked list. Attempting to delete rule anyway."
            self._log_message(msg, "yellow")

        rule_name = f"{FIREWALL_RULE_PREFIX}{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]

        try:
            msg = f"[ACTION] Attempting to unblock IP: {ip_address} by deleting rule '{rule_name}'..."
            self._log_message(msg, "yellow")
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
            msg = f"[SUCCESS] IP {ip_address} unblocked successfully. Output:\n{result.stdout.strip()}"
            self._log_message(msg, "green")
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self._save_blocked_ips()
            self._record_unblock_event(ip_address)
            if self.worker and hasattr(self.worker, 'blocked_ip_removed'): self.worker.blocked_ip_removed.emit(ip_address) # Signal GUI
            return True
        except subprocess.CalledProcessError as e:
            if "No rules match the specified criteria" in e.stderr:
                msg = f"[INFO] No firewall rule found for {ip_address} with name '{rule_name}'. It might already be unblocked or never blocked by this tool."
                self._log_message(msg, "yellow")
                if ip_address in self.blocked_ips:
                    self.blocked_ips.remove(ip_address)
                    self._save_blocked_ips()
                self._record_unblock_event(ip_address)
                if self.worker and hasattr(self.worker, 'blocked_ip_removed'): self.worker.blocked_ip_removed.emit(ip_address) # Signal GUI
                return True
            else:
                msg = f"[ERROR] Failed to unblock IP {ip_address}. Command failed with exit code {e.returncode}.\nStderr: {e.stderr.strip()}\nStdout: {e.stdout.strip()}"
                self._log_message(msg, "red")
                return False
        except FileNotFoundError:
            msg = "[ERROR] 'netsh' command not found. Ensure it's in your system PATH."
            self._log_message(msg, "red")
            return False
        except Exception as e:
            msg = f"[ERROR] An unexpected error occurred while unblocking IP {ip_address}: {e}"
            self._log_message(msg, "red")
            return False

    def get_blocked_ips_list(self):
        """Returns the current list of blocked IPs."""
        return sorted(list(self.blocked_ips))

    def get_unblocked_history(self):
        """Reads and returns the unblock history."""
        unblock_history = []
        if os.path.exists(self.unblocked_ips_file):
            try:
                with open(self.unblocked_ips_file, 'r') as f:
                    unblock_history = json.load(f)
                if not isinstance(unblock_history, list):
                    unblock_history = []
            except json.JSONDecodeError as e:
                msg = f"[ERROR] Failed to decode {self.unblocked_ips_file}: {e}."
                self._log_message(msg, "red")
            except Exception as e:
                msg = f"[ERROR] An error occurred reading {self.unblocked_ips_file}: {e}."
                self._log_message(msg, "red")
        return unblock_history

    def _unblock_all_ips(self):
        """Attempts to unblock all IPs currently tracked by this monitor."""
        if not self.blocked_ips:
            msg = "[INFO] No IPs to unblock."
            self._log_message(msg, "blue")
            return

        ips_to_unblock = list(self.blocked_ips.copy())
        msg = f"[ACTION] Attempting to unblock all {len(ips_to_unblock)} tracked IPs..."
        self._log_message(msg, "yellow")
        for ip in ips_to_unblock:
            self._unblock_ip(ip)

    def process_new_lines(self):
        """
        Reads and processes new lines from the log file.
        This method is called by the watchdog event handler.
        """
        try:
            if not os.path.exists(self.log_file_path):
                msg = f"[WARNING] Log file '{self.log_file_path}' not found. Waiting for it to appear..."
                self._log_message(msg, "yellow")
                self.last_read_position = 0
                self.last_inode = None
                self.last_file_size = 0
                return

            self._handle_log_rotation()

            with open(self.log_file_path, "rb") as f:
                f.seek(self.last_read_position)
                new_data = f.read()
                self.last_read_position = f.tell()

            new_data = new_data.replace(b'\x00', b'')
            new_lines = new_data.decode("utf-8", errors="ignore").splitlines()

            for line in new_lines:
                if line.strip():
                    log_entry = self.parse_log_line(line)
                    self.analyze_failed_logins(log_entry)

        except Exception as e:
            msg = f"[CRITICAL ERROR] An unexpected error occurred while processing lines: {e}"
            self._log_message(msg, "red")

    def analyze_failed_logins(self, log_entry):
        """
        Analyzes a parsed log entry for failed login attempts and triggers alerts.
        If ENABLE_IP_BLOCKING is True and threshold is met, attempts to block the IP.
        """
        if not log_entry:
            return

        ip = log_entry.ip
        timestamp = log_entry.timestamp

        self.failed_logins[ip].append(timestamp)
        self.failed_logins[ip] = [
            t for t in self.failed_logins[ip] if timestamp - t < self.time_window
        ]

        if len(self.failed_logins[ip]) >= self.attempt_limit:
            alert_message = (
                f"{len(self.failed_logins[ip])} failed login attempts from IP {ip} "
                f"in the last {self.time_window.total_seconds() / 60:.0f} minutes! Full log line: {log_entry.message}"
            )
            self._log_message(f"[SUSPICIOUS] {alert_message}", "red")
            
            # --- TRIGGER EMAIL NOTIFICATION HERE ---
            subject = f"Log Monitor Alert: Suspicious Activity from {ip}"
            self._send_email_notification(subject, alert_message) # Corrected: added self.
            # --- END TRIGGER EMAIL NOTIFICATION ---

            if self.enable_ip_blocking: # Use setting from SettingsManager
                self._block_ip(ip)
            
            # self.failed_logins[ip].clear() # Optional: clear after alert to prevent repeated alerts

class LogFileEventHandler(FileSystemEventHandler):
    """
    Custom event handler for watchdog to process log file changes.
    It tells the LogMonitorCore instance to process new lines.
    """
    def __init__(self, log_monitor_core_instance, worker_instance):
        super().__init__()
        self.monitor_core = log_monitor_core_instance
        self.worker = worker_instance
        self.log_file_basename = os.path.basename(log_monitor_core_instance.log_file_path)

    def on_modified(self, event):
        if not event.is_directory and os.path.basename(event.src_path) == self.log_file_basename:
            self.monitor_core.process_new_lines()

    def on_created(self, event):
        if not event.is_directory and os.path.basename(event.src_path) == self.log_file_basename:
            self.monitor_core._log_message(f"[DEBUG] File created event detected for: {event.src_path}", "blue")
            self.monitor_core.last_read_position = 0
            self.monitor_core.last_inode = None
            self.monitor_core.last_file_size = 0
            self.monitor_core.process_new_lines()

    def on_deleted(self, event):
        if not event.is_directory and os.path.basename(event.src_path) == self.log_file_basename:
            self.monitor_core._log_message(f"[DEBUG] File deleted event detected for: {event.src_path}", "blue")
            self.monitor_core.last_read_position = 0
            self.monitor_core.last_inode = None
            self.monitor_core.last_file_size = 0

    def on_moved(self, event):
        if not event.is_directory and os.path.basename(event.src_path) == self.log_file_basename:
            self.monitor_core._log_message(f"[DEBUG] File moved/renamed event detected for: {event.src_path} -> {event.dest_path}", "blue")
            self.monitor_core.last_read_position = 0
            self.monitor_core.last_inode = None
            self.monitor_core.last_file_size = 0


# --- Main GUI Application ---
class LogMonitorGUI(QMainWindow):
    log_message = pyqtSignal(str, str) # Signal for general log messages to GUI

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Log Monitor & IP Blocker")
        self.setGeometry(100, 100, 900, 700) # Increased size for better layout

        self.settings_manager = SettingsManager(DEFAULT_SETTINGS_FILE)
        self.settings_manager.settings_updated.connect(self._update_settings_ui) # Connect to update UI when settings change

        self.monitor_thread = None
        self.monitor_worker = None

        self._check_admin_status()
        self._init_ui()
        self.log_message.connect(self._append_log_message)
        self._update_blocked_ips_list() # Populate on startup
        self._update_unblock_history_list() # Populate on startup
        self._update_settings_ui() # Populate settings UI with current settings

    def _check_admin_status(self):
        """Checks and displays admin status."""
        if not is_admin():
            QMessageBox.warning(self, "Administrator Privileges Required",
                                "This application requires Administrator privileges to block/unblock IPs. "
                                "Please run it as Administrator for full functionality.")
            self.admin_status = False
        else:
            self.admin_status = True

    def _init_ui(self):
        """Initializes the main user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Top Control Panel ---
        control_panel = QHBoxLayout()
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self._start_monitoring)
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self._stop_monitoring)
        self.stop_button.setEnabled(False) # Disabled until monitoring starts

        control_panel.addWidget(self.start_button)
        control_panel.addWidget(self.stop_button)
        control_panel.addStretch(1) # Pushes buttons to left

        main_layout.addLayout(control_panel)

        # --- Tab Widget for Log, Blocked IPs, Unblock History, Settings ---
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Log Tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace;")
        log_layout.addWidget(self.log_output)
        self.tab_widget.addTab(log_tab, "Live Log")

        # Blocked IPs Tab
        blocked_ips_tab = QWidget()
        blocked_ips_layout = QVBoxLayout(blocked_ips_tab)
        
        # IP Unblock Controls
        unblock_controls_layout = QHBoxLayout()
        self.unblock_ip_input = QLineEdit()
        self.unblock_ip_input.setPlaceholderText("Enter IP to unblock (e.g., 192.168.1.99)")
        self.unblock_button = QPushButton("Unblock IP")
        self.unblock_button.clicked.connect(self._unblock_specific_ip)
        
        unblock_controls_layout.addWidget(self.unblock_ip_input)
        unblock_controls_layout.addWidget(self.unblock_button)
        blocked_ips_layout.addLayout(unblock_controls_layout)

        # List of Blocked IPs
        self.blocked_ips_list_widget = QListWidget()
        blocked_ips_layout.addWidget(self.blocked_ips_list_widget)

        # Action Buttons for Blocked IPs
        blocked_actions_layout = QHBoxLayout()
        self.refresh_blocked_button = QPushButton("Refresh List")
        self.refresh_blocked_button.clicked.connect(self._update_blocked_ips_list)
        self.unblock_all_button = QPushButton("Unblock All Tracked IPs")
        self.unblock_all_button.clicked.connect(self._unblock_all_tracked_ips)
        
        blocked_actions_layout.addWidget(self.refresh_blocked_button)
        blocked_actions_layout.addWidget(self.unblock_all_button)
        blocked_ips_layout.addLayout(blocked_actions_layout)

        self.tab_widget.addTab(blocked_ips_tab, "Blocked IPs")

        # Unblock History Tab
        unblock_history_tab = QWidget()
        unblock_history_layout = QVBoxLayout(unblock_history_tab)
        self.unblock_history_list_widget = QListWidget()
        unblock_history_layout.addWidget(self.unblock_history_list_widget)
        self.refresh_history_button = QPushButton("Refresh History")
        self.refresh_history_button.clicked.connect(self._update_unblock_history_list)
        unblock_history_layout.addWidget(self.refresh_history_button)
        self.tab_widget.addTab(unblock_history_tab, "Unblock History")

        # Settings Tab (NEW)
        settings_tab = QWidget()
        # Use a QVBoxLayout for the settings tab to allow addStretch
        settings_tab_main_layout = QVBoxLayout(settings_tab) 
        settings_form_layout = QFormLayout()

        # Log File Path
        log_path_layout = QHBoxLayout()
        self.log_file_path_input = QLineEdit()
        self.log_file_path_input.setReadOnly(True) # Make it read-only, force use of browse button
        self.browse_log_button = QPushButton("Browse...")
        self.browse_log_button.clicked.connect(self._browse_log_file)
        log_path_layout.addWidget(self.log_file_path_input)
        log_path_layout.addWidget(self.browse_log_button)
        settings_form_layout.addRow("Log File Path:", log_path_layout)

        # Failed Attempt Limit
        self.failed_attempt_limit_spinbox = QSpinBox()
        self.failed_attempt_limit_spinbox.setRange(1, 999) # Reasonable range
        settings_form_layout.addRow("Failed Attempt Limit:", self.failed_attempt_limit_spinbox)

        # Time Window Minutes
        self.time_window_minutes_spinbox = QSpinBox()
        self.time_window_minutes_spinbox.setRange(1, 1440) # 1 minute to 24 hours
        settings_form_layout.addRow("Time Window (Minutes):", self.time_window_minutes_spinbox)

        # Enable IP Blocking
        self.enable_ip_blocking_checkbox = QCheckBox("Enable Automatic IP Blocking")
        # Disable if not admin
        if not self.admin_status:
            self.enable_ip_blocking_checkbox.setEnabled(False)
            self.enable_ip_blocking_checkbox.setToolTip("Requires Administrator privileges to enable.")
        settings_form_layout.addRow(self.enable_ip_blocking_checkbox)

        # --- NEW EMAIL SETTINGS UI ---
        self.enable_email_notifications_checkbox = QCheckBox("Enable Email Notifications")
        settings_form_layout.addRow(self.enable_email_notifications_checkbox)

        self.smtp_server_input = QLineEdit()
        settings_form_layout.addRow("SMTP Server:", self.smtp_server_input)

        self.smtp_port_spinbox = QSpinBox()
        self.smtp_port_spinbox.setRange(1, 65535)
        settings_form_layout.addRow("SMTP Port:", self.smtp_port_spinbox)

        self.sender_email_input = QLineEdit()
        settings_form_layout.addRow("Sender Email:", self.sender_email_input)

        self.sender_password_input = QLineEdit()
        self.sender_password_input.setEchoMode(QLineEdit.Password) # Mask password
        settings_form_layout.addRow("Sender Password:", self.sender_password_input)

        self.recipient_email_input = QLineEdit()
        settings_form_layout.addRow("Recipient Email:", self.recipient_email_input)
        # --- END NEW EMAIL SETTINGS UI ---

        # Save Settings Button
        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self._save_settings_from_ui)
        settings_form_layout.addRow(self.save_settings_button)

        settings_tab_main_layout.addLayout(settings_form_layout) # Add the form layout to the main layout of the tab
        settings_tab_main_layout.addStretch(1) # Push content to top using the QVBoxLayout

        self.tab_widget.addTab(settings_tab, "Settings")


        # --- Status Bar ---
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready. Run as Administrator for IP blocking.")

        # Initial admin status display
        if not self.admin_status:
            self.statusBar.setStyleSheet("QStatusBar {background-color: red; color: white;}")
            self.statusBar.showMessage("WARNING: Not running as Administrator. IP blocking/unblocking disabled.")
            self.unblock_button.setEnabled(False)
            self.unblock_all_button.setEnabled(False)
        else:
            self.statusBar.setStyleSheet("") # Reset stylesheet
            self.statusBar.showMessage("Running as Administrator. IP blocking/unblocking enabled.")

    @pyqtSlot()
    def _update_settings_ui(self):
        """Updates the settings UI fields with values from SettingsManager."""
        self.log_file_path_input.setText(self.settings_manager.get_setting("log_file_path"))
        self.failed_attempt_limit_spinbox.setValue(self.settings_manager.get_setting("failed_attempt_limit"))
        self.time_window_minutes_spinbox.setValue(self.settings_manager.get_setting("time_window_minutes"))
        
        # Only set checkbox if admin, otherwise it's disabled
        if self.admin_status:
            self.enable_ip_blocking_checkbox.setChecked(self.settings_manager.get_setting("enable_ip_blocking"))
        else:
            self.enable_ip_blocking_checkbox.setChecked(False) # Ensure it's off if not admin

        # --- UPDATE EMAIL SETTINGS UI ---
        self.enable_email_notifications_checkbox.setChecked(self.settings_manager.get_setting("enable_email_notifications"))
        self.smtp_server_input.setText(self.settings_manager.get_setting("smtp_server"))
        self.smtp_port_spinbox.setValue(self.settings_manager.get_setting("smtp_port"))
        self.sender_email_input.setText(self.settings_manager.get_setting("sender_email"))
        self.sender_password_input.setText(self.settings_manager.get_setting("sender_password")) # This will be masked
        self.recipient_email_input.setText(self.settings_manager.get_setting("recipient_email"))
        # --- END UPDATE EMAIL SETTINGS UI ---

    @pyqtSlot()
    def _save_settings_from_ui(self):
        """Saves settings from the UI fields to SettingsManager and then to file."""
        # Check if monitoring is active
        if self.monitor_thread and self.monitor_thread.isRunning():
            reply = QMessageBox.question(self, 'Monitoring Active', 
                                         "Monitoring is currently active. Changes to settings (except IP blocking enable/disable) "
                                         "will only take effect after stopping and restarting the monitor. "
                                         "Do you want to save settings anyway?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return

        self.settings_manager.set_setting("log_file_path", self.log_file_path_input.text())
        self.settings_manager.set_setting("failed_attempt_limit", self.failed_attempt_limit_spinbox.value())
        self.settings_manager.set_setting("time_window_minutes", self.time_window_minutes_spinbox.value())
        
        # Only save IP blocking state if running as admin
        if self.admin_status:
            self.settings_manager.set_setting("enable_ip_blocking", self.enable_ip_blocking_checkbox.isChecked())
        else:
            # If not admin, ensure the setting is saved as False regardless of checkbox state
            self.settings_manager.set_setting("enable_ip_blocking", False)

        # --- SAVE NEW EMAIL SETTINGS ---
        self.settings_manager.set_setting("enable_email_notifications", self.enable_email_notifications_checkbox.isChecked())
        self.settings_manager.set_setting("smtp_server", self.smtp_server_input.text())
        self.settings_manager.set_setting("smtp_port", self.smtp_port_spinbox.value())
        self.settings_manager.set_setting("sender_email", self.sender_email_input.text())
        self.settings_manager.set_setting("sender_password", self.sender_password_input.text())
        self.settings_manager.set_setting("recipient_email", self.recipient_email_input.text())
        # --- END SAVE NEW EMAIL SETTINGS ---

        if self.settings_manager.save_settings():
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
            if self.monitor_thread and self.monitor_thread.isRunning():
                QMessageBox.information(self, "Restart Monitor", "Please stop and restart monitoring for new settings to take full effect.")
        else:
            QMessageBox.critical(self, "Save Error", "Failed to save settings. Check console for details.")

    @pyqtSlot()
    def _browse_log_file(self):
        """Opens a file dialog to select the log file path."""
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Select Log File")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Log Files (*.log);;Text Files (*.txt);;All Files (*.*)")

        if file_dialog.exec_():
            selected_file = file_dialog.selectedFiles()[0]
            self.log_file_path_input.setText(selected_file)

    @pyqtSlot(str, str)
    def _append_log_message(self, message, color_name="white"):
        """Appends a colored message to the log output."""
        color_map = {
            "white": QColor("white"),
            "red": QColor("red"),
            "green": QColor("lightgreen"),
            "yellow": QColor("yellow"),
            "blue": QColor("lightblue"),
            "cyan": QColor("cyan"),
            "magenta": QColor("magenta"),
            "reset": QColor("white") # Default for reset
        }
        color = color_map.get(color_name.lower(), QColor("white"))

        cursor = self.log_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(f"<span style='color:{color.name()};'>{message}</span><br>")
        self.log_output.setTextCursor(cursor)
        self.log_output.ensureCursorVisible()

    @pyqtSlot(str)
    def _add_blocked_ip_to_list(self, ip_address):
        """Adds a blocked IP to the list widget."""
        if self.blocked_ips_list_widget.findItems(ip_address, Qt.MatchExactly): # Avoid duplicates
            return
        self.blocked_ips_list_widget.addItem(ip_address)
        self.blocked_ips_list_widget.sortItems()
        self.statusBar.showMessage(f"IP {ip_address} blocked.", 3000)

    @pyqtSlot(str)
    def _remove_blocked_ip_from_list(self, ip_address):
        """Removes an unblocked IP from the list widget."""
        items = self.blocked_ips_list_widget.findItems(ip_address, Qt.MatchExactly)
        for item in items:
            self.blocked_ips_list_widget.takeItem(self.blocked_ips_list_widget.row(item))
        self.statusBar.showMessage(f"IP {ip_address} unblocked.", 3000)
        self._update_unblock_history_list() # Refresh history when an IP is unblocked

    @pyqtSlot(str)
    def _update_status_bar(self, message):
        """Updates the status bar message."""
        self.statusBar.showMessage(message)

    def _start_monitoring(self):
        """Starts the log monitoring thread."""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self._append_log_message("Monitor is already running.", "yellow")
            return

        # Ensure settings are up-to-date before starting monitor
        self.settings_manager._load_settings() # Reload from file to get latest saved settings
        
        self.monitor_thread = QThread()
        # Pass the settings manager instance to the worker
        self.monitor_worker = LogMonitorWorker(self.settings_manager)
        self.monitor_worker.moveToThread(self.monitor_thread)

        # Connect signals/slots
        self.monitor_thread.started.connect(self.monitor_worker.run)
        self.monitor_worker.log_message.connect(self._append_log_message)
        self.monitor_worker.blocked_ip_added.connect(self._add_blocked_ip_to_list)
        self.monitor_worker.blocked_ip_removed.connect(self._remove_blocked_ip_from_list)
        self.monitor_worker.status_update.connect(self._update_status_bar)
        self.monitor_thread.finished.connect(self.monitor_worker.deleteLater) # Clean up worker
        self.monitor_thread.finished.connect(self.monitor_thread.deleteLater) # Clean up thread

        self.monitor_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._append_log_message("Log monitoring initiated...", "blue")
        self._update_blocked_ips_list() # Refresh list to show existing blocks

    def _stop_monitoring(self):
        """Stops the log monitoring thread."""
        if self.monitor_worker:
            self.monitor_worker.stop()
            self.monitor_thread.quit()
            self.monitor_thread.wait() # Wait for thread to finish
            self.monitor_thread = None
            self.monitor_worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self._append_log_message("Log monitoring stopped.", "blue")
            self.statusBar.showMessage("Monitor stopped.")

    def _unblock_specific_ip(self):
        """Handles unblocking a specific IP entered by the user."""
        if not self.admin_status:
            QMessageBox.warning(self, "Permission Denied", "Administrator privileges are required to unblock IPs.")
            return

        ip_to_unblock = self.unblock_ip_input.text().strip()
        if not ip_to_unblock:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address to unblock.")
            return

        # Pass the settings manager and self (GUI) as worker for direct calls
        temp_monitor = LogMonitorCore(self.settings_manager, worker=self)
        success = temp_monitor._unblock_ip(ip_to_unblock)
        if success:
            QMessageBox.information(self, "Unblock Success", f"Successfully unblocked {ip_to_unblock}.")
            self.unblock_ip_input.clear()
            self._update_blocked_ips_list() # Refresh list
            self._update_unblock_history_list() # Refresh history
        else:
            QMessageBox.critical(self, "Unblock Failed", f"Failed to unblock {ip_to_unblock}. Check console for details.")

    def _update_blocked_ips_list(self):
        """Refreshes the list of currently blocked IPs."""
        self.blocked_ips_list_widget.clear()
        # Pass the settings manager and self (GUI) as worker for direct calls
        temp_monitor = LogMonitorCore(self.settings_manager, worker=self)
        blocked_ips = temp_monitor.get_blocked_ips_list()
        if not blocked_ips:
            self.blocked_ips_list_widget.addItem("No IPs currently blocked by LogMonitor.")
            return
        for ip in blocked_ips:
            self.blocked_ips_list_widget.addItem(ip)
        self.blocked_ips_list_widget.sortItems()

    def _unblock_all_tracked_ips(self):
        """Handles unblocking all IPs tracked by the monitor."""
        if not self.admin_status:
            QMessageBox.warning(self, "Permission Denied", "Administrator privileges are required to unblock IPs.")
            return

        reply = QMessageBox.question(self, 'Confirm Unblock All', 
                                     "Are you sure you want to unblock ALL IPs currently tracked by this monitor?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            # Pass the settings manager and self (GUI) as worker for direct calls
            temp_monitor = LogMonitorCore(self.settings_manager, worker=self)
            temp_monitor._unblock_all_ips()
            self._update_blocked_ips_list() # Refresh list
            self._update_unblock_history_list() # Refresh history
            QMessageBox.information(self, "Unblock All Complete", "Attempted to unblock all tracked IPs.")

    def _update_unblock_history_list(self):
        """Refreshes the list of unblock history."""
        self.unblock_history_list_widget.clear()
        # Pass the settings manager and self (GUI) as worker for direct calls
        temp_monitor = LogMonitorCore(self.settings_manager, worker=self)
        history = temp_monitor.get_unblocked_history()
        if not history:
            self.unblock_history_list_widget.addItem("No unblock history found.")
            return
        
        # Display in reverse chronological order (most recent first)
        for entry in reversed(history):
            ip = entry.get('ip', 'N/A')
            timestamp = entry.get('unblocked_at', 'N/A')
            self.unblock_history_list_widget.addItem(f"[{timestamp}] - {ip}")


# --- Main Application Execution ---
if __name__ == "__main__":
    # Print the banner to the console where the script is launched
    print_app_header() 

    app = QApplication(sys.argv)
    
    # Check admin status early for the GUI window itself
    if not is_admin():
        pass # Message box is shown in _check_admin_status

    gui = LogMonitorGUI()
    gui.show()
    sys.exit(app.exec_())