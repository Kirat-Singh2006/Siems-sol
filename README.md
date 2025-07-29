# Siems-sol


Author: wrench
Year: 2025
Overview

This is a powerful GUI-based Python application designed to:

    Monitor authentication logs for repeated failed login attempts

    Automatically block suspicious IPs using Windows Firewall

    Send email alerts for potential brute-force attacks

    Provide a live GUI for managing settings, monitoring logs, and viewing/unblocking IPs

This tool is useful for Windows-based environments where SSH, RDP, or other remote services may be under attack.
Features

    📜 Real-time log file monitoring (using watchdog)

    🔐 Automatic IP blocking via Windows Firewall

    📧 Optional email notifications for suspicious activities

    🖥️ Full GUI built with PyQt5

    💾 Persistent settings stored in settings.json

    🗃️ Blocked/unblocked IPs saved and loaded automatically

    ✅ Supports log rotation detection

Requirements

    Python 3.8+

    Windows OS with Administrator privileges (for IP blocking)

    Python dependencies (install via pip install -r requirements.txt):

PyQt5
watchdog
colorama

You may also need:

smtplib (built-in)

Installation

    Clone the repository:

git clone https://github.com/yourname/log-monitor.git
cd log-monitor

    Install dependencies:

pip install -r requirements.txt

    Run as Administrator (important):

python log-monitor.py

Usage

    Settings Tab: Configure the log file path, failed attempt limit, time window, and email settings.

    Live Log Tab: View real-time events and alerts.

    Blocked IPs Tab: See and unblock tracked IPs.

    Unblock History Tab: View unblocked IP history.

    Start/Stop Monitoring: Use the top control buttons to control the monitor.

Log Format

Supported log entries should match this pattern:

YYYY-MM-DD HH:MM:SS Failed password for (invalid user)? <user> from <ip>

Example:

2025-07-29 13:00:02 Failed password for invalid user admin from 192.168.1.10

Configuration Files

    settings.json: Stores all UI settings including email and firewall preferences.

    blocked_ips.json: List of currently blocked IPs.

    unblocked.json: Unblocked IP history.

Email Notifications (Optional)

To enable email alerts:

    Fill in SMTP details in the Settings tab:

        SMTP Server

        Port (465 for SMTPS, 587 for STARTTLS)

        Sender Email & Password

        Recipient Email

    Check Enable Email Notifications

    Save settings

    Use secure application passwords or environment variables for better security.

Notes

    This tool uses netsh to manage firewall rules. It will only work on Windows.

    Administrator privileges are required to block/unblock IPs.

    All actions and logs are color-coded in the GUI.

Troubleshooting

    Firewall rule not applying?

        Run as Administrator

        Check Windows Firewall is enabled

    Email not sending?

        Verify SMTP settings and credentials

    No log entries?

        Ensure the log file exists and is readable

License

This project is free to use and modify. Please credit the original author if redistributed.
