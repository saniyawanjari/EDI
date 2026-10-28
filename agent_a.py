"""Agent A - Log Analyst.

It READS logs and REPORTS suspicious IPs. It has no code to block anything:
suggesting is separate from executing (executing belongs to Agent C, later).
"""
import re
from pathlib import Path

import pandas as pd

# Always find the log file next to this script, no matter where we run from.
LOG_FILE = Path(__file__).parent / "server_logs.txt"

# Report every IP with this many (or more) failed logins.
THRESHOLD = 3

# Matches e.g. "Failed password for root from 203.0.113.5 port ..."
# and           "Failed password for invalid user admin from 203.0.113.5 port ..."
#   (?:invalid user )?  -> optional words "invalid user "
#   \S+                 -> the username (any non-space text)
#   (\d{1,3}(?:\.\d{1,3}){3}) -> the IP address, captured as group 1
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})"
)


def run_analysis() -> dict:
    """Read the log, count failed logins per IP, return IPs at or over THRESHOLD."""
    ips = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ips.append(match.group(1))

    # No failed logins at all -> empty report.
    if not ips:
        return {}

    # pandas: turn the list into a Series and count how often each IP appears.
    counts = pd.Series(ips).value_counts()
    suspicious = counts[counts >= THRESHOLD]

    # Convert numpy integers to normal Python ints so FastAPI can make JSON.
    return {ip: int(n) for ip, n in suspicious.items()}
