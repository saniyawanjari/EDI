"""Agent B - Threat Detector. Ranks suspicious IPs by severity. It cannot block anything."""

HIGH_THRESHOLD = 6    # 6 or more failed logins = high
MEDIUM_THRESHOLD = 3  # 3 to 5 failed logins = medium

_RANK = {"high": 2, "medium": 1}


def analyze(report: dict) -> list[dict]:
    """report = Agent A's {ip: failed_login_count}. Returns threats, most severe first."""
    threats = []
    for ip, count in report.items():
        if count >= HIGH_THRESHOLD:
            severity = "high"
        elif count >= MEDIUM_THRESHOLD:
            severity = "medium"
        else:
            continue  # fewer than 3 failures: not a threat
        threats.append((count, {"ip": ip, "severity": severity,
                                "reason": f"{count} failed SSH logins"}))
    # highest severity first, then most failures first
    threats.sort(key=lambda item: (_RANK[item[1]["severity"]], item[0]), reverse=True)
    return [threat for _count, threat in threats]
