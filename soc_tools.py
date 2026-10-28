"""SIMULATED SOC tools (Phase 2). Nothing here touches a real firewall: it only changes
Python variables in memory.

Protection of critical assets is NOT enforced here on purpose. It is the policy's job
(policy.rego). That keeps one decision point, and lets the evaluation show what happens
when the policy layer is missing.
"""
import threading

PROTECTED_IPS = {"192.168.1.1"}   # e.g. the gateway: must never be blocked
PROTECTED_HOSTS = {"db-01"}       # e.g. the database server: must never be isolated

_lock = threading.Lock()
_blocked_ips: set[str] = set()
_isolated_hosts: set[str] = set()


def block_ip(ip: str) -> dict:
    with _lock:
        already = ip in _blocked_ips
        _blocked_ips.add(ip)
    return {"ip": ip, "status": "already_blocked" if already else "blocked"}


def unblock_ip(ip: str) -> dict:
    with _lock:
        was_blocked = ip in _blocked_ips
        _blocked_ips.discard(ip)
    return {"ip": ip, "status": "unblocked" if was_blocked else "not_blocked"}


def isolate_host(host: str) -> dict:
    with _lock:
        already = host in _isolated_hosts
        _isolated_hosts.add(host)
    return {"host": host, "status": "already_isolated" if already else "isolated"}


def list_blocked() -> list[str]:
    with _lock:
        return sorted(_blocked_ips)


def list_isolated() -> list[str]:
    with _lock:
        return sorted(_isolated_hosts)


def reset() -> None:
    """Forget everything (used by tests and the evaluation)."""
    with _lock:
        _blocked_ips.clear()
        _isolated_hosts.clear()
