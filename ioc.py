"""
HawkEye IOC Extraction (Module 5)
Extracts Indicators of Compromise from the normalized event stream:
source IPs, usernames, hostnames, and processes, each with attempt
counts and a first/last-seen window — ready to render as a table or
export to a report.
"""

from collections import defaultdict


def _bucket(events, field, event_filter=None):
    counts = defaultdict(int)
    first_seen = {}
    last_seen = {}
    for e in events:
        if event_filter and not event_filter(e):
            continue
        value = e.get(field)
        if not value:
            continue
        counts[value] += 1
        ts = e.get("timestamp")
        if ts:
            if value not in first_seen or ts < first_seen[value]:
                first_seen[value] = ts
            if value not in last_seen or ts > last_seen[value]:
                last_seen[value] = ts
    return counts, first_seen, last_seen


def extract_iocs(events, limit=20):
    """
    Returns a dict with four IOC categories, each a list of dicts sorted
    by attempt count (descending), capped at `limit` entries:
        { "source_ips": [...], "usernames": [...], "hostnames": [...], "processes": [...] }
    """
    is_failed = lambda e: e.get("event_type") in ("auth_failure", "invalid_user")

    ip_counts, ip_first, ip_last = _bucket(events, "source_ip")
    ip_failed_counts, _, _ = _bucket(events, "source_ip", event_filter=is_failed)

    user_counts, user_first, user_last = _bucket(events, "username")
    user_failed_counts, _, _ = _bucket(events, "username", event_filter=is_failed)

    host_counts, host_first, host_last = _bucket(events, "hostname")
    proc_counts, proc_first, proc_last = _bucket(events, "process")

    def _rows(counts, failed_counts, first_map, last_map, ioc_type):
        rows = []
        for value, count in counts.items():
            rows.append({
                "type": ioc_type,
                "value": value,
                "attempts": count,
                "failed_attempts": failed_counts.get(value, 0),
                "first_seen": first_map.get(value),
                "last_seen": last_map.get(value),
            })
        rows.sort(key=lambda r: r["attempts"], reverse=True)
        return rows[:limit]

    return {
        "source_ips": _rows(ip_counts, ip_failed_counts, ip_first, ip_last, "Source IP"),
        "usernames": _rows(user_counts, user_failed_counts, user_first, user_last, "Username"),
        "hostnames": _rows(host_counts, {}, host_first, host_last, "Hostname"),
        "processes": _rows(proc_counts, {}, proc_first, proc_last, "Process"),
    }


def flatten_iocs(ioc_dict, limit=50):
    """Flatten the categorized IOC dict into one list for a single table view."""
    flat = []
    for category in ("source_ips", "usernames", "hostnames", "processes"):
        flat.extend(ioc_dict.get(category, []))
    flat.sort(key=lambda r: r["attempts"], reverse=True)
    return flat[:limit]
