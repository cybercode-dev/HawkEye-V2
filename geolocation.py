"""
HawkEye IP Geolocation
Resolves country/city/ISP for suspicious IP addresses using the free
ip-api.com batch endpoint (no API key required, 45 req/min limit on the
free tier). Private/reserved IPs are detected locally and skipped.
"""

import ipaddress
import logging

import requests

logger = logging.getLogger("hawkeye.geo")

GEO_BATCH_URL = "http://ip-api.com/batch"
GEO_FIELDS = "status,message,country,countryCode,regionName,city,isp,org,query"
REQUEST_TIMEOUT = 4  # seconds


def _is_private_or_reserved(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return True  # not a real IP -> treat as unlocatable


def get_geolocations(ip_list):
    """
    Given a list of IP address strings, return a dict:
        { ip: {"country": ..., "city": ..., "isp": ..., "flag": "🌐"} }
    Private/invalid IPs and lookup failures get a graceful fallback entry
    instead of raising, so the dashboard never breaks because of a
    network hiccup.
    """
    results = {}
    lookup_needed = []

    for ip in ip_list:
        if _is_private_or_reserved(ip):
            results[ip] = {
                "country": "Private network",
                "region": "",
                "city": "",
                "isp": "Internal / LAN",
                "query": ip,
            }
        else:
            lookup_needed.append(ip)

    if not lookup_needed:
        return results

    try:
        payload = [{"query": ip, "fields": GEO_FIELDS} for ip in lookup_needed]
        resp = requests.post(GEO_BATCH_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        for entry in data:
            ip = entry.get("query")
            if entry.get("status") == "success":
                results[ip] = {
                    "country": entry.get("country") or "Unknown",
                    "region": entry.get("regionName") or "",
                    "city": entry.get("city") or "",
                    "isp": entry.get("isp") or entry.get("org") or "Unknown",
                    "query": ip,
                }
            else:
                results[ip] = {
                    "country": "Unknown",
                    "region": "",
                    "city": "",
                    "isp": "Lookup failed",
                    "query": ip,
                }
    except requests.RequestException as e:
        logger.warning("Geolocation lookup failed: %s", e)
        for ip in lookup_needed:
            results[ip] = {
                "country": "Unavailable",
                "region": "",
                "city": "",
                "isp": "Geolocation service unreachable",
                "query": ip,
            }

    return results


def enrich_ips_with_geo(top_ips):
    """
    Takes the list of dicts produced by analyzer.analyze_log()'s
    'top_ips' field (each with an 'ip' key) and returns a new list with
    country/city/isp merged in.
    """
    if not top_ips:
        return top_ips

    ip_list = [item["ip"] for item in top_ips]
    geo = get_geolocations(ip_list)

    enriched = []
    for item in top_ips:
        info = geo.get(item["ip"], {
            "country": "Unknown", "region": "", "city": "", "isp": "Unknown",
        })
        merged = dict(item)
        merged["country"] = info["country"]
        merged["region"] = info.get("region", "")
        merged["city"] = info.get("city", "")
        merged["isp"] = info["isp"]
        merged["location"] = ", ".join(
            [p for p in [info.get("city"), info.get("region"), info.get("country")] if p]
        ) or info["country"]
        enriched.append(merged)

    return enriched
