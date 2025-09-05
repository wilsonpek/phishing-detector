#!/usr/bin/env python3.13
import re
from urllib.parse import urlparse
from datetime import datetime
import requests
import whois
import ipaddress
from scapy.all import sr1, IP, ICMP

# -----------------------------
# Helper functions
# -----------------------------

def yes_no(value):
    return "Yes" if value else "No"

def has_ip_address(url):
    ip_pattern = r'^(http[s]?://)?(\d{1,3}\.){3}\d{1,3}'
    return bool(re.match(ip_pattern, url))

def has_at_symbol(url):
    return '@' in url

def has_hyphen(url):
    domain = urlparse(url).netloc
    return '-' in domain

def is_https(url):
    return url.startswith('https://')

def has_mailto(url):
    return 'mailto:' in url

def domain_age(url):
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        return age_days
    except:
        return None

def check_url_reachable(url):
    """Check if URL is reachable via HTTP requests"""
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

def scapy_ping(host):
    """Check if host is reachable using Scapy ICMP ping"""
    try:
        pkt = IP(dst=host)/ICMP()
        resp = sr1(pkt, timeout=2, verbose=0)
        return resp is not None
    except:
        return False

# -----------------------------
# Main function for web use
# -----------------------------
def analyze_url_for_web(url):
    """
    Returns a dictionary of phishing indicators and overall assessment.
    Designed for Flask integration.
    """
    score = 0
    result = {"url": url, "indicators": {}, "assessment": ""}

    # Phishing indicators
    indicators = {
        "Contains IP address": has_ip_address(url),
        "Contains '@' symbol": has_at_symbol(url),
        "Contains '-' in domain": has_hyphen(url),
        "Uses HTTPS": is_https(url),
        "Contains 'mailto:'": has_mailto(url)
    }

    if not indicators["Uses HTTPS"]:
        score += 1

    for key, value in indicators.items():
        result["indicators"][key] = yes_no(value)
        if value and key != "Uses HTTPS":  # HTTPS already counted
            score += 1

    # Domain age check
    age = domain_age(url)
    if age is None:
        result["indicators"]["Domain age"] = "Unknown"
    else:
        result["indicators"]["Domain age"] = str(age) + " days"
        if age < 180:
            score += 1

    # Safe / Suspicious flag
    result["assessment"] = "Suspicious" if score >= 2 else "Safe"

    return result

