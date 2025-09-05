# phishing_detector.py
import re
import socket
import ipaddress
import whois
import datetime
from urllib.parse import urlparse

def contains_ip(url):
    """Check if URL contains an IP address."""
    try:
        hostname = urlparse(url).netloc
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def domain_age(domain):
    """Return the age of the domain in years."""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (datetime.datetime.now() - creation_date).days / 365
            return age
    except:
        return None

def check_url(url):
    """Check URL for phishing indicators and return a dictionary of results."""
    results = {}

    # IP address check
    results["Contains IP Address"] = "Yes" if contains_ip(url) else "No"

    # @ symbol
    results["Contains @"] = "Yes" if "@" in url else "No"

    # Hyphen in domain
    domain = urlparse(url).netloc
    results["Contains Hyphen"] = "Yes" if "-" in domain else "No"

    # HTTPS check
    results["Missing HTTPS"] = "Yes" if not url.startswith("https://") else "No"

    # Mailto check
    results["Contains mailto"] = "Yes" if "mailto:" in url else "No"

    # Domain age
    age = domain_age(domain)
    results["Domain Age < 1 year"] = "Yes" if age is not None and age < 1 else "No"

    # Overall Safe/Suspicious
    results["Safe/Suspicious"] = "Suspicious" if "Yes" in results.values() else "Safe"

    return results

