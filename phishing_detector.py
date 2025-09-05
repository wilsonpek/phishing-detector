import ipaddress
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime

# Suspicious words commonly used in phishing
SUSPICIOUS_WORDS = ['login', 'secure', 'account', 'verify', 'update', 'bank', 'confirm']

def check_url(url):
    result = {}
    result['URL'] = url

    # Normalize URL
    url = url.strip().lower()
    parsed = urlparse(url)

    # Contains IP Address
    try:
        ipaddress.ip_address(parsed.hostname)
        result['Contains IP Address'] = 'Yes'
    except ValueError:
        result['Contains IP Address'] = 'No'

    # Contains @ symbol
    result['Contains @'] = 'Yes' if '@' in url else 'No'

    # Contains hyphen
    result['Contains Hyphen'] = 'Yes' if '-' in parsed.hostname else 'No'

    # HTTPS
    result['HTTPS'] = 'Yes' if parsed.scheme == 'https' else 'No'

    # mailto
    result['Contains mailto'] = 'Yes' if 'mailto:' in url else 'No'

    # Subdomain count
    result['Subdomain Count'] = str(parsed.hostname.count('.') - 1)  # Exclude main domain + TLD

    # Suspicious words
    result['Suspicious Words'] = ', '.join([w for w in SUSPICIOUS_WORDS if w in url]) or 'None'

    # URL length
    result['URL Length'] = str(len(url))

    # Domain age
    try:
        domain_info = whois.whois(parsed.hostname)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            result['Domain Age (days)'] = str(age_days)
        else:
            result['Domain Age (days)'] = 'Unknown'
    except:
        result['Domain Age (days)'] = 'Unknown'

    # URL Reachable
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            result['URL Reachable'] = 'Yes'
        else:
            result['URL Reachable'] = 'No'
    except:
        result['URL Reachable'] = 'No'

    # SSL Certificate
    ssl_status = 'No'
    if parsed.scheme == 'https':
        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_status = 'Yes'
        except:
            ssl_status = 'No'
    result['Valid SSL'] = ssl_status

    # Determine Safe / Suspicious
    critical_flags = ['Contains IP Address', 'Contains @', 'Contains Hyphen', 'HTTPS', 'URL Reachable', 'Valid SSL']
    suspicious = any(result[flag] == 'Yes' or result[flag] == 'No' for flag in critical_flags if flag in ['Contains IP Address','Contains @','Contains Hyphen'] or flag in ['HTTPS','URL Reachable','Valid SSL'])
    result['Overall'] = 'Suspicious' if suspicious else 'Safe'

    return result

