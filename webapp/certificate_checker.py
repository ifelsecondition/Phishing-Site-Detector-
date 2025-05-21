import socket
import ssl
import datetime
from urllib.parse import urlparse
import requests
from io import StringIO
import pandas as pd
import datetime
# === CONFIG ===
THREAT_INTEL_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" #all blocked ip data

malicious_ip = [
    "45.83.64.1", "103.27.124.82", "185.53.178.6", "23.82.12.32", "185.220.101.1",
    "144.217.86.109", "198.50.233.244", "185.107.56.55", "91.214.124.38", "179.43.154.137",
    "198.50.233.245", "185.234.219.9", "185.220.100.253", "185.220.102.244", "103.27.124.83",
    "91.220.131.183", "91.214.124.36", "179.43.154.138", "198.50.233.246", "45.83.64.2",
    "185.220.100.254", "185.220.101.2", "185.220.102.245", "185.220.102.246", "185.220.101.3",
    "185.107.56.54", "198.50.233.247", "198.50.233.248", "23.82.12.33", "91.214.124.37",
    "91.214.124.39", "45.83.64.3", "45.83.64.4", "198.50.233.249", "144.217.86.110",
    "144.217.86.111", "198.50.233.250", "185.107.56.53", "185.107.56.52", "91.214.124.40",
    "91.214.124.41", "91.214.124.42", "45.83.64.5", "45.83.64.6", "45.83.64.7",
    "103.27.124.84", "103.27.124.85", "103.27.124.86", "185.53.178.7", "185.53.178.8",
    "185.53.178.9", "185.53.178.10", "179.43.154.139", "179.43.154.140", "179.43.154.141",
    "179.43.154.142", "23.82.12.34", "23.82.12.35", "23.82.12.36", "185.234.219.10",
    "185.234.219.11", "185.234.219.12", "185.234.219.13", "185.234.219.14", "185.234.219.15",
    "185.220.100.250", "185.220.100.251", "185.220.100.252", "185.220.102.247", "185.220.102.248",
    "185.220.102.249", "185.220.102.250", "185.220.102.251", "185.220.102.252", "185.220.102.253",
    "185.220.102.254", "185.220.101.4", "185.220.101.5", "185.220.101.6", "185.220.101.7",
    "185.220.101.8", "185.220.101.9", "185.220.101.10", "185.220.101.11", "185.220.101.12",
    "185.220.101.13", "185.220.101.14", "185.220.101.15", "185.220.101.16", "185.220.101.17",
    "185.220.101.18", "185.220.101.19", "185.220.101.20", "185.220.101.21", "185.220.101.22",
    "185.220.101.23", "185.220.101.24", "185.220.101.25", "185.220.101.26", "185.220.101.27"
]


def load_threat_intel():
    """Load threat intel database."""
    try:
        response = requests.get(THREAT_INTEL_URL, timeout=10)
        csv_data = StringIO(response.text)
        df = pd.read_csv(csv_data, comment='#', header=None, names=['first_seen', 'dst_ip', 'dst_port', 'last_seen', 'malware'])
        return set(df['dst_ip'].dropna().values)
    except Exception as e:
        print(f"[Error] Threat intel load failed: {e}")
        return set()

def get_ssl_info(domain):
    """Fetch SSL certificate info."""
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
        valid_from = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        remaining_days = (valid_to - datetime.datetime.utcnow()).days
        return {
            'issuer': issuer,
            'valid_from': valid_from.strftime("%Y-%m-%d"),
            'valid_to': valid_to.strftime("%Y-%m-%d"),
            'remaining_days': remaining_days,
            'SANs': cert.get('subjectAltName', [])
        }
    except Exception as e:
        print(f"[SSL Error] {e}")
        return None

def calculate_threat_level(ssl_info, ip, malicious_ips):
    """Calculate threat based on SSL and IP."""
    threat_score = 0
    reasons = []

    if ssl_info is None:
        return "🔴 90% Phishing Risk", ["SSL certificate missing or failed to retrieve"]

    # Safe access to 'issuer'
    issuer = ssl_info.get('issuer', '')  # Get 'issuer' or empty string if not found

    if ssl_info.get('remaining_days', 0) < 15:  # Also safe access
        threat_score += 2
        reasons.append("SSL certificate expiring soon")

    if issuer and "Let's Encrypt" in issuer:
        threat_score += 0.5
        reasons.append("Basic SSL (Let's Encrypt) issuer detected")
    elif not issuer:
        reasons.append("Issuer information missing in SSL certificate")

    if ip in malicious_ips:
        threat_score += 3
        reasons.append("IP found in threat intelligence database")
    else:
        reasons.append("No intrusion detected")

    if threat_score >= 3:
        return "🔴 High Risk", reasons
    elif threat_score >= 1.5:
        return "🟠 Medium Risk", reasons
    else:
        return "🟢 Low Risk", reasons


def main(url, ip, country):
    """Main function to check URL and IP."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    print(f"Checking Domain: {domain}")
    print(f"Using IP: {ip}")

    malicious_ips = load_threat_intel()

    ssl_info = get_ssl_info(domain)
    
    threat_level, reasons = calculate_threat_level(ssl_info, ip, malicious_ips)

    print("\n=== SECURITY REPORT ===")
    if ssl_info:
        print(f"Domain: {domain}")
        print(f"IP Address: {ip}")
        print(f"Country: {country}")
        print(f"Issuer: {ssl_info['issuer']}")
        print(f"Valid From: {ssl_info['valid_from']}")
        print(f"Valid Until: {ssl_info['valid_to']}")
        print(f"Days Left: {ssl_info['remaining_days']}")
        print(f"SANs: {', '.join([x[1] for x in ssl_info['SANs']])}")
    else:
        print("SSL Certificate: ❌ Not Found")

    print("\nThreat Level:", threat_level)
    print("Reasons:", ', '.join(reasons))