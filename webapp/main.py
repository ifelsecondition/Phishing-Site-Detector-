import psutil
import pyautogui
import pyperclip
import time
import pygetwindow as gw
from urllib.parse import urlsplit, parse_qs
import tldextract  # For advanced domain parsing
from dotenv import load_dotenv
from pathlib import Path
import os
import requests
import socket
import datetime
import requests
from urllib.parse import urlparse

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0.5

env_path = Path(__file__).parent / '.env'
load_dotenv(env_path, override=True)

SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = os.getenv("GOOGLE_API_URL")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_VERSION = os.getenv("CLIENT_VERSION")

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


phishing_keywords = {
    "generic_phishing": {
        "free": 8, "prize": 8, "win": 8, "congratulations": 8, "claim": 8, "reward": 8, "bonus": 8, "offer": 7, "limited": 7, "exclusive": 7,
        "selected": 6, "winner": 8, "lucky": 6, "draw": 6, "voucher": 6, "gift": 7, "cash": 7, "discount": 6, "deal": 5, "sale": 5,
        "opportunity": 6, "chance": 5, "instant": 6, "guaranteed": 6, "approval": 7, "accept": 6, "eligible": 5, "apply": 6, "register": 6,
        "subscription": 5, "membership": 5, "access": 6, "unclaimed": 7, "expire": 7, "urgent": 8, "important": 7, "immediate": 8,
        "action": 7, "required": 7, "verify": 8, "confirm": 8, "validate": 7, "reactivate": 7, "renew": 6, "update": 7, "information": 6,
        "account": 8, "details": 7, "security": 8, "notification": 6
    },
    "security_alerts": {
        "alert": 8, "unusual": 7, "suspicious": 8, "compromise": 9, "breach": 9, "hack": 9, "intrusion": 8, "attack": 8, "threat": 8,
        "malware": 9, "virus": 9, "ransomware": 9, "phishing": 8, "scam": 8, "fraud": 8, "spoofing": 8, "fake": 7, "unauthorized": 8,
        "login": 8, "access": 7, "password": 9, "credentials": 9, "stolen": 9, "leaked": 8, "exposed": 8, "vulnerability": 8,
        "patch": 7, "update": 7, "critical": 8, "emergency": 8, "action": 7, "required": 7, "verify": 8, "confirm": 7, "secure": 6,
        "protection": 6, "firewall": 5, "detection": 5, "incident": 7, "response": 6, "investigation": 5, "monitoring": 5, "safety": 6,
        "privacy": 7, "identity": 8, "theft": 8, "risk": 7, "warning": 7, "caution": 6, "danger": 7
    },
    "email_related": {
        "webmail": 7, "outlook": 7, "office365": 7, "mailbox": 6, "verification": 8, "login": 8, "account": 8, "password": 9, "credentials": 9,
        "inbox": 5, "message": 5, "attachment": 6, "quota": 4, "storage": 4, "sync": 4, "settings": 5, "profile": 5, "signature": 4, "forwarding": 5,
        "filter": 4, "spam": 5, "junk": 4, "blocked": 6, "suspended": 7, "disabled": 7, "expired": 6, "recovery": 7, "restore": 6, "backup": 5,
        "migration": 5, "upgrade": 5, "downtime": 5, "maintenance": 4, "notification": 5, "alert": 6, "security": 7, "privacy": 6, "encryption": 6,
        "authentication": 7, "2fa": 8, "mfa": 8, "otp": 7, "smtp": 4, "imap": 4, "pop3": 4, "server": 5, "domain": 5, "alias": 4, "address": 4, "contact": 4
    },
    "url_patterns": {
        "-secure": 8, "-login": 8, "-update": 7, "-verify": 8, "secure-": 8, "login-": 8, "update-": 7, "verify-": 8, "-account": 7, "-password": 8,
        "-recover": 7, "-reset": 7, "-confirm": 7, "-validation": 6, "-security": 7, "-authentication": 7, "-access": 6, "-portal": 6, "-service": 5,
        "-support": 5, "-help": 4, "-billing": 6, "-payment": 7, "-invoice": 6, "-subscription": 6, "-profile": 5, "-settings": 5, "-notification": 6,
        "-alert": 7, "-warning": 7, "-important": 7, "-urgent": 8, "-action": 7, "-required": 7, "-click": 7, "-here": 6, "-now": 7, "-today": 6,
        "-limited": 7, "-offer": 6, "-deal": 5, "-sale": 5, "-bonus": 6, "-reward": 6, "-prize": 7, "-win": 7, "-free": 7, "-congratulations": 7, "-claim": 7
    },
    "typosquatting": {
        "g00gle": 15, "faceb00k": 15, "amaz0n": 15, "micr0soft": 15, "paypa1": 15, "yaho0": 15, "bank0famerica": 15, "app1e": 15, "tw1tter": 15,
        "1nstagram": 15, "netf1ix": 15, "1inkedin": 15, "eb4y": 12, "whats4pp": 12, "tele9ram": 12, "redd1t": 12, "ad0be": 12, "sp0tify": 12,
        "dr0pbox": 12, "sl4ck": 12, "skyp3": 10, "vmw4re": 10, "int3l": 10, "cisc0": 10, "orac1e": 10, "samsu9g": 10, "1enovo": 10, "hp": 8,
        "d3ll": 8, "sn4pchat": 8, "p1nterest": 8, "tumbl3": 8, "f1ickr": 8, "v1meo": 8, "soundcl0ud": 8, "d1scord": 8, "tw1tch": 8, "h0ulu": 8,
        "qu0ra": 8, "med1um": 8, "w1kipedia": 8, "go0gle": 15, "facebo0k": 15, "amaz0n": 15, "micros0ft": 15, "payp4l": 15, "yah00": 15,
        "bankofamer1ca": 15, "app1e": 15, "tw1tter": 15
    }
}

def browser_running():
    """Check if any browser is running."""
    browsers = ["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe"]
    for process in psutil.process_iter(['name']):
        if process.info['name'].lower() in browsers:
            return process.info['name']
    return None

def active_window():
    """Find and return open browser window titles."""
    browser_titles = []
    all_windows = gw.getAllTitles()
    browsers = ["chrome", "edge", "brave", "firefox", "mozilla"]
    
    for title in all_windows:
        if title and any(browser in title.lower() for browser in browsers):
            browser_titles.append(title)
    return browser_titles

def focus_browser():
    """Activate the first browser window found."""
    browsers = ["chrome", "edge", "brave", "firefox"]
    for _ in range (2):
        for window in gw.getWindowsWithTitle(""):
            if window.title and any(browser in window.title.lower() for browser in browsers):
                try:
                   window.activate()
                   window.maximize()
                   if window.isMinimized:
                       window.restore()
                   time.sleep(0.8)
                   return True
                except Exception as e:
                   print(f"Error focusing window: {e}")
        time.sleep(1)
    return False

def get_browser_url():
    """Copy the current URL from the browser's address bar."""
    if not focus_browser():
        print("Unable to focus browser window.")
        return None
    
    max_retries = 5
    for attempt in range(max_retries):
    
        try:
            # Clear clipboard first
            pyperclip.copy('')
            time.sleep(0.5)
        
            # Select and copy URL
            pyautogui.hotkey("ctrl", "l")
            time.sleep(0.3)
            pyautogui.hotkey("ctrl", "c")
            time.sleep(0.5)
        
            url = pyperclip.paste().strip()
            return url if url and url.startswith(('http://', 'https://')) else None
            
            print(f"Attempt {attempt + 1}: Invalid URL")
            time.sleep(1)
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: str{(e)}")
            time.sleep(1)

    print(f"Failed after {max_retries} attempts")
    return None




def get_ip_from_url(url):
    # If the URL has a protocol (http/https), remove it
    if url.startswith('http://') or url.startswith('https://'):
        url = url.split('//')[1]
    # Remove any path/query params
    url = url.split('/')[0]
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror:
        return None

def get_country_from_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        country = data.get('country', 'Unknown')
        return country
    except Exception as e:
        print(f"Error finding country: {e}")
        return None



def advanced_url_analysis(url):
    """Perform advanced parsing and analysis of the URL."""
    if not url:
        return None
    
    parsed = urlsplit(url)
    extracted = tldextract.extract(url)
    
    # Parse query parameters into a dictionary
    query_params = parse_qs(parsed.query)
    
    # Split path into components
    path_components = [comp for comp in parsed.path.split('/') if comp]
    
    return {
        "full_url": url,
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "domain": {
            "subdomain": extracted.subdomain,
            "main_domain": extracted.domain,
            "suffix": extracted.suffix,
            "full_domain": f"{extracted.domain}.{extracted.suffix}"
        },
        "path": {
            "full_path": parsed.path,
            "components": path_components,
            "last_component": path_components[-1] if path_components else None
        },
        "query": {
            "raw": parsed.query,
            "params": query_params
        },
        "fragment": parsed.fragment
    }

def detect_suspicious_elements(url_analysis):
    """Check URL components against phishing keywords and return weighted matches."""
    if not url_analysis:
        return {}
    
    results = {category: {} for category in phishing_keywords}
    
    domain_parts = [
        url_analysis['domain']['subdomain'],
        url_analysis['domain']['main_domain'],
        url_analysis['domain']['suffix']
    ]
    
    # Check domain parts
    for part in domain_parts:
        if not part:
            continue
        part_lower = part.lower()
        for category, keywords in phishing_keywords.items():
            for kw, weight in keywords.items():
                if kw.lower() in part_lower:
                    results[category][kw] = weight
    
    # Check path components
    for comp in url_analysis['path']['components']:
        comp_lower = comp.lower()
        for category, keywords in phishing_keywords.items():
            for kw, weight in keywords.items():
                if kw.lower() in comp_lower:
                    results[category][kw] = weight
    
    # Check query parameters
    for param, values in url_analysis['query']['params'].items():
        param_lower = param.lower()
        for value in values:
            value_lower = value.lower()
            for category, keywords in phishing_keywords.items():
                for kw, weight in keywords.items():
                    if (kw.lower() in param_lower) or (kw.lower() in value_lower):
                        results[category][kw] = weight
    
    return {k: v for k, v in results.items() if v}

def check_safe_browsing(url):
    """Checks URL through API"""
    if not all([SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL, CLIENT_ID]):
        print("API not configured, skipping checks")
        return None
    
    payload = {
        "client": {
            "clientId": CLIENT_ID,
            "clientVersion": CLIENT_VERSION
        },
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        return response.json()
    except Exception as E:
        print("API Error")
        return None

# At the bottom of main.py, replace the current main() call with:

if __name__ == "__main__":
    try:
        # Check browser status
        browser = browser_running()
        if browser:
            print(f"Detected browser: {browser}")
        else:
            print("No supported browser detected.")
            exit()
        
        # Get active windows
        windows = active_window()
        print("Open browser windows:", windows or "None found")
        
        # Get current URL
        current_url = get_browser_url()
        if not current_url:
            print("Could not retrieve URL from browser")
            exit()
            
        print("\nCurrent URL:", current_url)
        ip_add = get_ip_from_url(current_url)
        country = get_country_from_url(current_url)
        print("IP ADDRESS:", ip_add)
        print("COUNTRY:", country)
        
        # Call certificate checker
        from certificate_checker import get_ssl_info, calculate_threat_level, load_threat_intel
        # Replace the certificate checker call in main.py with this:
        print("\n=== SSL Certificate Information ===")
        ssl_info = get_ssl_info(advanced_url_analysis['domain']['full_domain'])
        if ssl_info:
            # Print SSL info in rows of 6 items
            items = list(ssl_info.items())
            for i in range(0, len(items), 6):
                row = items[i:i+6]
                print(", ".join(f"{k}: {v}" for k, v in row))
        else:
            print("No SSL certificate information available")

        # Calculate and print threat level
        malicious_ips = load_threat_intel()
        malicious_ips.update(malicious_ip)  # Combine with local list
        threat_level, reasons = calculate_threat_level(ssl_info, ip_add, malicious_ips)
        print("\nThreat Level:", threat_level)
        print("Reasons:", ", ".join(reasons))
        
        # Advanced analysis
        url_analysis = advanced_url_analysis(current_url)
        print("\nAdvanced URL Analysis:")
        print(f"Domain: {url_analysis['domain']['full_domain']}")
        print(f"Path: {url_analysis['path']['full_path']}")
        if url_analysis['query']['params']:
            print("Query Parameters:", url_analysis['query']['params'])
        
        # Keyword detection
        detections = detect_suspicious_elements(url_analysis)
        print("\nSuspicious Elements Detected:")
        for category, keywords in detections.items():
            print(f"{category.upper()}: {', '.join(keywords)}")

        # Safe Browsing API Check
        safe_browsing_result = check_safe_browsing(current_url)
        if safe_browsing_result and safe_browsing_result.get("matches"):
            print("Safe Browsing Alert!")
            for match in safe_browsing_result["matches"]:
                print(f"- Threat Type: {match['threatType']}")
                print(f"- Platform: {match['platformType']}")
            
    except Exception as e:
        print(f"An error occurred: {e}")