import os 
from dotenv import load_dotenv

load_dotenv()

# Print logs iff debug if True
DEBUG = False

# Regex patterns

URL_PATTERN = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
"""
Looks for http, s is optional, then ://, then continues to read chars except (one or more)
from spaces/tabs (\s) and '<', '>' from HTML code
Another option is 'www.' as prefix
"""
SENDER_DOMAIN_PATTERN = r'[\w\.-]+@([\w\.-]+)'
"""
Looks for one or more valid email name characthers before the '@' sign, then '@' sign, then 
(one or more) domain characthers after the '@' sign
Group 0: all text
Group 1: domain only
"""
# HTML parsing
HTML_PARSER = "html.parser"
A_TAG = 'a'
HREF_ATTR = "href"

# Dictionary keys (for consistency between modules)
KEY_DISPLAY_TEXT = "display_text"
KEY_ACTUAL_URL = "actual_url"

# Safe Browsing API configuration
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_CLIENT_ID = "malicious-email-scorer"
SAFE_BROWSING_CLIENT_VERION = "1.0.0"

# Threat types
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
"""
MALWARE - Sites that host malicious software designed to damage or gain
    unauthorized access 
SOCIAL_ENGINEERING - Identifies deceptive sites, such as phising sites, that 
    trick users into revealing sensitive information like password or credit
    card number
UNWANTED_SOFTWARE - Flags sites that promote or distribute software that
    may be deceptive, difficult to uninstall or perform unexpected actions
    on a user's device
"""
PLATFORM_TYPES = ["ANY_PLATFORM"] # works for every platform, i.e Windows/Mac/Andriod etc
THREAT_ENTRY_TYPES = ["URL"]
URL_PLACEHOLDER = "{URL_HERE}"
REQUEST_TO_GOOGLE_API = {
    "client": {
        "clientId": SAFE_BROWSING_CLIENT_ID,
        "clientVersion": SAFE_BROWSING_CLIENT_VERION
    },
    "threatInfo": {
        "threatTypes": THREAT_TYPES,
        "platformTypes": PLATFORM_TYPES,
        "threatEntryTypes": THREAT_ENTRY_TYPES,
        "threatEntries": [{"url": URL_PLACEHOLDER}]
    }
}
TIMEOUT = 5
# Status codes
SUCCESS_STATUS_CODE = 200
CLIENT_ERROR_STATUS_CODE = 400

# Links to ignore
MAILTO_IGNORE = "mailto:"
TEL_IGNORE = "tel:"

# Status
SAFE_STATUS = "Safe"
MALICIOUS_STATUS = "Malicious"
SUSPICIOUS_STATUS = "Suspicious"

# VirusTotal API configuration
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

# Safe file extensions
SAFE_EXTENSIONS = {'log', 'txt', 'bmp', 'gif', 'png', 'jpeg', 'jpg', 'wma', 'avi',
                   'wav', 'mp4', 'mp3', 'webp'}

# Sender email domains
FREE_EMAIL_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", 
                      "icloud.com", "proton.me", "protonmail.com", "tuta.com",
                      "zoho.com", "aol.com", "gmx.com", "mail.com",
                      "walla.co.il", "yandex.com", "mailfence.com"}
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "googlemail.com"],
    "microsoft": ["microsoft.com", "office.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "leumi": ["leumi.co.il"],
    "discount": ["discountbank.co.il"],
    "bit": ["bitpay.co.il"],
    # for tests usage:
    "phishbank": ["phishbank.com"], 
    "notphishybank": ["notphishybank.com"] 
}

# Email content
PHISHING_KEYWORDS = ["urgent", "verify your account", "account suspended",
                     "password", "login", "payment failed", "security alert",
                     "unusual activity", "click here", "final warning",
                     "confirm your identity"]
SENSITIVE_REQUESTS = ["password", "credit card", "otp", "one time password",
                      "verification code", "bank account", "id number"]

# URL Shorteners
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", 
                     "ow.ly", "is.gd", "buff.ly", "cutt.ly",
                     "rebrand.ly", "rb.gy", "shorturl.at", "urli.info"}

# Authentication protocols
DKIM_TAG = "dkim"
SPF_TAG = "spf"
DMARC_TAG = "dmarc"
PASS_RESULT = "pass"