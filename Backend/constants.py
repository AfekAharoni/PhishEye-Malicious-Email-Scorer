import os 
from dotenv import load_dotenv

load_dotenv()

# Regex patterns

URL_PATTERN = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
"""
Find for http, s is optional, then ://, then continues to read chars except (one or more)
from spaces/tabs (\s) and '<', '>' from HTML code
Another option is 'www.' as prefix
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
PLATFORM_TYPES = ["ANY_PLATFORM"], # works for every platform, i.e Windows/Mac/Andriod etc
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
                   'wav', 'mp4', 'mp3', 'webp', 'txt'}