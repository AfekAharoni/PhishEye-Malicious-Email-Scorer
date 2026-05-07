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