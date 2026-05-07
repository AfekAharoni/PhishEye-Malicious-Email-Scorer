import re
from urllib.parse import urlparse 
from bs4 import BeautifulSoup
from constants import (
    URL_PATTERN, HTML_PARSER, A_TAG,
      HREF_ATTR, MAILTO_IGNORE, TEL_IGNORE, 
      KEY_ACTUAL_URL, KEY_DISPLAY_TEXT)

class EmailPreprocessor:
    @staticmethod
    def extract_urls(html_content: str) -> list[str]:
        """
        Extracts raw urls from html content using regular expression
        Args:
            html_content (str): The raw text to be processed
        Returns:
            list[str]: A list of all unique urls found in the string given
        """
        return re.findall(URL_PATTERN, html_content)
    
    @staticmethod
    def extract_hyperlinks(html_content: str) -> list[dict]:
        """
        Extracts hyperlinks from html content using regular expression
        Identifies all <a> tags with an href attribute and extract both the 
        visible display text and the actual url
        Args:
            html_content (str): The raw text to be processed
        Returns:
            list[dict]: A list of dictionaries, each contains:
                1. 'display_text' (str): The text the user see
                2. 'actual_url' (str): The real url the link points to
        """
        soup = BeautifulSoup(html_content, HTML_PARSER)
        links = []
        for a in soup.findAll(A_TAG, href=True): # find all <a> tags
            url = a[HREF_ATTR].strip()
            if url.lower().startswith(MAILTO_IGNORE) or url.lower().startswith(TEL_IGNORE):
                continue # ignore "mailto: EMAIL-ADDRESS" links, "tel: PHONE-NUMBER" links
            if url == "#" or url == "" or url.startswith('#'):
                continue # ignore empty links or fragment identifiers (#)
            links.append({
                KEY_ACTUAL_URL: url,
                KEY_DISPLAY_TEXT: a.get_text()
            })
        return links