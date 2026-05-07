import re
from urllib.parse import urlparse 
from bs4 import BeautifulSoup
from constants import (
    URL_PATTERN, HTML_PARSER, A_TAG,
      HREF_ATTR, KEY_DISPLAY_TEXT, KEY_ACTUAL_URL)

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
        soup = BeautifulSoup(html_content, "html.parser")
        hyperlinks = []
        for a in soup.findAll(A_TAG, href=True): # find all <a> tags
            hyperlinks.append({
                KEY_DISPLAY_TEXT: a.get_text().strip(),
                KEY_ACTUAL_URL: a[HREF_ATTR]
            })
        return hyperlinks