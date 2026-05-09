from typing import Tuple
from bs4 import BeautifulSoup
from constants import PHISHING_KEYWORDS, SENSITIVE_REQUESTS, HTML_PARSER, DEBUG

class ContentAnalyzer:
    @staticmethod
    def html_to_text(html_content: str) -> str:
        """
        Converts HTML email content into plain text
        Args:
            html_content (str): The raw HTML body of the email
        Returns:
            str: The visible text extracted from the HTML
        """
        return BeautifulSoup(html_content, HTML_PARSER).get_text(" ")

    @staticmethod
    async def analyze_content(subject: str, body: str) -> Tuple[list[str], int, bool]:
        """
        Analyzes the email subject and body for phishing-like language
        Args:
            subject (str): The email subject
            body (str): The email body, usually HTML
        Returns:
            A tuple of (reasons list, accumlated score, malicious flag)
        """
        reasons = []
        score = 0
        has_malicious = False
        if DEBUG:
            print(f"[CONTENT CHECK]:   Now checking content")
        text = f"{subject} {ContentAnalyzer.html_to_text(body)}".lower()
        found_keywords = [keyword for keyword in PHISHING_KEYWORDS if keyword in text]
        if found_keywords:
            score += min(10 + len(found_keywords) * 5, 35)
            reasons.append("Phishing-like wording detected: " + ", ".join(found_keywords[:5]) + ".")
        found_sensitive_requests = [request for request in SENSITIVE_REQUESTS if request in text]
        if found_sensitive_requests:
            score += 40
            reasons.append("Email appears to request sensitive information: " + ", ".join(found_sensitive_requests[:5]) + ".")
        return reasons, min(score, 70), has_malicious
        
