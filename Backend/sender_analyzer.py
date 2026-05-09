import re
from typing import Tuple
from constants import KNOWN_BRANDS, FREE_EMAIL_DOMAINS, SENDER_DOMAIN_PATTERN

class SenderAnalyzer:
    @staticmethod
    def extract_email_domain(sender: str) -> str:
        """
        Extracts the domain part from the sender email address
        Args:
            sender (str): The raw sender string from the email
        Returns:
            str: The extracted email domain, or an empty string if no valid email address was found
        """
        match = re.search(SENDER_DOMAIN_PATTERN, sender)
        return match.group(1) if match else ""
    
    @staticmethod
    async def analyze_sender(sender: str) -> Tuple[list[str], int, bool]:
        """
        Analyzes the email sender for suspicious brand impersonation signals
        Args:
            sender (str): The sender field from the email
        Returns:
            Tuple[list[str], int, bool]: A tuple of (reasons list, accumlated score, malicious flag)
        """
        reasons = []
        score = 0
        has_malicious = False
        sender_lower = sender.lower()
        domain = SenderAnalyzer.extract_email_domain(sender)
        print(f"[SENDER CHECK]:   Now checking sender")
        if not domain:
            return ["Could not parse sender email address"], 10, False
        for brand, allowed_domains in KNOWN_BRANDS.items():
            if brand in sender_lower and not any(domain.endswith(d) for d in allowed_domains):
                if domain in FREE_EMAIL_DOMAINS:
                    score += 40
                    reasons.append(f"Possible brand impersonation: sender mentions <b>{brand}</b>, "
                                   f"but uses free email domain <b>{domain}</b>.")
                else:
                    score += 35
                    reasons.append(f"Sender may be impersonating <b>{brand}</b>: actual sender domain is <b>{domain}</b>.")
        return reasons, min(score, 60), has_malicious