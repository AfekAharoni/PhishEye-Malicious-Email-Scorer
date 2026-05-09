from typing import Optional
import httpx
from constants import (
    SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL,
    REQUEST_TO_GOOGLE_API, SUCCESS_STATUS_CODE, TIMEOUT)
import copy
from typing import Set, Tuple

class URLAnalyzer:
    @staticmethod
    async def is_malicious_url_by_google(url: str) -> Optional[bool]:
        """
        Queries google safe browsing API
        Args:
            url (str): The url to be checked
        Returns:
            bool: True iff the url is malicious
        """
        request = copy.deepcopy(REQUEST_TO_GOOGLE_API)
        request["threatInfo"]["threatEntries"][0]["url"] = url
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(   
                    SAFE_BROWSING_URL,
                    params = {"key": SAFE_BROWSING_API_KEY},
                    json = request,
                    timeout = TIMEOUT)
                if response.status_code == SUCCESS_STATUS_CODE:
                    return "matches" in response.json()
            return None # if the status code is not 200
        except Exception:
            return None 
    
    @staticmethod
    async def analyze_urls(all_urls_to_check: Set[str], mismatched_urls: Set[str]) -> Tuple[list[str], int, bool]:
        """
        Scans a set of URLs against Google Safe Browsing and checks for deceptive links
        Args:
            all_urls_to_check: Unique URLs extracted from the email
            mismatched_urls: URLs where the display text and the atcual link are different
        Returns:
            A tuple of (reasons list, accumlated score, malicious flag)
        """
        reasons = []
        score = 0
        has_malicious = False
        for url in all_urls_to_check:
            print(f"[LINK CHECK]:   Now checking link {url}")
            result = await URLAnalyzer.is_malicious_url_by_google(url)
            if result is True:
                has_malicious = True
                score += 100
                if url in mismatched_urls:
                    reasons.append(f"Deceptive link detected, and the actual URL is dangerous: {url}")
                else:
                    reasons.append(f"Dangerous link detected: {url}")
            elif url in mismatched_urls:
                score += 15
                if result is False:
                    reasons.append(f"Deceptive link detected, but the actual URL appears safe: {url}")
                else:
                    reasons.append(f"Deceptive link detected, but the actual URL could not be fully verified: {url}")
            elif result is None:
                score += 15
                reasons.append(f"Could not verify the safety of: {url}")
        return reasons, score, has_malicious

