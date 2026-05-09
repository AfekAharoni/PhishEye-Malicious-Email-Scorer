from typing import Optional, Set, Tuple
import httpx
from constants import (
    SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL, DEBUG,
    REQUEST_TO_GOOGLE_API, SUCCESS_STATUS_CODE, TIMEOUT, SHORTENER_DOMAINS)
import copy
from urllib.parse import urlparse

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
    def normalize_url(url: str) -> str:
        """
        Ensures that a URL has an http/https scehema
        Args:
            url (str): The URL extracted from the email
        Returns:
            str: The url with a schema
        """
        if url.startswith("https://") or url.startswith("http://"):
            return url
        return "https://" + url
    
    @staticmethod
    async def get_final_url(url: str) -> str:
        """
        Resolves the final destination of a URL by following HTTP redirects
        Args:
            url (str): The original URL extracted from the email
        Returns:
            str: The final URL after following redirects.
        """
        normalized_url = URLAnalyzer.normalize_url(url)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(normalized_url, follow_redirects=True, timeout=TIMEOUT)
                return str(response.url)
        except Exception:
            return url
    
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
            if DEBUG:
                print(f"[LINK CHECK]:   Now checking link {url}")
            final_url = await URLAnalyzer.get_final_url(url)
            redirected = final_url != url
            if redirected:
                if DEBUG:
                    print(f"[LINK CHECK]: Redirects to {final_url}")
            result = await URLAnalyzer.is_malicious_url_by_google(final_url)
            if result is True:
                has_malicious = True
                score += 100
                if url in mismatched_urls:
                    reasons.append(f"Deceptive link detected, and the actual URL is dangerous: {final_url}")
                else:
                    label = f"(redirected from {url})" if redirected else ""
                    reasons.append(f"Dangerous link detected: {final_url} {label}".strip())
            elif url in mismatched_urls:
                if result is False:
                    reasons.append(f"Deceptive link detected, but the actual URL appears safe: {final_url}")
                else:
                    score += 15
                    reasons.append(f"Deceptive link detected, but the actual URL could not be fully verified: {final_url}")
            elif result is None:
                score += 15
                reasons.append(f"Could not verify the safety of: {final_url}")
            domain = urlparse(url).netloc.lower().removeprefix("www.")
            if domain in SHORTENER_DOMAINS and result is not True:
                score += 10
                reasons.append(f"URL shortener detected (resolved to: {final_url}): {url}")
        return reasons, score, has_malicious

