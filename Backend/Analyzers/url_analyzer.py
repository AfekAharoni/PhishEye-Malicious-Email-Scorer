from typing import Optional, Set, Tuple
import httpx
import asyncio
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
                response = await asyncio.wait_for(client.get(normalized_url, follow_redirects=True, 
                                                             timeout=3.0), timeout = 4.0)
                return str(response.url)
        except Exception:
            return url
    
    @staticmethod
    async def check_single_url(url: str, mismatched_urls: Set[str]) -> Tuple[list[str], int, bool]:
        """
        Helper function to perform a full check on a single URL
        Args:
            url (str): A single url
            mismtached_urls (Set[str]): Set of urls that their actual url diffe from their display texr
        Returns:
            A tuple of (reasons list, accumlated score, malicious flag)
        """
        if DEBUG:
            print(f"[LINK CHECK]:   Now checking link {url}")
        final_url = await URLAnalyzer.get_final_url(url)
        redirected = final_url != url
        result = await URLAnalyzer.is_malicious_url_by_google(final_url)
        url_reasons = []
        url_score = 0
        url_malicious = False
        if result is True:
            url_malicious = True
            url_score = 100
            if url in mismatched_urls:
                url_reasons.append(f"Deceptive link detected, and the actual URL is dangerous: {final_url}")
            else:
                label = f"(redirected from {url})" if redirected else ""
                url_reasons.append(f"Dangerous link detected: {final_url} {label}".strip())
        elif url in mismatched_urls:
            if result is False:
                url_reasons.append(f"Deceptive link detected, but the actual URL appears safe: {final_url}")
            else:
                url_score = 15
                url_reasons.append(f"Deceptive link detected, but the actual URL could not be fully verified: {final_url}")
        elif result is None:
            url_score = 15
            url_reasons.append(f"Could not verify the safety of: {final_url}")
        domain = urlparse(url).netloc.lower().removeprefix("www.")
        if domain in SHORTENER_DOMAINS and result is not True:
            url_score += 10
            url_reasons.append(f"URL shortener detected (resolved to: {final_url}): {url}")
        return url_reasons, url_score, url_malicious

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
        semaphore = asyncio.Semaphore(5) # maximum 5 concurrent checks
        async def limited_check(url):
            async with semaphore:
                return await URLAnalyzer.check_single_url(url, mismatched_urls)
        results = await asyncio.gather(*[limited_check(url) for url in all_urls_to_check])
        total_reasons, total_score, is_any_malicious = [], 0, False
        for r in results:
            if isinstance(r, Exception):
                continue 
            reasons, score, malicious = r
            total_reasons.extend(reasons)
            total_score += score
            if malicious:
                is_any_malicious = True
        return total_reasons, min(total_score, 100), is_any_malicious
        

