from typing import Optional
import httpx
from constants import (
    SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL,
    REQUEST_TO_GOOGLE_API, SUCCESS_STATUS_CODE, TIMEOUT)
import copy

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
