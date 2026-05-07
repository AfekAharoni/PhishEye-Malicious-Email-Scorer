from typing import Optional
import requests
from constants import (
    SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL,
    REQUEST_TO_GOOGLE_API, SUCCESS_STATUS_CODE, TIMEOUT)
import copy

class URLAnalyzer:
    @staticmethod
    def is_malicious_url_by_google(url: str) -> Optional[bool]:
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
            response = requests.post(
                SAFE_BROWSING_URL,
                params = {"key": SAFE_BROWSING_API_KEY},
                json = request,
                timeout = TIMEOUT)
            if response.status_code == SUCCESS_STATUS_CODE:
                result = response.json()
                return "matches" in result
            return None # if the status code is not 200
        except (requests.exceptions.RequestException, Exception):
            return None 
