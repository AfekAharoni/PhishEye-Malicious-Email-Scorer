import re
from typing import Tuple
from constants import DEBUG, DKIM_TAG, SPF_TAG, DMARC_TAG, PASS_RESULT

class AuthenticationAnalyzer:
    @staticmethod
    def extract_auth_result(auth_results: str, mechanism: str) -> str:
        """
        Extracts the authentication resut for a specific mechanism
        Args:
            auth_results (str): The authentication result header
            mechanism (str): The mechanism to extract (DKIM, SPF, DMARC)
        Returns:
            str: The mechanism result, or an empty string if not found
        """
        pattern = rf"{mechanism}\s*[:=]?\s*([a-zA-Z]+)"
        match = re.search(pattern, auth_results.lower())
        return match.group(1) if match else ""

    @staticmethod
    async def analyze_authentication(auth_results: str) -> Tuple[list[str], int, bool]:
        """
        Analyzes DKIM, SPF and DMARC results from the authentication result header
        Args:
            auto_results (str): The authentication result hreader extracted from gmail
        Returns:
            Tuple[list[str], int, bool]: A tuple of (reasons list, accumlated score, malicious flag)
        """
        reasons = []
        score = 0
        has_malicious = False
        if DEBUG:
            print("[AUTH CHECK]:    Now checking email authentication")
        if not auth_results:
            score += 10
            reasons.append("Email authentication results were not available.")
            return reasons, score, has_malicious
        dkim_result = AuthenticationAnalyzer.extract_auth_result(auth_results, DKIM_TAG)
        spf_result = AuthenticationAnalyzer.extract_auth_result(auth_results, SPF_TAG)
        dmarc_result = AuthenticationAnalyzer.extract_auth_result(auth_results, DMARC_TAG)
        if dkim_result == PASS_RESULT:
            reasons.append("The email's digital signature was verified as authentic (DKIM pass).")
        elif dkim_result:
            score += 25
            reasons.append(f"Warning: The digital signature is invalid or tempered with ({dkim_result}).")
        else:
            score += 10
            reasons.append("No digital signature was found (DKIM missing).")
        if spf_result == PASS_RESULT:
            reasons.append("The sending server is officially authorized by the sender's domain (SPF pass).")
        elif spf_result:
            score += 25
            reasons.append(f"Warning: Unauthorized sending server detected ({spf_result}).")
        else:
            score += 10
            reasons.append("No authorized server list found (SPF missing).")
        if dmarc_result == PASS_RESULT:
            reasons.append("This email passed the domain's comprehensive security policy (DMARC pass).")
        elif dmarc_result:
            score += 25
            reasons.append(f"Warning: The email failed the domain's security check ({dmarc_result}).")
        else:
            score += 10
            reasons.append("No advanced security policty is defined for this domain (DMARC missing).")
        return reasons, min(score, 60), has_malicious