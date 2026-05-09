import base64
import vt
import hashlib
from typing import Dict, Any, Tuple
from constants import SAFE_EXTENSIONS, SUSPICIOUS_STATUS, MALICIOUS_STATUS, DEBUG
from schemas import Attachment

class FileAnalyzer:
    def __init__(self, api_key: str):
        """
        Initializes the VirusTotal client
        Args:
            api_key (str): VirusTotal API key
        """
        self.api_key = api_key
        self.client = None
    
    def set_client(self, client: vt.Client):
        """
        Sets the VirusTotal client as data member
        """
        self.client = client
    
    async def get_file_report_by_hash(self, file_content: bytes) -> Dict[str, Any]:
        """
        Calculates the SHA256 hash of a file and retrieves it reports from VirusTotal
        Args:
            file_content (bytes): The raw binary content of the file
        Returns:
            Dict[str, Any]: A dictionary containing the analysis results
        """
        if self.client is None:
            return {"status": "error", "message": "Client not ready"}
        file_hash = hashlib.sha256(file_content).hexdigest()
        try:
            file_obj = await self.client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            return {
                "status": "found",
                MALICIOUS_STATUS: stats.get('malicious', 0),
                SUSPICIOUS_STATUS: stats.get('suspicious', 0),
                "total_engines": sum(stats.values()),
                "last_analysis_data": file_obj.last_analysis_date
                }
        except vt.APIError as e:
            if e.code == "NotFoundError":
                return {
                    "status": "not_found",
                    "message": "File hash not found in VirusTotal database"
                }
            raise e
    
    async def analyze_files(self, attachments: list[Attachment]) -> Tuple[list[str], int, bool]:
        """
        Scans email attachments using VirusTotal by checking their file hashes
        Args:
            attachments: List of attachment objects
        Returns:
            A tuple of (reasons list, accumlated score, malicious flag)
        """
        reasons = []
        score = 0
        has_malicious = False
        for att in attachments:
                if DEBUG:
                    print(f"[FILE CHECK]:   Now checking file {att.filename}")
                extension = att.filename.rsplit(".", 1)[-1].lower()
                if extension in SAFE_EXTENSIONS:
                    continue
                try:
                    file_bytes = base64.b64decode(att.content)
                    report = await self.get_file_report_by_hash(file_bytes)
                    if report.get("status") == "found":
                        if report.get(MALICIOUS_STATUS, 0) > 0:
                            has_malicious = True
                            score += 100
                            reasons.append(f"Malicious file detected: {att.filename}")
                        elif report.get(SUSPICIOUS_STATUS, 0) > 0:
                            score += 60
                            reasons.append(f"Suspicious file detected: {att.filename}")
                        else:
                            reasons.append(f'File "{att.filename}" was checked and is clean')
                    elif report.get("status") == "not_found":
                        score += 20
                        reasons.append(f"File {att.filename} is unknown to VirusTotal")
                    elif report.get("status") == "error":
                        score += 20
                        reasons.append(f"System error: {report.get('message')}")
                except Exception as e:
                    score += 20
                    reasons.append(f"Error analyzing file {att.filename}")
        return reasons, score, has_malicious

    async def close(self) -> None:
        """
        Closes the VirusTotal client sessions gracefully
        """
        await self.client.close_async()