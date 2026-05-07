import vt
import hashlib
from typing import Dict, Any
from constants import SUSPICIOUS_STATUS, MALICIOUS_STATUS


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
    
    async def close(self) -> None:
        """
        Closes the VirusTotal client sessions gracefully
        """
        await self.client.close_async()