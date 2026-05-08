from typing import Optional, Set, Tuple, Any
from fastapi import FastAPI, Request
from pydantic import BaseModel
from preprocessor import EmailPreprocessor
from url_analyzer import URLAnalyzer
from file_analyzer import FileAnalyzer
from constants import (KEY_ACTUAL_URL, SAFE_STATUS,
                        MALICIOUS_STATUS, SUSPICIOUS_STATUS,
                        VIRUS_TOTAL_API_KEY, KEY_DISPLAY_TEXT, 
                        SAFE_EXTENSIONS)
from contextlib import asynccontextmanager
import base64
import uvicorn
import vt
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Sets the client of the VirusTotal only when the server is up
    """
    async with vt.Client(VIRUS_TOTAL_API_KEY) as client:
        analyzer = FileAnalyzer(VIRUS_TOTAL_API_KEY)
        analyzer.set_client(client)
        app.state.file_analyzer = analyzer
        yield

class Attachment(BaseModel):
    """
    Schema for email attachments
    """
    filename: str
    content: str 
    mimeType: str

class EmailData(BaseModel):
    """
    Schema for incoming email analysis requests
    """
    subject: str 
    body: str
    sender: str 
    attachments: Optional[list[Attachment]] = []

app = FastAPI(lifespan=lifespan)

async def check_urls(all_urls_to_check: Set[str], mismatched_urls: Set[str]) -> Tuple[list[str], int, bool]:
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
            reasons.append(f"Dangerous link detected: {url}")
        elif result is None and url in mismatched_urls:
            score += 40
            reasons.append(f"Deceptive link pointing to unverified URL: {url}")
        elif result is None:
            score += 15
            reasons.append(f"Could not verify the safety of: {url}")
    return reasons, score, has_malicious

async def check_files(attachments: list[Attachment], file_analyzer: FileAnalyzer) -> Tuple[list[str], int, bool]:
    """
    Scans email attachments using VirusTotal by checking their file hashes
    Args:
        attachments: List of attachment objects
        file_analyzer: The initialized FileAnalyzer instance
    Returns:
        A tuple of (reasons list, accumlated score, malicious flag)
    """
    reasons = []
    score = 0
    has_malicious = False
    for att in attachments:
            print(f"[FILE CHECK]:   Now checking file {att.filename}")
            extension = att.filename.rsplit(".", 1)[-1].lower()
            if extension in SAFE_EXTENSIONS:
                continue
            try:
                file_bytes = base64.b64decode(att.content)
                report = await file_analyzer.get_file_report_by_hash(file_bytes)
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
    

@app.post("/analyze")
async def analyze_email(data: EmailData, request: Request) -> dict[str, Any]:
    """
    Main endpoint that process the email data
    Uses asyncio.gather to run URL and File checks concurrently
    """
    all_urls_to_check = set()
    mismatched_urls = set()
    # Preprocess hyperlinks for mismatches
    hyperlinks = EmailPreprocessor.extract_hyperlinks(data.body)
    for link in hyperlinks:
        display_text = link.get(KEY_DISPLAY_TEXT, "")
        actual_url = link[KEY_ACTUAL_URL]
        all_urls_to_check.add(actual_url)
        # Check for deceptive/mismtached link 
        if display_text and (display_text.startswith("http") or display_text.startswith("www")):
            if not actual_url.startswith(display_text) and not display_text.startswith(actual_url):
                mismatched_urls.add(actual_url)
    # Add raw URLs from content
    raw_urls = EmailPreprocessor.extract_urls(data.body)
    for url in raw_urls:
        all_urls_to_check.add(url)
    url_task = check_urls(all_urls_to_check, mismatched_urls)
    if data.attachments:
        file_task = check_files(data.attachments, request.app.state.file_analyzer)
    else:
        async def get_empty_result():
            return [], 0, False
        file_task = get_empty_result()
    url_results, file_results = await asyncio.gather(url_task, file_task)
    url_reasons, url_score, url_malicious = url_results
    file_reasons, file_score, file_malicious = file_results
    # Summary of reasons, malicious status and score
    total_reasons = url_reasons + file_reasons
    has_malicious = url_malicious or file_malicious
    final_score = min(url_score + file_score, 100)
    if has_malicious:
        final_status = MALICIOUS_STATUS
        display_message = "Warning: this email contains malicious content (links or files)."
    elif final_score > 0:
        final_status = SUSPICIOUS_STATUS
        display_message = "Caution: some elements could not be fully verified."
    else:
        final_status = SAFE_STATUS
        display_message = "All elements in this email appear to be safe."
    return {
        "status": final_status,
        "score": final_score,
        "message": display_message,
        "details": total_reasons
    }


if __name__ == "__main__":
    # Run the server on port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)