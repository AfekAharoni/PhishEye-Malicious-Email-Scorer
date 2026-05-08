from typing import Optional
from fastapi import FastAPI, Request
from pydantic import BaseModel
from preprocessor import EmailPreprocessor
from url_analyzer import URLAnalyzer
from file_analyzer import FileAnalyzer
from constants import (KEY_ACTUAL_URL, SAFE_STATUS, MALICIOUS_STATUS,
                        SUSPICIOUS_STATUS, VIRUS_TOTAL_API_KEY)
from contextlib import asynccontextmanager
import base64
import uvicorn
import vt
import hashlib

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
    filename: str
    content: str 
    mimeType: str

class EmailData(BaseModel):
    subject: str 
    body: str
    sender: str 
    attachments: Optional[list[Attachment]] = []

app = FastAPI(lifespan=lifespan);

@app.post("/analyze")
async def analyze_email(data: EmailData, request: Request):
    reasons = [] 
    score = 0
    has_malicious = False
    # URL checker
    hyperlinks = EmailPreprocessor.extract_hyperlinks(data.body)
    raw_urls = EmailPreprocessor.extract_urls(data.body)
    all_urls_to_check = set()
    for link in hyperlinks:
        all_urls_to_check.add(link[KEY_ACTUAL_URL])
    for url in raw_urls:
        all_urls_to_check.add(url)
    for url in all_urls_to_check:
        print(f"[LINK Check]:    Now checking link {url}")
        result = URLAnalyzer.is_malicious_url_by_google(url)
        if result is True:
            has_malicious = True
            score += 100
            reasons.append(f"Dangerous link detected: {url}")
        elif result is None:
            score += 15
            reasons.append(f"Could not verify the safety of: {url}")
    if data.attachments:
        for att in data.attachments:
            print(f"[FILE CHECK]:   Now checking file {att.filename}")
            try:
                file_bytes = base64.b64decode(att.content)
                report = await request.app.state.file_analyzer.get_file_report_by_hash(file_bytes)
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
    # Sum up
    final_score = min(score, 100)
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
        "details": reasons
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)