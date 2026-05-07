from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel
from preprocessor import EmailPreprocessor
from url_analyzer import URLAnalyzer
from file_analyzer import FileAnalyzer
from constants import (KEY_ACTUAL_URL, SAFE_STATUS, MALICIOUS_STATUS,
                        SUSPICIOUS_STATUS, VIRUS_TOTAL_API_KEY)
import base64
import uvicorn

app = FastAPI();
file_analyzer = FileAnalyzer(VIRUS_TOTAL_API_KEY)

class Attachment(BaseModel):
    filename: str
    content: str 
    mimeType: str

class EmailData(BaseModel):
    subject: str 
    body: str
    sender: str 
    attachments: Optional[list[Attachment]] = []


@app.post("/analyze")
async def analyze_email(data: EmailData):
    reasons = []
    has_malicious = False
    could_not_check_all = False 

    # URL checker
    hyperlinks = EmailPreprocessor.extract_hyperlinks(data.body)
    raw_urls = EmailPreprocessor.extract_urls(data.body)
    all_urls_to_check = set()
    for link in hyperlinks:
        all_urls_to_check.add(link[KEY_ACTUAL_URL])
    for url in raw_urls:
        all_urls_to_check.add(url)
    for url in all_urls_to_check:
        result = URLAnalyzer.is_malicious_url_by_google(url)
        if result is True:
            has_malicious = True
            reasons.append(f"Dangerous link detected: {url}")
        elif result is None:
            could_not_check_all = True
            reasons.append(f"Could not verify the safety of: {url}")
    
    # Attachment checker
    if data.attachments:
        for att in data.attachments:
            try:
                file_bytes = base64.b64decode(att.content)
                report = await file_analyzer.get_file_report_by_hash(file_bytes)
                if report.get("status") == "found":
                    if report[MALICIOUS_STATUS] > 0:
                        has_malicious = True
                        reasons.append(f"Malicious file detected: {att.filename}")
                elif report[SUSPICIOUS_STATUS] > 0:
                    could_not_check_all = True
                    reasons.append(f"Suspicious file detected: {att.filename}")
                else:
                    reasons.append(f"File {att.filename} is unknown to VirusTotal")
            except Exception as e:
                could_not_check_all = True
                reasons.append(f"Error analyzing file {att.filename}")
    
    # Sum up
    if has_malicious:
        final_status = MALICIOUS_STATUS
        final_score = 100
        display_message = "Warning: this email contains malicious content (links or files)."
    elif could_not_check_all:
        final_status = SUSPICIOUS_STATUS
        final_score = 50
        display_message = "Caution: some elements could not be fully verified."
    else:
        final_status = SAFE_STATUS
        final_score = 0
        display_message = "All elements in this email appear to be safe."
    return {
        "status": final_status,
        "score": final_score,
        "message": display_message,
        "details": reasons
    }

@app.on_event("shutdown")
async def shutdown_event():
    await file_analyzer.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)