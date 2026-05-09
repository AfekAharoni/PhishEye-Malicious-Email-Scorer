from typing import Any
from fastapi import FastAPI, Request
from schemas import EmailData
from preprocessor import EmailPreprocessor
from url_analyzer import URLAnalyzer
from file_analyzer import FileAnalyzer
from sender_analyzer import SenderAnalyzer
from constants import (KEY_ACTUAL_URL, SAFE_STATUS,
                        MALICIOUS_STATUS, SUSPICIOUS_STATUS,
                        VIRUS_TOTAL_API_KEY, KEY_DISPLAY_TEXT)
from contextlib import asynccontextmanager
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


app = FastAPI(lifespan=lifespan)    

@app.post("/analyze")
async def analyze_email(data: EmailData, request: Request) -> dict[str, Any]:
    """
    Main endpoint that process the email data
    Uses asyncio.gather to run URL, file and sender checks concurrently
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
    url_task = URLAnalyzer.analyze_urls(all_urls_to_check, mismatched_urls)
    if data.attachments:
        file_task = request.app.state.file_analyzer.analyze_files(data.attachments)
    else:
        async def get_empty_result():
            return [], 0, False
        file_task = get_empty_result()
    sender_task = SenderAnalyzer.analyze_sender(data.sender)
    url_results, file_results, sender_results = await asyncio.gather(url_task, file_task, sender_task)
    url_reasons, url_score, url_malicious = url_results
    file_reasons, file_score, file_malicious = file_results
    sender_reasons, sender_score, sender_malicious = sender_results
    # Summary of reasons, malicious status and score
    total_reasons = url_reasons + file_reasons + sender_reasons
    has_malicious = url_malicious or file_malicious or sender_malicious
    final_score = min(url_score + file_score + sender_score, 100)
    if has_malicious:
        final_status = MALICIOUS_STATUS
        display_message = "Warning: this email contains malicious content."
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