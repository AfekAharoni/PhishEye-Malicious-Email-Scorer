from fastapi import FastAPI
from pydantic import BaseModel
from preprocessor import EmailPreprocessor
from url_analyzer import URLAnalyzer
from constants import KEY_ACTUAL_URL, KEY_DISPLAY_TEXT

app = FastAPI();

class EmailData(BaseModel):
    subject: str 
    body: str
    sender: str 


@app.post("/analyze")
async def analyze_email(data: EmailData):
    hyperlinks = EmailPreprocessor.extract_hyperlinks(data.body)
    raw_urls = EmailPreprocessor.extract_urls(data.body)
    all_urls_to_check = set()
    for link in hyperlinks:
        all_urls_to_check.add(link[KEY_ACTUAL_URL])
    for url in raw_urls:
        all_urls_to_check.add(url)
    if not all_urls_to_check:
        return {"status": "safe",
                "score": 0,
                "message": "no links found in the email",
                "details": []
        }
    reasons = []
    has_malicious = False
    could_not_check_all = False 
    final_score = 0
    for url in all_urls_to_check:
        result = URLAnalyzer.is_malicious_url_by_google(url)
        if result is True:
            has_malicious = True 
            reasons.append(f"Dangerous link detected: {url}")
        elif result is None:
            could_not_check_all = True 
            reasons.append(f"Could not verify the safety of: {url}")
    if has_malicious:
        final_status = "Malicious"
        final_score = 100
        display_message = "Warning: this email contains malicious links"
    elif could_not_check_all:
        final_status = "Suspicious"
        final_status = 50
        display_message = "Caution: some links could not be verified at this time"
    else:
        final_status = "Safe"
        display_message = "All links in this email appear to be safe."
    return {
        "status": final_status,
        "score": final_score,
        "message": display_message,
        "details": reasons
    }
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)