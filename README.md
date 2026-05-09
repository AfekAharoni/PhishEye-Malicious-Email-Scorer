<div align="center">
# PhishEye: Malicious Email Scorer

![PhishEye Logo](assets/New/circled-logo.png)

## Overview
**PhishEye** is a Gmail Add-on designed to enhance user security by analyzing incoming emails for potential threats. Developed as a home assignment for the **Upwind Security Bootcamp**, PhishEye provides a maliciousness score, a clear verdict (Safe, Suspicious, or Malicious), and detailed reasoning to help users make informed decisions about their inbox.

---

## The Assignment
This project was developed in response to the Upwind Bootcamp Home Assignment.

---

## Core Security Features
PhishEye evaluates email integrity through several key vectors:

* **Authentication Protocols:**
    * **SPF (Sender Policy Framework):** Validates that the sending mail server is authorized to send mail on behalf of the domain.
    * **DKIM (DomainKeys Identified Mail):** Uses a cryptographic signature to verify that the email content hasn't been tampered with.
    * **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Ensures the email aligns with SPF and DKIM policies, providing a final verdict on sender authenticity.
* **Link Analysis:** Extracts and scans URLs within the email body for phishing patterns.
* **Attachment Inspection:** Analyzes file metadata and extensions to identify potentially harmful payloads.

---

## Technical Decisions & Trade-offs

### 1. Link Scanning Strategy: Security over Convenience
* **The Choice:** If a link check fails due to a Google API error or technical issue, the system reports the status as **"Unknown/Warning"** rather than marking it as safe.
* **Reasoning:** A "False Negative" (marking a malicious link as safe) is significantly more dangerous than a "False Positive" or an "Unknown" status. I prioritize user safety by refusing to vouch for links I cannot verify.


### 2. Runtime Optimization: Extension Whitelisting
* **The Choice:** The scanner skips deep analysis for specific "inherently safe" file extensions based on AI lists.
* **Reasoning:** This improves performance and reduces backend latency. By not wasting resources on low-risk files (like basic text or standard images), I focus compute power on high-risk executable or script-based attachments.

### 3. High-Performance Concurrency
* **The Choice:** Implemented `asyncio` combined with **Semaphores** for backend processing.
* **Reasoning:** Scanning multiple links and attachments sequentially is too slow for a real-time UI. Using `asyncio` allows for parallelized API calls, while Semaphores ensure we stay within rate limits and manage server resources effectively.

### 4. Link De-duplication
* **The Choice:** Utilized a `Set` data structure to store and process unique links.
* **Reasoning:** Emails often contain redundant links (e.g., the same social media icon links). Using a set avoids duplicate API requests and unnecessary processing, further optimizing runtime.

### 5. Context Switching: Task Persistence vs. Resource Saving
* **The Scenario:** When a user triggers a scan but quickly switches to a different email.
* **The Choice:** **Cache results for 30 minutes.**
* **Reasoning:** While stopping the calculation might save immediate server time, caching provides a vastly superior User Experience. If a user toggles back to the previous email, the score is delivered instantly. This prevents redundant, expensive security scans and handles non-linear user behavior gracefully.

---

## Future Work & Limitations
* **Language Support:** Currently, PhishEye is optimized for **English** content only. 

---

## Getting Started
### Prerequisites
* Google Workspace account
* Python 3.9+ (for backend)
* ngrok: Required to tunnel the local backend to the Google Apps Script environment.

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/AfekAharoni/PhishEye-Malicious-Email-Scorer](https://github.com/AfekAharoni/PhishEye-Malicious-Email-Scorer)
2. **Backend Setup:**
   * Open the backend project in VS Code.
   * Install the necessary dependencies.
   * Run the backend server.
   * Ensure the server is listening on **port 8000**.

3. **Expose the Local Server (ngrok):**
   * Since the Gmail Add-on requires a public HTTPS endpoint, use **ngrok** to tunnel your local port 8000:
     ```bash
     ngrok http 8000
     ```
   * Copy the `https` forwarding URL provided by ngrok.
  
</div>

4. **Deploy the Add-on:**
   * Push the frontend code to Google Apps Script using the web editor.
   * Update the script properties with your ngrok URL so the Add-on can communicate with your local backend service.
   * Ensure you are logged into the same Gmail account intended for the live demonstration.
