from pydantic import BaseModel
from typing import Optional

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