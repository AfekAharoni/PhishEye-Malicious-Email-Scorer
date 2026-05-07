from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI();

class EmailData(BaseModel):
    subject: str 
    body: str
    sender: str 


@app.post("/analyze")
async def analyze_email(data: EmailData):
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)