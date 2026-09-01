from fastapi import FastAPI, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import json, os
from groq import Groq
from log_analysis_agent import analyze_logs

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client = Groq(api_key=os.environ["GROQ_API_KEY"])

def get_context(flagged_event, all_events, max_context=3):
    ip = flagged_event.get("source_ip")
    user = flagged_event.get("user")
    matches = [e for e in all_events if (e.get("source_ip") == ip or e.get("user") == user)]
    return matches[:max_context]

def investigate(flagged_events, all_events):
    flagged_events = flagged_events[:4]
    context = []
    seen = set()
    for ev in flagged_events:
        for c in get_context(ev, all_events):
            key = (c.get("timestamp"), c.get("source_ip"), c.get("user"), c.get("event_type"))
            if key not in seen:
                seen.add(key)
                context.append(c)

    instructions = "You are a threat investigation analyst. Given flagged events and related context events:\n"
    instructions += "1. Group events that likely belong to the same attack.\n"
    instructions += "2. Assign a risk level: Low, Medium, High, or Critical.\n"
    instructions += "3. Cite specific evidence (exact fields/values).\n"
    instructions += "4. Write a 2-3 sentence plain-English explanation.\n\n"
    instructions += "Flagged events:\n" + json.dumps(flagged_events) + "\n\n"
    instructions += "Context events:\n" + json.dumps(context) + "\n\n"
    instructions += 'Return ONLY valid JSON: {"incident_id": "string", "risk_level": "Low|Medium|High|Critical", "evidence": ["..."], "explanation": "..."}'

    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": instructions}]
    )
    text = response.choices[0].message.content.strip()
    text = text[text.find("{"):text.rfind("}")+1]
    return json.loads(text)

@app.post("/investigate")
async def investigate_endpoint(file: UploadFile):
    raw = await file.read()
    all_events = json.loads(raw)

    flagged_events = analyze_logs(all_events)
    if not flagged_events:
        return {"message": "No suspicious activity detected."}

    result = investigate(flagged_events, all_events)
    return result