import os
import time

import httpx

key = os.environ.get("GEMINI_API_KEY", "")
model = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
think = os.environ.get("GEMINI_THINKING", "low")
print("key set:", bool(key), "| model:", model, "| thinking:", think)

body = {"contents": [{"role": "user", "parts": [{"text": 'Reply with JSON {"ok": true}'}]}],
        "generationConfig": {"responseMimeType": "application/json",
                             "thinkingConfig": {"thinkingLevel": think}}}
url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
for i in range(2):
    t = time.time()
    try:
        r = httpx.post(url, headers={"x-goog-api-key": key, "Content-Type": "application/json"}, json=body, timeout=60)
        print(f"try {i+1}: HTTP {r.status_code} in {time.time()-t:.1f}s\n", r.text.replace(key, "[KEY]")[:400])
    except Exception as e:
        print(f"try {i+1}: error after {time.time()-t:.1f}s:", type(e).__name__)