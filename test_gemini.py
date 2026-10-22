import os
import httpx

key = os.environ.get("GEMINI_API_KEY", "")
model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
print("key set:", bool(key), "| starts with:", key[:3], "| length:", len(key), "| model:", model)

body = {"contents": [{"role": "user", "parts": [{"text": 'Reply with JSON {"ok": true}'}]}],
        "generationConfig": {"responseMimeType": "application/json"}}
urls = {
    "AI Studio": f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    "Vertex express": f"https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:generateContent",
}
for name, url in urls.items():
    try:
        r = httpx.post(url, headers={"x-goog-api-key": key, "Content-Type": "application/json"}, json=body, timeout=20)
        print(f"\n[{name}] HTTP {r.status_code}\n", r.text.replace(key, "[KEY]")[:400])
    except Exception as e:
        print(f"\n[{name}] error:", type(e).__name__, str(e).replace(key, "[KEY]")[:200])