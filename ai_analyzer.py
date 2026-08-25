"""
ai_analyzer.py
--------------
This is the "AI" layer. Instead of training our own ML model, we send
the suspicious text/URL to Google's Gemini API (free tier) and ask it
to reason about phishing intent the way a human security analyst would.

We combine this with heuristics.py -> that's rule-based, this is AI-based.
Together they make the tool's verdict much stronger than either alone.
"""

import os
import json
import requests

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)

PROMPT_TEMPLATE = """You are a cybersecurity analyst specializing in phishing and social engineering detection.

Analyze the following text/URL and determine if it shows signs of being a phishing attempt, scam, or malicious message.

CONTENT TO ANALYZE:
\"\"\"
{content}
\"\"\"

Known rule-based red flags already detected for context (may be empty):
{heuristic_flags}

Respond ONLY with valid JSON in exactly this format, no markdown, no extra text:
{{
  "verdict": "PHISHING" or "SUSPICIOUS" or "SAFE",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentence plain-English explanation a SOC analyst would write in a ticket>",
  "recommended_action": "<one short actionable recommendation>"
}}
"""


def get_api_key() -> str:
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError(
            "GEMINI_API_KEY not set. Add it to your .env file. "
            "Get a free key at https://aistudio.google.com/apikey"
        )
    return key


def analyze_with_ai(content: str, heuristic_flags=None) -> dict:
    """
    Sends content to Gemini and returns a structured verdict.
    Falls back to a safe error object if the API call fails,
    so the web app never crashes on the user.
    """
    api_key = get_api_key()
    flags_text = "\n".join(f"- {f}" for f in (heuristic_flags or [])) or "None detected"

    prompt = PROMPT_TEMPLATE.format(content=content, heuristic_flags=flags_text)

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2}
    }

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={api_key}",
            json=payload,
            timeout=20
        )
        response.raise_for_status()
        data = response.json()

        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
        # Strip markdown code fences if Gemini adds them anyway
        cleaned = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

        result = json.loads(cleaned)
        return result

    except Exception as e:
        return {
            "verdict": "ERROR",
            "confidence": 0,
            "reasoning": f"AI analysis failed: {str(e)}",
            "recommended_action": "Check your API key and internet connection."
        }
