# PhishScope — AI-Powered Phishing & Scam Detector

A web app that analyzes URLs and messages for phishing/scam intent using a
**two-layer detection approach**: classic rule-based cybersecurity heuristics,
combined with AI reasoning (Google Gemini) — the same pattern used by real
SOC (Security Operations Center) triage tools.

## How it works

1. **User pastes** a URL, email body, or SMS text into the web app.
2. **Layer 1 — Rule-based heuristics** (`heuristics.py`): checks the URL against
   8 classic phishing indicators (no HTTPS, IP address instead of domain,
   `@` symbol tricks, excessive subdomains, URL shorteners, suspicious
   keywords, hyphenated lookalike domains, abnormal length) and produces a
   risk score.
3. **Layer 2 — AI reasoning** (`ai_analyzer.py`): sends the content — plus the
   heuristic flags as context — to Google's Gemini API, which reasons about
   *intent* the way a human analyst would, and returns a structured verdict
   (`SAFE` / `SUSPICIOUS` / `PHISHING`) with a confidence score and
   recommended action.
4. **Every scan is logged** to `scan_log.jsonl`, mimicking how a SOC keeps an
   audit trail of triaged alerts.

## Why two layers instead of just AI?

Rule-based checks are fast, free, explainable, and can't be "fooled" by a
weird AI response — they're a safety net. AI reasoning catches things
heuristics can't (e.g. a technically clean URL with a socially-engineered
urgent message). Combining both is exactly how modern security tools like
email gateways and browser phishing filters are designed.

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Get a free Gemini API key (no credit card required)
#    -> https://aistudio.google.com/apikey

# 3. Set up your API key
cp .env.example .env
# then open .env and paste your key

# 4. Run the app
python app.py

# 5. Open in browser
# http://127.0.0.1:5000
```

## Project structure

```
ai-phishing-detector/
├── app.py              # Flask routes, ties heuristics + AI together
├── heuristics.py        # Rule-based phishing checks (no API needed)
├── ai_analyzer.py       # Gemini API integration + prompt
├── templates/
│   └── index.html       # Web UI
├── static/
│   ├── style.css
│   └── script.js
├── requirements.txt
├── .env.example
└── scan_log.jsonl        # Auto-created — local scan history
```

## Resume bullet (example)

> Built an AI-augmented phishing detection web app (Flask + Gemini API)
> combining 8 rule-based URL heuristics with LLM-based intent analysis;
> outputs SOC-style verdicts with confidence scoring and maintains a
> local audit log of all scans.

## Talking points for interviews

- **Why heuristics + AI, not just one?** Explain the "defense in depth" /
  layered-detection reasoning above.
- **What specific phishing indicators did you check for, and why does each
  one matter?** Walk through 2–3 from `heuristics.py` (e.g. why `@` in a URL
  is dangerous — browsers ignore everything before it).
- **How would you extend this for production?** e.g. add a real-time
  threat-intel API (VirusTotal/PhishTank), rate limiting, user accounts,
  a dashboard of historical scans, Slack/email alerting.
- **What are the limitations?** AI can hallucinate or be wrong; heuristics
  can false-positive on legitimate long/complex URLs (e.g. tracking links);
  this is a decision-support tool, not a guaranteed blocker.

## Disclaimer

Educational project. Do not paste real credentials into any tool, including
this one. Do not use this to test against systems you don't own or have
permission to test.
