"""
app.py
------
Main Flask web application.
Combines rule-based heuristics + AI reasoning into one phishing verdict.

Run with: python app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from datetime import datetime
import json
import os

from heuristics import analyze_text
from ai_analyzer import analyze_with_ai

load_dotenv()

app = Flask(__name__)

LOG_FILE = "scan_log.jsonl"


def save_to_log(entry: dict):
    """Append every scan to a local log file - mimics how a SOC keeps records."""
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    content = request.form.get("content", "").strip()

    if not content:
        return jsonify({"error": "Please paste a URL or message to analyze."}), 400

    # Step 1: Rule-based heuristics (fast, no API needed)
    heuristic_result = analyze_text(content)

    all_flags = []
    for r in heuristic_result["results"]:
        all_flags.extend(r["flags"])

    # If no URL found, still let AI analyze the raw text (e.g. email body)
    max_heuristic_score = max(
        [r["heuristic_score"] for r in heuristic_result["results"]], default=0
    )

    # Step 2: AI reasoning layer
    ai_result = analyze_with_ai(content, heuristic_flags=all_flags)

    response = {
        "input": content,
        "heuristics": heuristic_result,
        "max_heuristic_score": max_heuristic_score,
        "ai": ai_result
    }

    save_to_log(response)

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
