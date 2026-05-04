# core/api_check.py
import requests
import base64
import json
import streamlit as st
from config import GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_KEY
from core.preprocessor import extract_urls


def check_google_safe_browsing(urls: list[str]) -> tuple[int, list[str]]:
    """
    Checks URLs against Google Safe Browsing API.
    Returns (score, reasons)
    Free API: https://developers.google.com/safe-browsing
    """
    if not GOOGLE_SAFE_BROWSING_KEY or not urls:
        return 0, []

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_SAFE_BROWSING_KEY}"
    )

    payload = {
        "client":    {"clientId": "campus-fraud-shield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": u} for u in urls],
        },
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        data = resp.json()

        if "matches" in data and data["matches"]:
            reasons = []
            for match in data["matches"]:
                threat = match.get("threatType", "THREAT")
                url    = match.get("threat", {}).get("url", "")
                reasons.append(f"🌐 Google Safe Browsing: {threat} detected in {url}")
            return 90, reasons

        return 0, []

    except requests.exceptions.Timeout:
        return 0, []
    except Exception:
        return 0, []


def check_virustotal(url: str) -> tuple[int, list[str]]:
    """
    Checks a single URL against VirusTotal.
    Free tier: 4 requests/minute
    Free API: https://www.virustotal.com/gui/join-us
    """
    if not VIRUSTOTAL_KEY or not url:
        return 0, []

    try:
        # Encode URL to base64 (VirusTotal requirement)
        url_id   = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers  = {"x-apikey": VIRUSTOTAL_KEY}

        resp = requests.get(endpoint, headers=headers, timeout=8)

        if resp.status_code == 404:
            # URL not in database — submit it
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=8,
            )
            return 0, ["🔍 VirusTotal: URL submitted for analysis (not in DB yet)"]

        if resp.status_code != 200:
            return 0, []

        data    = resp.json()
        stats   = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total   = sum(stats.values()) or 1

        if malicious > 0:
            score   = min(int((malicious / total) * 100) + 50, 100)
            reasons = [f"🦠 VirusTotal: {malicious} engine(s) flagged this URL as malicious"]
            return score, reasons
        elif suspicious > 0:
            score   = min(int((suspicious / total) * 100) + 30, 70)
            reasons = [f"⚠️ VirusTotal: {suspicious} engine(s) flagged as suspicious"]
            return score, reasons

        return 0, ["✅ VirusTotal: URL appears clean"]

    except requests.exceptions.Timeout:
        return 0, []
    except Exception:
        return 0, []


def run_api_checks(text: str) -> tuple[int, list[str]]:
    """
    Master function: runs all available API checks.
    Gracefully handles no internet / missing keys.
    """
    urls = extract_urls(text)
    if not urls:
        return 0, []

    total_score = 0
    all_reasons = []

    # Google Safe Browsing check
    gsb_score, gsb_reasons = check_google_safe_browsing(urls)
    total_score += gsb_score
    all_reasons.extend(gsb_reasons)

    # VirusTotal check (first URL only to respect free tier)
    if urls:
        vt_score, vt_reasons = check_virustotal(urls[0])
        total_score += vt_score
        all_reasons.extend(vt_reasons)

    return min(total_score, 100), all_reasons