# utils/action_advisor.py
# ═════════════════════════════════════════════════════════════════
# Dynamic Action Advisor & Cybercrime Complaint Generator
# Maps scam categories to explicit mitigation roadmaps
# Auto-extracts target vectors to structure reporting payloads
# ═════════════════════════════════════════════════════════════════

import re
import datetime
from typing import Dict, Any, List

# ── Action Blueprints Configuration ──────────────────────────────
ACTIONS_CONFIG = {
    "internship_fee": {
        "steps": [
            "Do NOT transfer any money under the guise of registration, security, or data verification.",
            "Block the sender on WhatsApp, Telegram, or email immediately to terminate tracking.",
            "Take screenshots of the message, payment numbers, and any fraudulent cross-references.",
            "Report the occurrence on the official corporate platform being impersonated (e.g., Internshala Help desk).",
            "Alert your college placement cell or student WhatsApp group instantly with screenshots to prevent peer leakage."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "I received a fraudulent internship offer impersonating a recognized recruitment portal on {date}. "
            "The bad actor attempted to extract an unverified up-front fee under the pretext of 'Registration/Onboarding'.\n"
            "• Demanded Amount: {amount}\n"
            "• Fraudulent Contact Point: {contact}\n"
            "• Identified Shortlink/Domain: {url}\n"
            "• Verbatim Text Evidence: \"{preview}\"\n"
            "Please log this complaint under Cyber Job Fraud monitoring headers."
        )
    },
    "job_fee": {
        "steps": [
            "Stop any ongoing negotiation. Indian MNCs (TCS, Infosys, Wipro) NEVER charge onboarding fees.",
            "Do not supply scans of your Aadhaar card, PAN card, or university score sheets to unverified domains.",
            "Cross-verify the job ID directly on the company's official corporate portal careers branch.",
            "Log the transaction frames and report the banking identifiers directly on the cybercrime.gov.in portal."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in/Webform/Crime_DetailsPage.aspx",
        "template": (
            "I was targeted by a corporate employment scam on {date}. The perpetrator sent an unsolicited job offer "
            "claiming to represent an enterprise corporate body, and requested a document processing/verification fee.\n"
            "• Financial Demand: {amount}\n"
            "• Originating Endpoint: {contact}\n"
            "• Phishing link: {url}\n"
            "• Message Context: \"{preview}\"\n"
            "Requesting tracking of the associated payment routing networks."
        )
    },
    "scholarship_fee": {
        "steps": [
            "Remember: Real government systems (NSP, PM-Scholarship) NEVER require processing fees to dispatch awards.",
            "Do not supply your bank account passbook scans or net banking profiles to external contacts.",
            "Manually log in directly to scholarships.gov.in to confirm compliance status.",
            "File an official grievance stack with the institutional nodal officer of your university."
        ],
        "helpline": "1930",
        "online_url": "https://scholarships.gov.in",
        "template": (
            "An entity attempted to commit scholarship extraction fraud on my profile on {date}. "
            "They claimed that an authorized student welfare award was frozen pending an processing fee transfer.\n"
            "• Extortion Amount: {amount}\n"
            "• Direct Target Identifier: {contact}\n"
            "• Link payload: {url}\n"
            "• Raw Message Content: \"{preview}\"\n"
            "Filing for government portal impersonation audit."
        )
    },
    "otp_fraud": {
        "steps": [
            "Do NOT share or type the verification code under any circumstances.",
            "If code transfer occurred: Lock your banking cards instantly using your official bank mobile app.",
            "Call your banking emergency nodal desk immediately to freeze active payment paths.",
            "SBI: 1800-11-2211 | HDFC: 1800-202-6161 | ICICI: 1800-1080 | Axis: 1800-419-5959",
            "File a financial fraud tracking request on the national portal within the golden hour parameter."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "URGENT: Financial account takeover mapping logged on {date}. "
            "The malicious endpoint attempted to extract a dynamic high-value OTP token under bank service deactivation pretexts.\n"
            "• Apparent Targets: {amount}\n"
            "• Direct Communication Source: {contact}\n"
            "• Destination Vector Link: {url}\n"
            "• Input context text: \"{preview}\"\n"
            "Filing for tracking of immediate account injection parameters."
        )
    },
    "lottery_prize": {
        "steps": [
            "Dismiss the alert completely. Unsolicited lottery wins for contests you never registered for are fraudulent.",
            "Do not pay any hidden delivery fee, stamp duty, or clearance processing taxes.",
            "Block the group coordinate strings on WhatsApp or Telegram immediately.",
            "Do not pass over banking KYC profile details or location data links."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "Perpetrator attempted lottery extortion mechanics on my device on {date}. "
            "Sent an advance win framework claiming high-value currency award distribution under false lucky draw parameters.\n"
            "• Processing Tax Demanded: {amount}\n"
            "• Attacking Mobile Identifier: {contact}\n"
            "• Domain: {url}\n"
            "• Metadata content: \"{preview}\""
        )
    },
    "parttime_job": {
        "steps": [
            "Terminate task interaction. The 'Like YouTube videos/Review products' cycle is a structured deposit trap.",
            "Do not transfer cash to buy higher tier access plans or unlock frozen balance structures.",
            "Do not link your main banking accounts to unverified web app payout profiles.",
            "Report the coordinate tracking groups immediately to cyber cell authorities."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "I was pulled into a high-yield structured Task/Part-Time employment trap on {date}. "
            "Perpetrators used algorithmic social media tasks to build trust, then blocked withdrawal options until an escrow payment was processed.\n"
            "• Total Escrow Request: {amount}\n"
            "• Operating Number: {contact}\n"
            "• App Web link: {url}\n"
            "• Verbatim content: \"{preview}\""
        )
    },
    "bank_impersonation": {
        "steps": [
            "Ignore urgent deactivation warnings. Real banks will never block accounts over WhatsApp strings.",
            "Do not access banking links via SMS strings. Always type official URLs manually.",
            "Visit your localized physical brick-and-mortar branch manager to audit profile settings directly.",
            "Report suspicious phishing numbers to the financial service provider node."
        ],
        "helpline": "1930",
        "online_url": "https://www.rbi.org.in/commonman/English/Scripts/AgainstBank.aspx",
        "template": (
            "Perpetrators attempted financial institutional impersonation vector mapping on {date}. "
            "Sent high-panic warnings of profile freeze to force credentials extraction via insecure custom gateways.\n"
            "• Claimed Penalty: {amount}\n"
            "• Number: {contact}\n"
            "• Link: {url}\n"
            "• Phishing Text: \"{preview}\""
        )
    },
    "gov_scheme_fraud": {
        "steps": [
            "Note: Government schemes always deploy funds directly to Aadhaar-linked accounts (DBT) for free.",
            "Do not pay processing fees to independent welfare allocation channels.",
            "Verify all notifications directly at clean secure government domains ending strictly in `.gov.in`."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "Government scheme allocation forgery encountered on {date}. "
            "Perpetrators mapped false direct benefit structures to collect administrative setup payments up front.\n"
            "• Cost Claim: {amount}\n"
            "• Originating Contact: {contact}\n"
            "• Domain Link: {url}\n"
            "• Source Message: \"{preview}\""
        )
    },
    "suspicious": {
        "steps": [
            "Exercise strong caution. This communication matches multiple intermediate risk vectors.",
            "Do not download unverified attachments or open tracking shortlinks.",
            "Perform direct verification of the claim from official public directory configurations before proceeding.",
            "Consult a university authority or trust node before signing digital contracts."
        ],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "template": (
            "Logging suspicious text sequence interaction audit on {date}. "
            "Text contains anomaly clusters indicating potential social engineering patterns.\n"
            "• Financial Strings: {amount}\n"
            "• Target Vector Origin: {contact}\n"
            "• Payload URLs: {url}\n"
            "• Full context dump: \"{preview}\""
        )
    },
    "safe": {
        "steps": [
            "This communication matches structural clean verification parameters.",
            "Good practice check: Always access verified frameworks via clean browser tabs rather than relying solely on inbound message triggers.",
            "Confirm corporate credential mappings matches verified corporate profiles on official nodes."
        ],
        "helpline": "",
        "online_url": "",
        "template": ""
    }
}


def get_action(score: float, category: str, text: str) -> Dict[str, Any]:
    """
    Generate situational post-incident response mapping based on score metrics.
    """
    # Route category based on severity thresholds
    if score < 40.0:
        target_cat = "safe"
    elif score < 70.0:
        target_cat = "suspicious"
    else:
        target_cat = category if category in ACTIONS_CONFIG else "unknown_scam"
        if target_cat == "unknown_scam" and "otp" in text.lower():
            target_cat = "otp_fraud"

    blueprint = ACTIONS_CONFIG.get(target_cat, ACTIONS_CONFIG["suspicious"])
    
    # Process extractions for complaint formatting
    extracted_data = _extract_indicators(text)
    current_date = datetime.datetime.now().strftime("%d/%m/%Y")
    
    preview_limit = text.replace('\n', ' ')[:120] + ("..." if len(text) > 120 else "")
    
    complaint_text = ""
    if blueprint["template"]:
        complaint_text = blueprint["template"].format(
            date=current_date,
            amount=extracted_data["amount"],
            contact=extracted_data["contact"],
            url=extracted_data["url"],
            preview=preview_limit
        )

    return {
        "steps": blueprint["steps"],
        "helpline": blueprint["helpline"],
        "online_url": blueprint["online_url"],
        "complaint_text": complaint_text,
        "target_category": target_cat
    }


def _extract_indicators(text: str) -> Dict[str, str]:
    """
    Internal locator parsing dirty strings for structured reporting vectors.
    """
    # Currency extraction
    amount_match = re.search(r"(?:rs\.?|₹|inr)\s*([\d,]+)", text, re.IGNORECASE)
    if not amount_match:
        amount_match = re.search(r"([\d,]+)\s*(?:rs|rupees)", text, re.IGNORECASE)
    amount_str = amount_match.group(0).strip() if amount_match else "Not explicitly specified"

    # Contact point phone extraction
    phone_match = re.search(r"\b[6-9]\d{9}\b", text)
    contact_str = phone_match.group(0).strip() if phone_match else "Unknown sender number"

    # URL payload tracking location
    url_match = re.search(r"(https?://\S+|www\.\S+|bit\.ly/\S+)", text, re.IGNORECASE)
    url_str = url_match.group(0).strip() if url_match else "No link payload extracted"

    return {
        "amount": amount_str,
        "contact": contact_str,
        "url": url_str
    }


if __name__ == "__main__":
    # Test advisor output
    sample_scam = "Selected for Internshala position. Pay Rs.1500 registration fee immediately to 9876543210 visit bit.ly/scam"
    advice = get_action(92.0, "internship_fee", sample_scam)
    print("Action Steps:")
    for step in advice["steps"]:
        print(f" - {step}")
    print("\nPre-filled Complaint Payload:")
    print("="*60)
    print(advice["complaint_text"])