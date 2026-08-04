import os
from dotenv import load_dotenv
import google.genai as genai

load_dotenv()

def get_llm_explanation(user_message: str, score: float, reasons: list, category: str) -> str:
    try:
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in .env")

        client = genai.Client(api_key=api_key)

        reasons_text = "\n".join(f"- {r}" for r in reasons)
        category_clean = category.replace("_", " ").title()

        prompt = f"""You are a cybersecurity assistant helping Indian college students avoid online scams.

A student received this message:
"{user_message[:500]}"

Our fraud detection system flagged it with:
- Risk Score: {score:.0f}/100
- Category: {category_clean}
- Reasons detected:
{reasons_text}

Write a response in exactly 3 short paragraphs:
1. WHY this is likely a scam (what red flags are present)
2. WHAT the scammer is trying to do (their goal)
3. WHAT the student should do RIGHT NOW (be specific)

Keep it simple, direct, and in easy English.
Mention Indian context where relevant (rupees, cybercrime.gov.in, helpline 1930).
Do NOT use bullet points. Write in plain paragraphs."""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        return response.text

    except Exception as e:
        print(f"DEBUG ERROR: {e}")
        return None