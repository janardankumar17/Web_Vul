# ai_integration.py
import google.generativeai as genai
import os
import time
import random
import re
import logging
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.ERROR)
api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if not api_key:
    logging.error("GEMINI_API_KEY environment variable not set.")
else:
    genai.configure(api_key=api_key)

def _retry_seconds(exc):
    s = str(exc)
    m = re.search(r"retryDelay['\"]?\s*[:=]\s*['\"]?(\d+\.?\d*)s", s) or \
        re.search(r"\"retryDelay\"\s*:\s*\"(\d+\.?\d*)s\"", s)
    return float(m.group(1)) if m else None

def _call_model(model_name: str, prompt: str):
    model_obj = genai.GenerativeModel(model_name)
    resp = model_obj.generate_content(prompt)
    return getattr(resp, "text", None) or getattr(resp, "message", None) or str(resp)

def generate_with_retries(model: str, prompt: str,
                          attempts: int = 3,
                          base: float = 0.5,
                          max_back: float = 4.0,
                          fallback: str | None = None):

    last_exc = None
    current_model = model

    for i in range(1, attempts + 1):
        try:
            return _call_model(current_model, prompt).strip()
        except Exception as e:
            last_exc = e
            s = str(e).lower()

            # Leaked or invalid API key
            if "reported as leaked" in s or "api_key_invalid" in s or "api key not valid" in s:
                return "AI analysis unavailable: The Gemini API key in backend/.env is invalid or has been revoked (reported as leaked). Please set a valid GEMINI_API_KEY in backend/.env."

            # Quota / rate limit
            if "resource_exhausted" in s or "429" in s or "quota" in s:
                retry = _retry_seconds(e)
                if retry and retry > 20 and fallback and fallback != current_model:
                    try:
                        return _call_model(fallback, prompt).strip()
                    except Exception:
                        return f"AI unavailable due to quota; retry in {int(retry)}s."
                if retry and retry > 30:
                    return f"AI unavailable due to quota; retry in {int(retry)}s."

                back = min(max_back, base * (2 ** (i - 1)))
                sleep = min(back, retry) if retry else random.uniform(0, back)
                time.sleep(sleep)

                if i >= attempts - 1 and fallback and fallback != current_model:
                    current_model = fallback

                continue

            # transient 5xx
            if any(x in s for x in ("503", "502", "504", "unavailable", "overloaded", "timeout")):
                back = min(max_back, base * (2 ** (i - 1)))
                time.sleep(random.uniform(0, back))
                continue

            return f"AI analysis failed: {e}"

    return f"AI analysis failed after {attempts} attempts: {last_exc}"

def get_ai_analysis(vulnerabilities):
    if not api_key:
        return "AI analysis unavailable: Gemini API key not configured."
    if not vulnerabilities:
        return "No vulnerabilities found. The website appears secure."

       # --- replace the previous prompt with this block ---
    prompt = (
        "You are a cybersecurity auditor. Analyze the vulnerabilities below and return the output "
        "in the EXACT FORMAT shown (strict). Use emojis + UPPERCASE labels so the subtopics are highlighted\n\n"
        "### Vulnerability 1: <TITLE>\n"
        "🔸 RISK: <short>\n"
        "🔸 SUMMARY: <1-2 short lines>\n"
        "🔸 RECOMMENDATIONS:\n"
        "- <short bullet>\n"
        "- <short bullet>\n\n"
        "### Vulnerability 2: <TITLE>\n"
        "🔸 RISK: <short>\n"
        "🔸 SUMMARY: <1-2 short lines>\n"
        "🔸 RECOMMENDATIONS:\n"
        "- <short bullet>\n"
        "- <short bullet>\n\n"
        "KEEP ALL LABELS EXACTLY AS SHOWN (use the emoji + UPPERCASE label). "
        "DO NOT add extra text, headings, or explanations. Keep content concise.\n\n"
        "Vulnerabilities:\n"
    )



    for v in vulnerabilities:
        prompt += f"- {v.get('type','Unknown')}: {v.get('description','')} (Risk: {v.get('risk','Unknown')})\n"

    primary_model = "models/gemini-3.6-flash"
    fallback_model = "models/gemini-3.8-flash"

    return generate_with_retries(primary_model, prompt, attempts=3, base=0.5, max_back=4.0, fallback=fallback_model)

def get_barcode_ai_analysis(barcode_data):
    if not api_key:
        return "AI analysis unavailable: Gemini API key not configured."

    prompt = (
        "You are an expert digital forensics and cybersecurity auditor specializing in barcode and QR code inspection.\n"
        "Analyze the following decoded barcode/QR payload and return an audit with EXACTLY the following structure:\n\n"
        "### Purpose & Destination\n"
        "🔸 PURPOSE: Describe clearly what this code is for (e.g. payment request, website link, Wi-Fi access, contact card, product GTIN, form autofill).\n"
        "🔸 DESTINATION: Identify where it directs the user or who receives the data.\n\n"
        "### Security & Quishing Assessment\n"
        "🔸 VERDICT: Safe, Caution, Suspicious, or Malicious with brief rationale.\n"
        "🔸 THREAT CHECKS: Check for QR phishing (quishing), obscured shortlinks, fake merchant VPAs, or unexpected parameters.\n\n"
        "### Expiry & Validity\n"
        "🔸 LIFESPAN: Note whether the code contains session tokens, timestamps, or static long-term data.\n\n"
        "### Recommended Action\n"
        "- Clear step for the user before interacting with this code.\n\n"
        f"Format: {barcode_data.get('format', 'Unknown')}\n"
        f"Category: {barcode_data.get('category', 'Unknown')} ({barcode_data.get('sub_type', '')})\n"
        f"Payload: {barcode_data.get('raw_content', '')}\n"
    )

    product_info = barcode_data.get("product_info") or {}
    if product_info.get("found"):
        prompt += (
            f"\nDetected Product: {product_info.get('product_name', 'Unknown')}\n"
            f"Brand: {product_info.get('brand', 'Unknown')}\n"
            f"Origin Country: {product_info.get('origin_country', 'Unknown')}\n"
            f"Category: {product_info.get('category', 'Unknown')}\n"
        )

    primary_model = "models/gemini-3.6-flash"
    fallback_model = "models/gemini-3.8-flash"

    return generate_with_retries(primary_model, prompt, attempts=3, base=0.5, max_back=4.0, fallback=fallback_model)

