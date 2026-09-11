import re
from urllib.parse import urlsplit, parse_qs
from datetime import datetime, timezone
import os
import io
import json
from dotenv import load_dotenv
import zxingcpp
from PIL import Image
import google.generativeai as genai
from product_lookup import lookup_product_by_barcode

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

def decode_barcode_from_image(image_bytes: bytes) -> dict | None:
    """
    Decodes barcode or QR code from raw image bytes.
    Uses ultra-fast C++ zxingcpp first; falls back to Gemini Vision for blurry,
    tilted, or damaged barcodes.
    """
    if not image_bytes:
        return None

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception:
        return None

    # Pass 1: zxingcpp engine
    try:
        results = zxingcpp.read_barcodes(img, try_rotate=True, try_downscale=True, try_invert=True)
        if results:
            return {
                "code": results[0].text.strip(),
                "format": str(results[0].format).split(".")[-1],
                "engine": "zxing-cpp"
            }
    except Exception:
        pass

    # Pass 2: Gemini Vision fallback
    if api_key:
        try:
            model = genai.GenerativeModel("models/gemini-3.6-flash")
            prompt = (
                "Examine this image carefully. If there is a barcode, QR code, or product barcode "
                "digits (such as EAN-13, UPC, Code 128, etc.), identify the exact numbers or text.\n"
                "Return valid JSON ONLY:\n"
                '{"found": true, "code": "exact characters or digits", "format": "EAN-13 or QR_CODE or UPC"}\n'
                'If no barcode or code is present, return: {"found": false}'
            )
            resp = model.generate_content([img, prompt])
            txt = (resp.text or "").strip()
            if "{" in txt:
                clean = txt[txt.find("{"):txt.rfind("}") + 1]
                data = json.loads(clean)
                if data.get("found") and data.get("code"):
                    return {
                        "code": str(data["code"]).strip(),
                        "format": data.get("format", "EAN-13"),
                        "engine": "Gemini-Vision"
                    }
        except Exception:
            pass

    return None

def analyze_barcode_payload(content: str, barcode_format: str = "UNKNOWN"):
    """
    Parses and categorizes a barcode/QR code payload.
    Identifies purpose (Payment, URL, Wi-Fi, vCard, Product, Form, Plain Text)
    and evaluates embedded expiry timestamps or parameters.
    """
    text = (content or "").strip()
    result = {
        "format": barcode_format,
        "raw_content": text,
        "category": "Plain Text / Data",
        "sub_type": "Generic Data",
        "category_icon": "📝",
        "details": {},
        "safety_level": "Safe",
        "expiry_status": "No Expiry Detected",
        "expiry_details": "This code contains static data with no embedded expiration timestamp.",
        "warnings": []
    }

    if not text:
        result["category"] = "Empty"
        return result

    # 1. UPI & Payment Protocols
    if text.startswith("upi://pay"):
        result["category"] = "Payment & Banking"
        result["category_icon"] = "💳"
        result["sub_type"] = "UPI Payment Link"
        
        parsed = urlsplit(text)
        params = parse_qs(parsed.query)
        pa = params.get("pa", [""])[0] # Payee VPA
        pn = params.get("pn", [""])[0] # Payee Name
        am = params.get("am", [""])[0] # Amount
        tn = params.get("tn", [""])[0] # Note
        tr = params.get("tr", [""])[0] # Transaction Ref

        result["details"] = {
            "Payee VPA / ID": pa or "Unspecified",
            "Payee Name": pn or "Not Provided",
            "Requested Amount": f"INR {am}" if am else "Open / User entered",
            "Transaction Note": tn or "None",
            "Transaction Ref": tr or "None"
        }

        if not pa:
            result["warnings"].append("UPI link missing payee VPA address.")
            result["safety_level"] = "Suspicious"
        else:
            result["safety_level"] = "Caution" # All payment links warrant caution

    # Crypto Payments
    elif any(text.lower().startswith(c) for c in ["bitcoin:", "ethereum:", "solana:", "litecoin:"]):
        result["category"] = "Payment & Banking"
        result["category_icon"] = "🪙"
        result["sub_type"] = "Cryptocurrency Address"
        parts = text.split(":", 1)
        result["details"] = {
            "Network": parts[0].upper(),
            "Recipient Address": parts[1].split("?")[0]
        }
        result["safety_level"] = "Caution"

    # PayPal
    elif "paypal.me/" in text.lower():
        result["category"] = "Payment & Banking"
        result["category_icon"] = "💳"
        result["sub_type"] = "PayPal Transfer Link"
        result["details"] = {"Link": text}
        result["safety_level"] = "Caution"

    # 2. Wi-Fi Configuration
    elif text.upper().startswith("WIFI:"):
        result["category"] = "Wi-Fi Network Access"
        result["category_icon"] = "📶"
        result["sub_type"] = "Wi-Fi Quick Connect"
        
        ssid = re.search(r"S:([^;]+)", text)
        auth = re.search(r"T:([^;]+)", text)
        pwd = re.search(r"P:([^;]+)", text)
        hidden = re.search(r"H:([^;]+)", text)

        result["details"] = {
            "Network Name (SSID)": ssid.group(1) if ssid else "Unknown",
            "Authentication": auth.group(1) if auth else "None (Open)",
            "Password Configured": "Yes (Masked)" if pwd else "No",
            "Hidden Network": "Yes" if hidden and hidden.group(1).lower() == "true" else "No"
        }
        result["safety_level"] = "Safe"

    # 3. Contact Card (vCard)
    elif "BEGIN:VCARD" in text.upper():
        result["category"] = "Contact Card (vCard)"
        result["category_icon"] = "👤"
        result["sub_type"] = "Personal / Business Contact"
        
        fn = re.search(r"FN:(.+)", text, re.IGNORECASE)
        tel = re.search(r"TEL[^:]*:(.+)", text, re.IGNORECASE)
        email = re.search(r"EMAIL[^:]*:(.+)", text, re.IGNORECASE)
        org = re.search(r"ORG:(.+)", text, re.IGNORECASE)

        result["details"] = {
            "Full Name": fn.group(1).strip() if fn else "Unknown",
            "Phone Number": tel.group(1).strip() if tel else "Not specified",
            "Email Address": email.group(1).strip() if email else "Not specified",
            "Organization": org.group(1).strip() if org else "Not specified"
        }
        result["safety_level"] = "Safe"

    # 4. Web URLs & Deep Links
    elif re.match(r"^https?:\/\/", text, re.IGNORECASE):
        result["category"] = "Web URL / Online Navigation"
        result["category_icon"] = "🔗"
        result["sub_type"] = "Hyperlink"
        
        parsed = urlsplit(text)
        netloc = parsed.netloc.lower()
        is_https = parsed.scheme.lower() == "https"

        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"]
        is_shortener = any(netloc == s or netloc.endswith("." + s) for s in shorteners)

        # Check for IP address in place of domain
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", netloc))

        result["details"] = {
            "Domain / Host": netloc,
            "Scheme": parsed.scheme.upper(),
            "Path": parsed.path or "/",
            "SSL/TLS Encrypted": "Yes (HTTPS)" if is_https else "No (Insecure HTTP)"
        }

        if is_shortener:
            result["warnings"].append("Uses URL shortener; target destination is obscured (common in Quishing attacks).")
            result["safety_level"] = "Suspicious"
        elif is_ip:
            result["warnings"].append("URL uses raw IP address instead of domain name.")
            result["safety_level"] = "Suspicious"
        elif not is_https:
            result["warnings"].append("Connection is unencrypted HTTP.")
            result["safety_level"] = "Caution"
        else:
            result["safety_level"] = "Safe"

    # 5. Retail / Product Barcodes
    elif re.match(r"^\d{8}$|^\d{12}$|^\d{13}$|^\d{14}$", re.sub(r"[\s\-]+", "", text)):
        clean_digits = re.sub(r"[\s\-]+", "", text)
        result["category"] = "Product & Logistics"
        result["category_icon"] = "🏷️"
        sub = "GTIN/EAN-13" if len(clean_digits) == 13 else ("UPC-A" if len(clean_digits) == 12 else "Retail Barcode")
        result["sub_type"] = sub
        result["raw_content"] = clean_digits
        
        # Real-world product database lookup
        product_info = lookup_product_by_barcode(clean_digits)
        result["product_info"] = product_info
        
        details = {
            "Standard": sub,
            "Barcode Number": clean_digits,
            "Country of Origin (GS1)": product_info.get("origin_country") or "International / Unassigned",
            "Usage": "Retail point-of-sale, logistics & inventory identification"
        }

        if product_info.get("found"):
            if product_info.get("product_name"):
                details["Product Name"] = product_info["product_name"]
            if product_info.get("brand"):
                details["Brand / Manufacturer"] = product_info["brand"]
            if product_info.get("category"):
                details["Product Category"] = product_info["category"]
            if product_info.get("quantity"):
                details["Volume / Quantity"] = product_info["quantity"]
            if product_info.get("source"):
                details["Catalog Source"] = f"Verified in {product_info['source']}"
        else:
            details["Product Catalog"] = "Not listed in public open registries (Private/Custom barcode)"

        result["details"] = details
        result["safety_level"] = "Safe"

    # 6. Form Autofill / Key-Value Pairs
    elif ("=" in text and "&" in text) or (text.startswith("{") and text.endswith("}")):
        result["category"] = "Form Data / Parameter Payload"
        result["category_icon"] = "📋"
        result["sub_type"] = "Structured Form Data"
        result["details"] = {
            "Data Format": "JSON Object" if text.startswith("{") else "URL-Encoded Form Parameters",
            "Characters": len(text)
        }
        result["safety_level"] = "Safe"

    # --- EXPIRY TIMESTAMP DETECTION ---
    # Look for common expiry keywords in URL queries or text
    exp_matches = re.findall(r"(?:exp|expires|expiry|valid_until|validto|validity|token_exp)=(\d+|[0-9T:\-Z]+)", text, re.IGNORECASE)
    if exp_matches:
        raw_val = exp_matches[0]
        now_ts = datetime.now(timezone.utc).timestamp()
        try:
            # Check epoch timestamp (seconds or ms)
            if raw_val.isdigit():
                ts_int = int(raw_val)
                if ts_int > 100000000000: # milliseconds
                    ts_int = ts_int / 1000.0
                
                exp_date = datetime.fromtimestamp(ts_int, timezone.utc)
                exp_str = exp_date.strftime("%Y-%m-%d %H:%M:%S UTC")

                if ts_int < now_ts:
                    result["expiry_status"] = "EXPIRED"
                    result["expiry_details"] = f"This code expired on {exp_str}."
                    result["warnings"].append(f"Embedded expiration timestamp has passed ({exp_str}).")
                else:
                    result["expiry_status"] = "ACTIVE (Valid)"
                    result["expiry_details"] = f"Valid until {exp_str}."
            else:
                result["expiry_status"] = "Timestamp Embedded"
                result["expiry_details"] = f"Expiration parameter detected: {raw_val}."
        except Exception:
            result["expiry_status"] = "Timestamp Present"
            result["expiry_details"] = f"Found expiry parameter: {raw_val}."

    return result
