import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import logging
from scanner import run_full_scan
from barcode_analyzer import analyze_barcode_payload, decode_barcode_from_image
from ai_integration import get_barcode_ai_analysis
import base64

# Configure logging
logging.basicConfig(level=logging.ERROR)

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)  # Enable CORS for all routes

@app.route("/")
def home():
    if os.path.exists(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return "Backend is working!"

@app.route("/scan", methods=["POST"])
def scan():
    import traceback
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        result = run_full_scan(url)
        return jsonify(result)
    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"Error during scan: {str(e)}\n{tb}")
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.route("/analyze-barcode", methods=["GET", "POST", "OPTIONS"])
@app.route("/analyze-barcode/", methods=["GET", "POST", "OPTIONS"])
def analyze_barcode():
    if request.method == "OPTIONS":
        return "", 200
    if request.method == "GET":
        return jsonify({"status": "ready", "endpoint": "/analyze-barcode"}), 200

    import traceback
    data = request.get_json() or {}
    content = data.get("content", "")
    barcode_format = data.get("format", "QR_CODE")

    if not content:
        return jsonify({"error": "No barcode content provided"}), 400

    try:
        analysis = analyze_barcode_payload(content, barcode_format)
        ai_audit = get_barcode_ai_analysis(analysis)
        analysis["ai_analysis"] = ai_audit
        return jsonify(analysis)
    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"Error during barcode analysis: {str(e)}\n{tb}")
        return jsonify({"error": f"Barcode analysis failed: {str(e)}"}), 500

@app.route("/decode-barcode-image", methods=["GET", "POST", "OPTIONS"])
@app.route("/decode-barcode-image/", methods=["GET", "POST", "OPTIONS"])
def decode_image_endpoint():
    if request.method == "OPTIONS":
        return "", 200
    if request.method == "GET":
        return jsonify({"status": "ready", "endpoint": "/decode-barcode-image"}), 200
    import traceback
    try:
        raw_bytes = None

        # Check for multipart file upload
        if "file" in request.files:
            file_storage = request.files["file"]
            raw_bytes = file_storage.read()

        # Check for JSON base64 image
        elif request.is_json:
            data = request.get_json() or {}
            img_data = data.get("image", "")
            if img_data:
                if "," in img_data:
                    img_data = img_data.split(",", 1)[1]
                # Fix missing padding
                clean_b64 = img_data.strip().replace(" ", "+")
                missing_padding = len(clean_b64) % 4
                if missing_padding != 0:
                    clean_b64 += "=" * (4 - missing_padding)
                try:
                    raw_bytes = base64.b64decode(clean_b64)
                except Exception as b64_err:
                    return jsonify({"error": f"Invalid base64 image payload: {str(b64_err)}"}), 400

        if not raw_bytes:
            return jsonify({"error": "No image data provided"}), 400

        decoded = decode_barcode_from_image(raw_bytes)
        if not decoded:
            return jsonify({"error": "No barcode or QR code could be detected in this image. Ensure the code is clearly visible."}), 404

        analysis = analyze_barcode_payload(decoded["code"], decoded.get("format", "UNKNOWN"))
        analysis["decoded_by"] = decoded.get("engine", "server")
        ai_audit = get_barcode_ai_analysis(analysis)
        analysis["ai_analysis"] = ai_audit
        return jsonify(analysis)

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"Error during image decoding: {str(e)}\n{tb}")
        return jsonify({"error": f"Image decoding failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)


