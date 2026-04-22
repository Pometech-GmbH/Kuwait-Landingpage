"""
Vexoplay – OTP PIN Flow
Mobimind MGP API Integration (Version 2.0)
"""

import base64
import json
import os
import secrets

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ─── Load environment ────────────────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")

# ─── Config from .env ────────────────────────────────────────────────────────
HOST             = os.getenv("HOST", "0.0.0.0")
PORT             = int(os.getenv("PORT", "8000"))
DEBUG            = os.getenv("DEBUG", "false").lower() == "true"

API_BASE_URL     = os.getenv("API_BASE_URL", "http://apisdp.digitalsp.net")
API_VERSION      = os.getenv("API_VERSION", "V1")
API_USERNAME     = os.getenv("API_USERNAME", "")
API_PASSWORD     = os.getenv("API_PASSWORD", "")

CHANNEL_ID       = int(os.getenv("CHANNEL_ID", "1111"))
SP_ID            = int(os.getenv("SP_ID", "111"))
LANGUAGE_ID      = int(os.getenv("DEFAULT_LANGUAGE_ID", "3"))

ANTIFRAUD_BASE_URL = os.getenv(
    "ANTIFRAUD_BASE_URL",
    "http://antifraud.cgparcel.net/AntiFraud/Prepare/",
)

SITE_NAME        = os.getenv("SITE_NAME", "Vexoplay")
SITE_TAGLINE     = os.getenv("SITE_TAGLINE", "Arcade gaming, reimagined for web.")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _auth_token() -> str:
    """Build HTTP Basic Auth token from .env credentials."""
    raw = f"{API_USERNAME}:{API_PASSWORD}"
    return "Basic " + base64.b64encode(raw.encode("ascii")).decode("ascii")


def _headers_b64() -> str:
    # Wir nehmen die Header so, wie sie kommen. 
    # .items() in Flask bewahrt normalerweise die Schreibweise der Browser-Header.
    header_dict = {k: v for k, v in request.headers.items()}
    
    # Umwandlung in JSON-String
    json_string = json.dumps(header_dict)
    
    # Base64 Kodierung
    return base64.b64encode(json_string.encode("utf-8")).decode("utf-8")

def _user_ip_b64() -> str:
    """Nimmt die echte IP des Nutzers (remote_addr) und kodiert sie in Base64."""
    # Falls du später hinter einem Proxy (wie Nginx/Heroku) bist, 
    # nutze: request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = request.remote_addr or "127.0.0.1"
    return base64.b64encode(ip.encode("utf-8")).decode("utf-8")

def _antifraud(page_id: int, click_id: str) -> tuple[str, str]:
    """
    Korrektes Aufrufen der Anti-Fraud API mittels GET (laut Doku S. 4).
    """
    try:
        # Parameter für die URL
        params = {
            "Page":      page_id,
            "ChannelID": CHANNEL_ID,
            "ClickID":   click_id,
            "Headers":   _headers_b64(),
            "UserIP":    _user_ip_b64(),
        }
        
        # Requests hängt params automatisch als ?Page=...&ChannelID=... an die URL an
        resp = requests.get(ANTIFRAUD_BASE_URL, params=params, timeout=5)
        
        if resp.status_code != 200:
            print(f"AF-Error: Status {resp.status_code}, Text: {resp.text}", flush=True)
            return "", "0"

        # Laut Doku: "include the JS received in the page header"
        # Das bedeutet, der Body (resp.text) IST das JavaScript.
        js_snippet = resp.text
        
        # Die UniqID steckt im Response-Header (NICHT im JSON)
        uniqid = resp.headers.get("AntiFrauduniqid", "0")
        
        return js_snippet, uniqid

    except Exception as e:
        print(f"AF-Exception: {str(e)}", flush=True)
        return "", "0"

def _new_click_id() -> str:
    """Generate a unique alphanumeric ClickID (exactly 12 chars, alphanumeric only)."""
    return secrets.token_hex(6)  # 6 bytes → exactly 12 hex characters
 

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Step 1 – Phone number entry page."""
    click_id = _new_click_id()
    session["click_id"] = click_id

    af_js, _ = _antifraud(1, click_id)
    print("DEBUG ANTIFRAUD API RESPONSE:", repr(af_js), flush=True)

    return render_template(
        "index.html",
        antifraud_js=af_js,
        site_name=SITE_NAME,
        site_tagline=SITE_TAGLINE,
    )


@app.route("/request-pin", methods=["POST"])
def request_pin():
    """Step 2 – Call PinRequest API; redirect to OTP entry on success."""
    msisdn   = request.form.get("msisdn", "").strip()
    click_id = session.get("click_id", _new_click_id())

    if not msisdn:
        af_js, _ = _antifraud(1, click_id)
        return render_template(
            "index.html",
            error="Please enter your mobile number.",
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )

    full_msidn = "965" + msisdn
    session["msisdn"] = full_msidn

    url = f"{API_BASE_URL}/api/{API_VERSION}/PinRequest"
    payload = {
        "API": {
            "ClickID":    click_id,
            "MSISDN":     full_msidn,
            "ChannelID":  CHANNEL_ID,
            "SPID":       SP_ID,
            "LanguageID": LANGUAGE_ID,
        }
    }
    headers = {
        "Authorization": _auth_token(),
        "Content-Type":  "application/json; charset=UTF-8",
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        data = resp.json()
    except Exception:
        af_js, _ = _antifraud(1, click_id)
        return render_template(
            "index.html",
            error="Connection error. Please try again.",
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )

    if data.get("Success"):
        # Prepare anti-fraud for page 2 (same ClickID!)
        af_js, af_uniqid = _antifraud(2, click_id)
        session["antifraud_uniqid"] = af_uniqid
        return render_template(
            "verify.html",
            msisdn=msisdn,
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )
    else:
        error_msg = data.get("Message", "Failed to send PIN. Please try again.")
        af_js, _ = _antifraud(1, click_id)
        return render_template(
            "index.html",
            error=error_msg,
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )


@app.route("/verify-pin", methods=["POST"])
def verify_pin():
    """Step 3 – Call PinVerify API; redirect to success on valid PIN."""
    pin              = request.form.get("pin", "").strip()
    msisdn           = session.get("msisdn", request.form.get("msisdn", ""))
    click_id         = session.get("click_id", "0")
    antifraud_uniqid = session.get("antifraud_uniqid", "0")

    if not pin:
        af_js, af_uniqid = _antifraud(2, click_id)
        return render_template(
            "verify.html",
            msisdn=msisdn,
            error="Please enter the PIN code.",
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )

    url = f"{API_BASE_URL}/api/{API_VERSION}/PinVerify"
    payload = {
        "API": {
            "ClickID":          click_id,
            "MSISDN":           msisdn,
            "ChannelID":        CHANNEL_ID,
            "SPID":             SP_ID,
            "LanguageID":       LANGUAGE_ID,
            "Pin":              pin,
            "AntiFrauduniqid":  antifraud_uniqid,
        }
    }
    headers = {
        "Authorization": _auth_token(),
        "Content-Type":  "application/json; charset=UTF-8",
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        data = resp.json()
    except Exception:
        af_js, _ = _antifraud(2, click_id)
        return render_template(
            "verify.html",
            msisdn=msisdn,
            error="Connection error. Please try again.",
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )

    if data.get("Success"):
        session.clear()
        return render_template(
            "success.html",
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )
    else:
        error_msg = data.get("Message", "Invalid PIN. Please try again.")
        af_js, af_uniqid = _antifraud(2, click_id)
        session["antifraud_uniqid"] = af_uniqid   # refresh uniqid on retry
        return render_template(
            "verify.html",
            msisdn=msisdn,
            error=error_msg,
            antifraud_js=af_js,
            site_name=SITE_NAME,
            site_tagline=SITE_TAGLINE,
        )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
