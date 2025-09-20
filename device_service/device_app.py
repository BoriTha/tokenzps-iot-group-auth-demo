from flask import Flask, request, jsonify
import requests
import logging
import os, shutil
import secrets
import json
import time
import threading # For running device's own Flask server
from unencrypted_recorder import record as record_unencrypted
from common_utils import (
    CryptoUtils, SimulatedPUF, HASH, generate_random_bits_hex,
    current_timestamp, MAX_TIME_DRIFT, FOG_NODE_URL
)

# ─── optionally wipe all stored state on startup ───
DEVICE_ID = os.environ.get("DEVICE_ID", "device_unknown")
if os.environ.get("WIPE_DEVICE_STORAGE_ON_START", "false").lower() in ("1","true"):
    fn = f"storage/device_{DEVICE_ID}_storage.json"
    try:
        os.remove(fn)
        print(f"WIPE_DEVICE_STORAGE_ON_START: removed {fn}")
    except FileNotFoundError:
        pass

# --- Global Variables for Device App ---
DEVICE_FLASK_PORT = int(os.environ.get("DEVICE_FLASK_PORT", 5001))
device_flask_app = Flask(__name__) # This is the device's own small Flask server
DEVICE_INSTANCE = None # Will be set to BaseDeviceLogic or LeaderDeviceLogic instance

# --- Device's own Flask App Routes (for receiving commands) ---
@device_flask_app.route('/health_device', methods=['GET'])
def health_device():
    if not DEVICE_INSTANCE: return jsonify({"error": "Device not initialized"}), 500
    return jsonify({"id": DEVICE_INSTANCE.id, "role": DEVICE_INSTANCE.role, "status": "healthy"}), 200

@device_flask_app.route('/request_group_auth_coords', methods=['POST'])
def handle_request_group_auth_coords():
    # Leader calls this on member devices
    if not DEVICE_INSTANCE: return jsonify({"error": "Device not initialized"}), 500
    data = request.json # Should contain {"sessionNonce": ...}
    response_pkg = DEVICE_INSTANCE.retrieve_stored_coordinates_for_group_auth(data)
    if response_pkg:
        return jsonify(response_pkg), 200
    return jsonify({"error": "Failed to get coordinates"}), 500

@device_flask_app.route('/receive_delegated_share', methods=['POST'])
def handle_receive_delegated_share():
    # Leader calls this on member devices for Phase 3
    if not DEVICE_INSTANCE: return jsonify({"error": "Device not initialized"}), 500
    data = request.json # {"share_xy": ..., "from_leader_id": ...}
    DEVICE_INSTANCE.receive_group_token_share(data["share_xy"], data["from_leader_id"])
    return jsonify({"message": "Share received"}), 200

@device_flask_app.route('/receive_session_token_point', methods=['POST'])
def handle_receive_session_token_point():
    # Leader calls this on member devices for Phase 5
    if not DEVICE_INSTANCE: return jsonify({"error": "Device not initialized"}), 500
    data = request.json # {"token_point_xy": ..., "from_leader_id": ..., "session_id": ...}
    DEVICE_INSTANCE.receive_session_token_point(data["token_point_xy"], data["from_leader_id"], data.get("session_id"))
    return jsonify({"message": "Token point received"}), 200

@device_flask_app.route('/trigger_send_data', methods=['POST'])
def route_trigger_send_data():
    data = request.json.get("data")
    if not data:
        return jsonify({"error": "data payload required"}), 400
    success = DEVICE_INSTANCE.send_authenticated_data_phase6(data)
    return jsonify({"sent": success}), 200

@device_flask_app.route('/trigger_reauth', methods=['POST'])
def route_trigger_reauth():
    ok = False
    if hasattr(DEVICE_INSTANCE, 'authenticate_with_fog_phase2'):
        ok = DEVICE_INSTANCE.authenticate_with_fog_phase2()
    return jsonify({"reauthed": ok}), 200

@device_flask_app.route('/trigger_group_auth', methods=['POST'])
def route_trigger_group_auth():
    """
    Leader fetches the latest device URLs from the Fog, then
    runs Phase 4 (group authentication) against whoever’s registered.
    """
    body = request.json or {}
    members = body.get("member_ids")

    # ── Step 0: refresh leader’s all_device_urls from the Fog ──
    # so any newly‐added devices get pulled in automatically
    if hasattr(DEVICE_INSTANCE, 'fetch_all_device_urls_from_fog'):
        got = DEVICE_INSTANCE.fetch_all_device_urls_from_fog()
        if not got:
            DEVICE_INSTANCE.logger.warning(
                "Failed to refresh device URLs from Fog before group-auth"
            )

    # ── Step 1: decide which members to include ──
    if not members and hasattr(DEVICE_INSTANCE, 'all_device_urls'):
        members = list(DEVICE_INSTANCE.all_device_urls.keys())

    DEVICE_INSTANCE.logger.info(
        f"Trigger_group_auth: running Phase 4 over members={members}"
    )
    resp = DEVICE_INSTANCE.coordinate_group_authentication_phase4(members)
    return jsonify(resp), 200

@device_flask_app.route('/trigger_token_gen', methods=['POST'])
def route_trigger_token_gen():
    body = request.json or {}
    members = body.get("legit_device_ids")
    if not members and hasattr(DEVICE_INSTANCE, 'all_device_urls'):
        members = list(DEVICE_INSTANCE.all_device_urls.keys())
    ok, sid = DEVICE_INSTANCE.trigger_token_generation_and_distribute_phase5(members)
    return jsonify({"result": ok, "session_id": sid}), 200

@device_flask_app.route('/trigger_register', methods=['POST'])
def route_trigger_register():
    """
    Ask this device to re-run Phase 1 registration with the Fog.
    """
    if not DEVICE_INSTANCE:
        return jsonify({"error": "Device not initialized"}), 500
    ok = DEVICE_INSTANCE.register_with_fog_phase1(force=True)
    return jsonify({"registered": ok}), 200


# --- Device Logic Classes ---
class BaseDeviceLogic:
    def __init__(self, device_id, role="base"):
        self.id = device_id
        self.role = role
        
        # Initialize logger FIRST
        self.logger = logging.getLogger(f"Device_{self.id}")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(f'[%(asctime)s] [{self.id}] %(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        self.storage_path = f"storage/device_{self.id}_storage.json"
        self.storage = {}
        self.puf = SimulatedPUF(self.id)
        self._load_storage()

        # Key generation/loading logic
        if "private_key_pem" not in self.storage or "public_key_pem" not in self.storage:
            self.logger.info("Generating new RSA key pair as it's not found in storage.")
            self.priv_key, self.pub_key = CryptoUtils.generate_rsa_key_pair()
            self._update_storage("private_key_pem", CryptoUtils.serialize_private_key(self.priv_key))
            self._update_storage("public_key_pem", CryptoUtils.serialize_public_key(self.pub_key))
            self.pub_key_pem = self.storage["public_key_pem"] 
        else:
            self.logger.info("Loading RSA key pair from storage.")
            self.priv_key = CryptoUtils.deserialize_private_key(self.storage["private_key_pem"])
            self.pub_key = self.priv_key.public_key()
            self.pub_key_pem = self.storage["public_key_pem"] 
            
        override = os.environ.get("DEVICE_URL_OVERRIDE")
        if override:
            self.my_url = override
        else:
            self.my_url = f"http://{self.id}:{DEVICE_FLASK_PORT}"
        self.logger.info(f"Initialized as {self.role}. URL: {self.my_url}")
        
        self.logger.info(f"Initialized as {self.role}. Storage: {self.storage_path}. URL: {self.my_url}. PK loaded/generated.")

    def _load_storage(self):
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r') as f:
                    self.storage = json.load(f)
                self.logger.info(f"Loaded storage from {self.storage_path}")
        except Exception as e:
            self.logger.error(f"Error loading storage: {e}")
            self.storage = {}

    def _update_storage(self, key, value):
        self.storage[key] = value
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.storage, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving storage: {e}")
        self.logger.info(f"Device Storage Updated: '{key}'")
    
    def _make_fog_request(self, endpoint, method="POST", payload=None):
        url = f"{FOG_NODE_URL}{endpoint}"
        try:
            if method.upper() == "POST":
                response = requests.post(url, json=payload, timeout=10)
            elif method.upper() == "GET":
                response = requests.get(url, timeout=10)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error occurred for {url}: {http_err} - {response.text if hasattr(response, 'text') else 'No response text'}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Fog request to {url} failed: {e}")
        return None

    def register_with_fog_phase1(self, force=False):
        # EARLY GUARD: skip auto-register unless forced
        if not force and os.environ.get("DISABLE_AUTO_REGISTER", "false") \
                           .lower() in ("1","true"):
            self.logger.info(
                "AUTO-REGISTER DISABLED; skipping register_with_fog_phase1()"
            )
            return False

        start_time = time.perf_counter()
        self.logger.info("Phase 1: Registering with Fog Node.")

        enroll_C     = generate_random_bits_hex(32)
        enroll_R     = self.puf.get_response(enroll_C)
        enroll_nonce = generate_random_bits_hex(16)
        device_T0    = current_timestamp()

        x_val_str    = HASH(f"{enroll_R}{self.id}")
        y_val_str    = HASH(f"{enroll_R}{enroll_nonce}{device_T0}")
        x_numeric    = int(x_val_str[:8], 16)
        y_numeric    = int(y_val_str[:8], 16)

        # persist local enrollment state
        self._update_storage("enrollment_challenge_C",      enroll_C)
        self._update_storage("enrollment_response_R",       enroll_R)
        self._update_storage("enrollment_nonce_device",     enroll_nonce)
        self._update_storage("enrollment_T0_device",        device_T0)
        self._update_storage("my_coord_for_group_poly_x_str",  x_val_str)
        self._update_storage("my_coord_for_group_poly_y_str",  y_val_str)
        self._update_storage("my_coord_for_group_poly_x_numeric", x_numeric)
        self._update_storage("my_coord_for_group_poly_y_numeric", y_numeric)

        # build the Fog payload
        payload = {
            "id":                    self.id,
            "public_key_pem":        self.pub_key_pem,
            "url":                   self.my_url,
            "enrollment_challenge":  enroll_C,
            "puf_response_R":        enroll_R,
            "enrollment_nonce":      enroll_nonce,
            "enrollment_T0_device":  device_T0,
            "coord_x_str":           x_val_str,
            "coord_y_str":           y_val_str,
            "coord_x_numeric":       x_numeric,
            "coord_y_numeric":       y_numeric
        }
        # ← NEW: if this device has an EC key, include it
        if hasattr(self, "ec_vk_hex"):
            payload["public_key_ec"] = self.ec_vk_hex

        # call the Fog and measure perf
        response = self._make_fog_request("/register_device_phase1", payload=payload)
        if response:
            self.logger.info("Successfully registered with Fog: %s",
                             response.get("message"))
            self.logger.info("PERF: Phase 1 Device Registration took %.4fs",
                             time.perf_counter() - start_time)
            return True

        self.logger.error("Failed to register with Fog.")
        return False



    def receive_group_token_share(self, share_xy, from_leader_id):
        self.logger.info(f"Received group token share {share_xy} from leader {from_leader_id}")
        self._update_storage("my_group_token_share", share_xy)

    def retrieve_stored_coordinates_for_group_auth(self, request_from_leader):
        start_time = time.perf_counter()
        self.logger.info(f"Received request for group auth coords (nonce: {request_from_leader['sessionNonce']})")
        
        x_numeric = self.storage.get("my_coord_for_group_poly_x_numeric")
        y_numeric = self.storage.get("my_coord_for_group_poly_y_numeric")

        if x_numeric is None or y_numeric is None:
            self.logger.error("ERROR: No enrollment coordinates (numeric) found!")
            return None

        pkg_data = {
            "x": x_numeric, "y": y_numeric,
            "deviceID": self.id,
            "sessionNonce": request_from_leader["sessionNonce"],
            "timestamp": current_timestamp()
        }
        data_to_sign_str = json.dumps(pkg_data, sort_keys=True)
        signature = CryptoUtils.sign_data(self.priv_key, data_to_sign_str)
        
        response = {"coordinates_pkg": pkg_data, "signature": signature}
        self.logger.info(f"Prepared group auth package. Sig: {signature[:10]}...")
        self._update_storage(f"last_group_auth_resp_nonce_{request_from_leader['sessionNonce']}", response)
        self.logger.info(f"PERF: Retrieve_Stored_Coordinates (Device) took {time.perf_counter() - start_time:.4f}s")
        return response

    def receive_session_token_point(self, token_point_xy,
                                    from_leader_id, session_id=None):
        """
        Called by the leader to hand out each device's (x,y) token point.
        We clear any old send-flag when the session changes, store the new
        token, then auto-send exactly one Phase 6 message per session.
        """
        self.logger.info(
            f"Received session token point {token_point_xy} "
            f"from leader {from_leader_id} for session {session_id}"
        )

        # 1) If this is a new session, clear our 'phase6_sent' marker
        prev_sess = self.storage.get("current_session_id_for_data_auth")
        if session_id and session_id != prev_sess:
            self.logger.info(
                f"New session {session_id} (was {prev_sess}), "
                "clearing phase6_sent"
            )
            self._update_storage("phase6_sent", False)

        # 2) Persist the token point
        self._update_storage("my_session_token_point", token_point_xy)

        # 3) Persist the session ID for Phase 6
        if session_id:
            self._update_storage("current_session_id_for_data_auth",
                                 session_id)
            self.logger.info(
                f"Stored current session ID for data auth: {session_id}"
            )

        # 4) Auto-send exactly once per session
        if not self.storage.get("phase6_sent"):
            success = self.send_authenticated_data_phase6(
                f"Auto_data_from_{self.id}"
            )
            if success:
                self._update_storage("phase6_sent", True)
                self.logger.info("Auto Phase 6 send succeeded")
            else:
                self.logger.error("Auto Phase 6 send failed")


    def _auto_send_phase6(self):
        sess = self.storage.get("current_session_id_for_data_auth")
        data = f"Auto_data_from_{self.id}"
        success = self.send_authenticated_data_phase6(data)
        if success:
            self._update_storage("phase6_sent", True)
            self.logger.info("Auto Phase 6 send succeeded")
        else:
            self.logger.error("Auto Phase 6 send failed")


    def send_authenticated_data_phase6(self, data_payload):
        """
        Phase 6: encrypt & send data under ChaCha20-Poly1305 using a
        256-bit key derived from our token-share y, but log & ship
        a padded version of that key for audit.
        """
        start_time = time.perf_counter()

        # 1) pull session ID
        session_id = self.storage.get("current_session_id_for_data_auth")
        if not session_id:
            self.logger.error("No current session ID for Phase 6!")
            return False

        # 2) pull our token point
        token_pt = self.storage.get("my_session_token_point")
        if not token_pt:
            self.logger.error("No session token point for Phase 6!")
            return False

        # 3) Derive the raw 256-bit key from y
        key_raw_int      = int(token_pt["y"])
        raw_key_bytes    = key_raw_int.to_bytes(32, "big")  # exactly 32 bytes

        # 4) Build real random padding (16 bytes on each side)
        PAD_BYTES    = 16
        pad_left     = secrets.token_bytes(PAD_BYTES)
        pad_right    = secrets.token_bytes(PAD_BYTES)
        padded_bytes = pad_left + raw_key_bytes + pad_right

        key_padded_hex   = padded_bytes.hex()        # 64 bytes → 128 hex chars
        key_unpadded_hex = raw_key_bytes.hex()       # 32 bytes → 64 hex chars

        # 5) encrypt with the REAL raw_key_bytes
        encrypted = CryptoUtils.chacha20_encrypt(raw_key_bytes, data_payload)

        # 6) record everything (for audit) 
        record_unencrypted(
            device_id        = self.id,
            session_id       = session_id,
            nonce_hex        = encrypted["nonce"],
            ciphertext_hex   = encrypted["ciphertext"],
            key_padded_hex   = key_padded_hex,
            key_unpadded_hex = key_unpadded_hex,
            key_bytes        = raw_key_bytes
        )

        # 7) build the JSON payload for the Fog, including paddedKeyHex
        payload = {
            "deviceID":    self.id,
            "sessionID":   session_id,
            "timestamp":   current_timestamp(),
            "tokenX":      token_pt["x"],
            "nonce":       encrypted["nonce"],
            "ciphertext":  encrypted["ciphertext"],
            # ship the padded key so Fog can unpad it
            "paddedKeyHex": key_padded_hex
        }

        # 8) send to Fog
        response = self._make_fog_request(
            "/authenticate_data_phase6", payload=payload
        )

        # 9) log perf & result
        self.logger.info(
            f"PERF: Phase 6 Send Auth Data took "
            f"{time.perf_counter() - start_time:.4f}s"
        )
        ok = response and response.get("result") == "VERIFICATION_SUCCESSFUL"
        if ok:
            self.logger.info("Phase 6: Fog accepted our data.")
        else:
            self.logger.error(f"Phase 6: Fog rejected our data: {response}")
        return ok




class LeaderDeviceLogic(BaseDeviceLogic):
    def __init__(self, device_id):
        super().__init__(device_id, role="leader")
        self.leader_pub_key_pem = self.pub_key_pem
        self.session_key_with_fog_bytes = None
        self.all_device_urls = {}
        self.ec_sk, self.ec_vk = CryptoUtils.generate_schnorr_key_pair()
        # serialize the public key in compressed form (hex)
        self.ec_vk_hex = CryptoUtils.serialize_schnorr_vk(self.ec_vk)
        # persist it so we can reload across restarts if you like
        self._update_storage("leader_public_key_ec", self.ec_vk_hex)

    def _make_device_request(self, target_device_url, endpoint, payload=None):
        url = f"{target_device_url}{endpoint}"
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error for {url}: {http_err} - {response.text if hasattr(response, 'text') else 'No response text'}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request to {url} failed: {e}")
        return None

    def fetch_all_device_urls_from_fog(self):
        response = self._make_fog_request("/get_device_urls", method="GET")
        if response:
            self.all_device_urls = response
            self._update_storage("all_device_urls_known_to_leader", self.all_device_urls)
            self.logger.info(f"Fetched all device URLs from Fog: {len(self.all_device_urls)} devices.")
            return True
        self.logger.error("Failed to fetch device URLs from Fog.")
        return False

   # device_app.py, inside class LeaderDeviceLogic
    def authenticate_with_fog_phase2(self):
        """
        Phase 2: Leader proves identity via non-interactive Schnorr ZKP,
        then receives a symmetric session key encrypted under RSA.
        """
        start_time = time.perf_counter()
        self.logger.info("Phase 2: Leader authenticating via Schnorr ZKP.")

        # 1) Build the statement
        session_nonce = generate_random_bits_hex(32)
        ts            = current_timestamp()
        statement     = {
            "publicKeyEC":  self.ec_vk_hex,
            "sessionNonce": session_nonce,
            "timestamp":    ts
        }

        # 2) Prove with Schnorr
        proof = CryptoUtils.schnorr_prove(self.ec_sk, statement)
        self.logger.info(
            "Schnorr ZKP Proof → R=%s, s=%s", proof["R"], proof["s"]
        )

        # 3) Send to Fog
        payload = {
            "leader_id": self.id,
            "statement": statement,
            "zkp_proof": proof
        }
        resp = self._make_fog_request("/leader_auth_phase2", payload=payload)
        self.logger.info(
            "PERF: Phase 2 Leader Auth took %.4fs",
            time.perf_counter() - start_time
        )

        # 4) Handle Fog response
        if resp and resp.get("result") == "AUTHENTICATION_SUCCESSFUL":
            encrypted_sk_hex = resp["encryptedSessionKey"]
            sk_bytes = CryptoUtils.decrypt_asymmetric(
                self.priv_key, encrypted_sk_hex
            )
            self.session_key_with_fog_bytes = sk_bytes
            self._update_storage("session_key_with_fog_hex", sk_bytes.hex())
            self.logger.info("Phase 2: Authenticated & session key stored.")
            return True

        self.logger.error(
            "Phase 2: Authentication FAILED. Fog response: %s", resp
        )
        return False



    def trigger_delegate_group_shares_phase3(self, member_ids, group_token_value):
        start_time = time.perf_counter()
        self.logger.info(f"Phase 3: Leader triggering group share delegation for token {group_token_value}.")
        payload_to_fog = {
            "leader_id": self.id,
            "member_ids": member_ids,
            "group_token_value": group_token_value
        }
        fog_response = self._make_fog_request("/delegate_shares_phase3", payload=payload_to_fog)
        self.logger.info(f"PERF: Phase 3 Trigger Delegation (Leader side) took {time.perf_counter() - start_time:.4f}s")

        if fog_response and fog_response.get("result") == "SUCCESS":
            shares_to_distribute = fog_response.get("shares_for_distribution", {})
            self.logger.info(f"Received {len(shares_to_distribute)} shares from Fog to distribute.")
            dist_count = 0
            for dev_id, share_xy in shares_to_distribute.items():
                if dev_id == self.id:
                    self.receive_group_token_share(share_xy, self.id)
                    dist_count +=1
                else:
                    target_device_url = self.all_device_urls.get(dev_id)
                    if target_device_url:
                        dist_payload = {"share_xy": share_xy, "from_leader_id": self.id}
                        member_resp = self._make_device_request(target_device_url, "/receive_delegated_share", payload=dist_payload)
                        if member_resp and member_resp.get("message") == "Share received":
                            self.logger.info(f"Successfully delegated share to {dev_id}")
                            dist_count +=1
                        else:
                            self.logger.warning(f"Failed to delegate share to {dev_id}, response: {member_resp}")
                    else:
                        self.logger.warning(f"No URL found for device {dev_id} to delegate share.")
            self.logger.info(f"Finished distributing Phase 3 shares to {dist_count} members.")
            return True
        else:
            self.logger.error(f"Phase 3: Fog failed to prepare shares for delegation. Response: {fog_response}")
            return False

    def coordinate_group_authentication_phase4(self, member_ids_for_auth):
        start_time = time.perf_counter()
        self.logger.info("Phase 4: Leader coordinating group authentication.")
        
        if not self.session_key_with_fog_bytes:
             if not self.authenticate_with_fog_phase2():
                self.logger.error("Leader re-authentication failed for Phase 4. Aborting.")
                return None
            
        session_nonce_group = generate_random_bits_hex(32)
        collected_member_data = {}

        for member_id in member_ids_for_auth:
            coord_request_payload = {"sessionNonce": session_nonce_group}
            if member_id == self.id:
                leader_response_pkg = self.retrieve_stored_coordinates_for_group_auth(coord_request_payload)
                if leader_response_pkg: collected_member_data[self.id] = leader_response_pkg
            else:
                target_device_url = self.all_device_urls.get(member_id)
                if target_device_url:
                    member_response_pkg = self._make_device_request(target_device_url, "/request_group_auth_coords", payload=coord_request_payload)
                    if member_response_pkg:
                        collected_member_data[member_id] = member_response_pkg
                        self.logger.info(f"Collected coords from {member_id}")
                    else:
                        self.logger.warning(f"Failed to collect coords from {member_id}")
                else:
                    self.logger.warning(f"No URL for member {member_id} in Phase 4 collection.")
        
        self.logger.info(f"Collected {len(collected_member_data)} coordinate packages for Phase 4.")
        
        payload_to_fog = {
            "leader_id": self.id,
            "received_from_members": collected_member_data,
            "sessionNonce": session_nonce_group
        }
        fog_response = self._make_fog_request("/verify_group_poly_phase4", payload=payload_to_fog)
        self.logger.info(f"PERF: Phase 4 Group Auth Coordination (Leader side) took {time.perf_counter() - start_time:.4f}s")
        return fog_response

    def trigger_token_generation_and_distribute_phase5(self, legit_device_ids):
        start_time = time.perf_counter()
        self.logger.info("Phase 5: Leader triggering token generation and distribution.")
        payload_to_fog = {"leader_id": self.id, "legit_device_ids": legit_device_ids}
        fog_response = self._make_fog_request("/generate_token_poly_phase5", payload=payload_to_fog)
        self.logger.info(f"PERF: Phase 5 Trigger Token Gen (Leader side) took {time.perf_counter() - start_time:.4f}s")

        if fog_response and fog_response.get("result") == "SUCCESS":
            encrypted_token_pkg_for_leader = fog_response["encrypted_token_package_for_leader"]
            if not self.session_key_with_fog_bytes:
                self.logger.error("Leader has no session key with Fog to decrypt token package.")
                return False, None
            
            try:
                decrypted_package = CryptoUtils.decrypt_symmetric(self.session_key_with_fog_bytes, encrypted_token_pkg_for_leader)
                session_id = decrypted_package["sessionID"]
                device_token_points_map = decrypted_package["deviceTokenPoints"]
                self.logger.info(f"Decrypted token package for session {session_id}. Distributing...")

                dist_count = 0
                for dev_id, token_point_xy in device_token_points_map.items():
                    dist_payload = {
                        "token_point_xy": token_point_xy,
                        "from_leader_id": self.id,
                        "session_id": session_id
                    }
                    if dev_id == self.id:
                        self.receive_session_token_point(token_point_xy, self.id, session_id)
                        dist_count +=1
                    else:
                        target_device_url = self.all_device_urls.get(dev_id)
                        if target_device_url:
                            member_resp = self._make_device_request(target_device_url, "/receive_session_token_point", payload=dist_payload)
                            if member_resp and member_resp.get("message") == "Token point received":
                                self.logger.info(f"Successfully distributed token point to {dev_id}")
                                dist_count +=1
                            else:
                                self.logger.warning(f"Failed to distribute token point to {dev_id}, resp: {member_resp}")
                        else:
                            self.logger.warning(f"No URL for device {dev_id} for token point.")
                self.logger.info(f"Finished distributing Phase 5 token points to {dist_count} members.")
                return True, session_id
            except Exception as e:
                self.logger.error(f"Error decrypting/distributing token package: {e}")
                return False, None
        else:
            self.logger.error(f"Phase 5: Fog failed to generate/provide token package. Response: {fog_response}")
            return False, None

# --- Main script execution (for device_app.py) ---
if __name__ == "__main__":
    import threading

    # 1) Read our ID & role from the environment
    DEVICE_ID   = os.environ.get("DEVICE_ID",   "device_unknown")
    DEVICE_ROLE = os.environ.get("DEVICE_ROLE", "base")

    # 2) Instantiate the appropriate logic class
    if DEVICE_ROLE == "leader":
        DEVICE_INSTANCE = LeaderDeviceLogic(DEVICE_ID)
    else:
        DEVICE_INSTANCE = BaseDeviceLogic(DEVICE_ID)

    # 3) DEBUG: check that our DISABLE_AUTO_REGISTER flag actually arrived
    disable_auto = (
        os.environ.get("DISABLE_AUTO_REGISTER", "false")
        .lower() in ("1", "true")
    )
    raw = os.environ.get("DISABLE_AUTO_REGISTER")
    DEVICE_INSTANCE.logger.info(
        f"▸ ENV DISABLE_AUTO_REGISTER={raw!r}, disable_auto={disable_auto}"
    )

    # 4) Start the device's internal Flask server
    def run_device_flask_server():
        DEVICE_INSTANCE.logger.info(
            f"Starting internal Flask server on port {DEVICE_FLASK_PORT}"
        )
        device_flask_app.run(
            host="0.0.0.0",
            port=DEVICE_FLASK_PORT,
            debug=False,
            use_reloader=False
        )

    flask_thread = threading.Thread(
        target=run_device_flask_server, daemon=True
    )
    flask_thread.start()
    DEVICE_INSTANCE.logger.info(
        f"Internal server thread started for {DEVICE_ID}."
    )

    # 5) Give it a moment to spin up
    time.sleep(7)

    # 6) Handle Phase-1 auto-registration only if not disabled
    if not disable_auto:
        # 6a) If we've never registered locally, do it now
        if not DEVICE_INSTANCE.storage.get("phase1_registered_with_fog"):
            if DEVICE_INSTANCE.register_with_fog_phase1():
                DEVICE_INSTANCE._update_storage(
                    "phase1_registered_with_fog", True
                )
            else:
                DEVICE_INSTANCE.logger.error(
                    "Failed initial registration with Fog."
                )
        else:
            DEVICE_INSTANCE.logger.info(
                "Already completed Phase 1 registration with Fog."
            )

        # 6b) Double-check Fog’s registry
        DEVICE_INSTANCE.logger.info("Phase 1: Checking registration on Fog.")
        urls = DEVICE_INSTANCE._make_fog_request(
            "/get_device_urls", method="GET"
        ) or {}

        if DEVICE_INSTANCE.id in urls:
            DEVICE_INSTANCE.logger.info(
                f"{DEVICE_INSTANCE.id} already in Fog’s registry. Skipping register."
            )
            DEVICE_INSTANCE._update_storage(
                "phase1_registered_with_fog", True
            )
        else:
            DEVICE_INSTANCE.logger.info(
                f"{DEVICE_INSTANCE.id} not found on Fog. Registering now."
            )
            if DEVICE_INSTANCE.register_with_fog_phase1():
                DEVICE_INSTANCE._update_storage(
                    "phase1_registered_with_fog", True
                )
                DEVICE_INSTANCE.logger.info(
                    "Phase 1 registration succeeded."
                )
            else:
                DEVICE_INSTANCE.logger.error(
                    "Phase 1 registration failed. Device may not function."
                )
    else:
        DEVICE_INSTANCE.logger.info(
            "AUTO-REGISTER DISABLED; skipping all Phase 1 register/check"
        )

    # 7) Leader orchestration vs. base‐device idle/send‐data
    if DEVICE_ROLE == "leader":
        leader = DEVICE_INSTANCE
        leader.logger.info("Leader waiting for others to register…")
        time.sleep(15)

        # 7a) Always re‐trigger Phase-1 poly setup on Fog
        if leader.storage.get("phase1_fog_poly_setup_triggered"):
            leader.logger.info(
                "Clearing stale Phase 1 setup flag for re-trigger."
            )
            leader.storage.pop("phase1_fog_poly_setup_triggered", None)
            leader._update_storage(
                "phase1_fog_poly_setup_triggered", False
            )

        leader.logger.info("Triggering Phase 1 polynomial setup on Fog.")
        resp1 = leader._make_fog_request(
            "/trigger_phase1_polynomial_setup", payload={}
        )
        if resp1 and "group_secret_S" in resp1:
            leader.logger.info(f"Phase 1 setup OK: {resp1}")
            leader._update_storage(
                "phase1_fog_poly_setup_triggered", True
            )
        else:
            leader.logger.error(f"Phase 1 setup failed: {resp1}")
            exit(1)

        # 7b) Leader Phase-2 auth
        if not leader.authenticate_with_fog_phase2():
            exit(1)

        # 7c) Fetch device list, Phase-3 share delegation
        if not leader.fetch_all_device_urls_from_fog():
            exit(1)
        member_ids = list(leader.all_device_urls.keys())
        if not leader.trigger_delegate_group_shares_phase3(
                member_ids, "S_from_phase1_placeholder"
            ):
            exit(1)

        # 7d) Phase-4 group authentication
        time.sleep(5)
        phase4 = leader.coordinate_group_authentication_phase4(member_ids)
        if not phase4 or phase4.get("result") != "AUTHENTICATION_SUCCESSFUL":
            exit(1)
        leader.logger.info(
            f"Phase 4 succeeded (session {phase4['sessionID']})"
        )

        # 7e) Phase-5 token generation & distribution
        ok5, session5 = leader.trigger_token_generation_and_distribute_phase5(
            member_ids
        )
        if not ok5:
            exit(1)
        leader.logger.info(f"Phase 5 succeeded (session {session5})")

        # 7f) Phase-6 the leader sends its own data
        time.sleep(5)
        leader.send_authenticated_data_phase6(
            f"Leader_data_for_session_{session5}"
        )
        leader.logger.info("Leader orchestration complete.")
    else:
        base = DEVICE_INSTANCE
        base.logger.info("Base device idle—waiting for leader flows…")

        WAIT_SECS     = 30
        POLL_INTERVAL = 1

        for _ in range(int(WAIT_SECS / POLL_INTERVAL)):
            # if auto already sent, break out immediately
            if base.storage.get("phase6_sent", False):
                base.logger.info("Phase 6 already sent; skipping fallback")
                break

            sess = base.storage.get("current_session_id_for_data_auth")
            tok  = base.storage.get("my_session_token_point")
            if sess and tok:
                base.logger.info("Fallback Phase 6: Sending data.")
                ok = base.send_authenticated_data_phase6(
                    f"Base_device_{base.id}_data"
                )
                base._update_storage("phase6_sent", ok)
                if ok:
                    base.logger.info("Fallback Phase 6 send succeeded")
                else:
                    base.logger.error("Fallback Phase 6 send failed")
                break

            time.sleep(POLL_INTERVAL)
        else:
            # only runs if for‐loop never broke
            base.logger.info(
                f"No session token/ID found after {WAIT_SECS}s; skipping Phase 6."
            )


    # 8) Keep the container alive
    while True:
        time.sleep(60)



