# fog_service.py

from flask import Flask, request, jsonify
import secrets
import logging
import secrets
import os, shutil
import json
import time
import math
import random  # Ensure random sampling is available
from common_utils import (
    CryptoUtils, SimulatedPUF, HASH,
    generate_random_bits_hex, current_timestamp, MAX_TIME_DRIFT
)
import numpy as np

WIPE = os.environ.get("WIPE_STORAGE_ON_START", "false").lower() in ("1","true")
if WIPE:
    # 1) Remove the entire storage folder (this deletes fog_node_storage.json)
    shutil.rmtree("storage", ignore_errors=True)
    # 2) Recreate the base storage dir
    os.makedirs("storage", exist_ok=True)
    print("WIPE_STORAGE_ON_START: wiped storage/ directory")

# Now set up the logs directory and wipe the old device_data.log too
logs_dir = os.path.join(os.getcwd(), "storage", "logs")
os.makedirs(logs_dir, exist_ok=True)
data_log = os.path.join(logs_dir, "device_data.log")
if WIPE and os.path.exists(data_log):
    os.remove(data_log)
    print(f"WIPE_STORAGE_ON_START: wiped log file {data_log}")

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [FogService] %(levelname)s: %(message)s'
)


storage_dir   = os.path.join(os.getcwd(), "storage", "logs")
os.makedirs(storage_dir, exist_ok=True)
data_log_path = os.path.join(storage_dir, "device_data.log")

data_logger = logging.getLogger("DeviceDataLogger")
data_logger.setLevel(logging.INFO)
fh = logging.FileHandler(data_log_path)
fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
data_logger.addHandler(fh)

class FogNodeSingleton:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FogNodeSingleton, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, storage_path="storage/fog_node_storage.json"):
        if self._initialized:
            return
        self.storage_path = storage_path
        self.storage = {}
        self.devices_public_keys = {}
        self.device_urls = {}
        self.current_session_id = None

        self._load_storage()

        # --- Parameter Initialization ---
        env_num_devices = os.environ.get("NUM_DEVICES")
        env_t_phase1 = os.environ.get("THRESHOLD_T")
        env_delegation_t_prime = os.environ.get("DELEGATION_THRESHOLD_T_PRIME")
        env_leader_id = os.environ.get("LEADER_DEVICE_ID")

        params = self.storage.get("parameters", {})
        self.num_total_devices = int(
            env_num_devices if env_num_devices is not None
            else params.get("total_devices", 3)
        )
        self.t_threshold_phase1 = int(
            env_t_phase1 if env_t_phase1 is not None
            else params.get("t_phase1", 2)
        )
        self.delegation_threshold_t_prime = int(
            env_delegation_t_prime if env_delegation_t_prime is not None
            else params.get("delegation_t_prime", 2)
        )
        self.config_leader_id = (
            env_leader_id if env_leader_id is not None
            else self.storage.get("config_leader_id", "device_1")
        )

        self.storage["parameters"] = {
            "total_devices": self.num_total_devices,
            "t_phase1": self.t_threshold_phase1,
            "delegation_t_prime": self.delegation_threshold_t_prime
        }
        self.storage["config_leader_id"] = self.config_leader_id

        if "leader_id" not in self.storage:
            self.storage["leader_id"] = None
        if "leader_public_key_pem" not in self.storage:
            self.storage["leader_public_key_pem"] = None

        self._save_storage()
        app.logger.info(
            f"FogNode initialized. Expect leader={self.config_leader_id}, "
            f"devices={self.num_total_devices}, t_phase1={self.t_threshold_phase1}"
        )
        self._initialized = True

    def _load_storage(self):
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r") as f:
                    self.storage = json.load(f)
                self.devices_public_keys = self.storage.get(
                    "registered_devices_pks", {}
                )
                self.device_urls = self.storage.get(
                    "registered_devices_urls", {}
                )
                self.current_session_id = self.storage.get(
                    "active_session_info", {}
                ).get("sessionID")
                app.logger.info(f"Loaded storage from {self.storage_path}")
            else:
                app.logger.info(
                    f"No storage at {self.storage_path}, starting fresh."
                )
                self.storage = {}
                self.devices_public_keys = {}
                self.device_urls = {}
                self.current_session_id = None
        except Exception as e:
            app.logger.error(f"Error loading storage: {e}")
            self.storage = {}
            self.devices_public_keys = {}
            self.device_urls = {}
            self.current_session_id = None

    def _save_storage(self):
        try:
            self.storage["registered_devices_pks"] = self.devices_public_keys
            self.storage["registered_devices_urls"] = self.device_urls
            with open(self.storage_path, "w") as f:
                json.dump(
                    self.storage,
                    f,
                    indent=2,
                    default=lambda o: "<object>"
                )
        except Exception as e:
            app.logger.error(f"Error saving storage: {e}")

    def _update_storage_key(self, key, value):
        self.storage[key] = value
        self._save_storage()
        log_value = value
        if isinstance(value, dict) and len(value) > 3:
            log_value = f"dict with {len(value)} keys"
        elif isinstance(value, list) and len(value) > 3:
            log_value = f"list with {len(value)} items"
        app.logger.info(f"Fog Storage Updated: '{key}': {log_value}")

    def initialize_system_phase1(self):
        """
        Phase 1: (re)compute the group polynomial P(x), S=P(0), and per-device
        offsets.  First we clear any old Phase 1 data to guarantee fresh state.
        """
        phase_start_time = time.perf_counter()
        app.logger.info("Phase 1: Clearing old polynomial data from Fog storage")

        # 1) Clear any previous Phase 1 keys, but keep device registrations
        keys_to_remove = [
            "group_poly_P_defining_points",
            "group_poly_P_coeffs",
            "group_secret_S",
            "group_poly_P_degree",
            "group_poly_P_device_offsets"
        ]
        for k in keys_to_remove:
            if k in self.storage:
                self.storage.pop(k)
        # Persist deletion
        self._save_storage()

        app.logger.info("Phase 1: Starting fresh polynomial setup")
        # --- rest is your existing logic ---
        t = self.t_threshold_phase1
        enrolled = self.storage.get("all_device_enrollment_data", {})
        registered = list(self.devices_public_keys.keys())
        valid_ids = [
            dev for dev in registered
            if dev in enrolled and "x_numeric" in enrolled[dev]
        ]
        app.logger.info(f"{len(valid_ids)} devices have full enrollment; t={t}")
        if len(valid_ids) < t:
            app.logger.error(
                f"Not enough fully enrolled devices ({len(valid_ids)}) for t={t}"
            )
            return False, "Not enough fully enrolled devices for P(x) threshold"

        # 2) select t devices to define P(x)
        selected = random.sample(valid_ids, t)
        pts = [(enrolled[d]["x_numeric"], enrolled[d]["y_numeric"])
               for d in selected]
        self._update_storage_key("group_poly_P_defining_points", pts)
        app.logger.info(f"Defining points for P(x): {pts}")

        # 3) interpolate P(x)
        try:
            poly_P = CryptoUtils.get_polynomial_from_points(pts)
            self._update_storage_key(
                "group_poly_P_coeffs", poly_P.coeffs.tolist()
            )
        except Exception as e:
            app.logger.error(f"P(x) interpolation error: {e}")
            return False, f"P(x) error: {e}"

        # 4) compute S = P(0)
        S = float(CryptoUtils.evaluate_polynomial(poly_P, 0))
        self._update_storage_key("group_secret_S", S)
        self._update_storage_key("group_poly_P_degree", t - 1)
        app.logger.info(f"Group secret S=P(0)={S}, degree={t-1}")

        # 5) compute offsets for *all* enrolled devices
        offsets = {}
        for dev_id, data in enrolled.items():
            if "x_numeric" not in data or "y_numeric" not in data:
                continue
            x_i = data["x_numeric"]
            y_i = data["y_numeric"]
            y_on_curve = float(
                CryptoUtils.evaluate_polynomial(poly_P, x_i)
            )
            off = y_on_curve - y_i
            offsets[dev_id] = off
            app.logger.info(
                f"Offset[{dev_id}] = P({x_i})={y_on_curve:.4f} - "
                f"y={y_i:.4f} → {off:.4f}"
            )
        self._update_storage_key("group_poly_P_device_offsets", offsets)
        app.logger.info(f"Stored offsets for {len(offsets)} devices")

        app.logger.info(
            f"PERF: Phase 1 Poly Setup TOTAL "
            f"{time.perf_counter() - phase_start_time:.4f}s"
        )
        return True, "Phase 1 polynomial setup complete on Fog."


    # fog_app.py, inside class FogNodeSingleton
    def handle_verify_leader_identity(self, request_data, source_id):
        """
        Phase 2: Verify leader’s Schnorr ZKP, then issue a symmetric key.
        """
        start = time.perf_counter()
        app.logger.info("Phase 2: VERIFY_LEADER_IDENTITY from %s", source_id)

        # 1) must be the registered leader
        actual = self.storage.get("leader_id")
        if source_id != actual:
            return {"result":"AUTHENTICATION_FAILED","reason":"Not leader"}

        stmt  = request_data.get("statement", {})
        proof = request_data.get("zkp_proof", {})

        # 2) freshness
        ts = stmt.get("timestamp", 0)
        if abs(current_timestamp() - ts) > MAX_TIME_DRIFT:
            app.logger.warning("Leader Auth Failed: timestamp drift")
            return {
                "result":"AUTHENTICATION_FAILED",
                "reason":"Timestamp expired"
            }

        # 3) EC key must match what we stored in Phase 1
        reg_vk_hex = self.storage.get("leader_public_key_ec")
        if not reg_vk_hex or stmt.get("publicKeyEC") != reg_vk_hex:
            app.logger.warning("Leader Auth Failed: PublicKeyEC mismatch")
            return {
                "result":"AUTHENTICATION_FAILED",
                "reason":"PublicKeyEC mismatch"
            }

        # 4) verify Schnorr proof
        ok = CryptoUtils.schnorr_verify(reg_vk_hex, proof, stmt)
        app.logger.info("Schnorr verification result: %s", ok)
        if not ok:
            return {
                "result":"AUTHENTICATION_FAILED",
                "reason":"ZKP verification failed"
            }

        # 5) success → issue symmetric session key under RSA
        rsa_pub_pem = self.storage.get("leader_public_key_pem")
        sk = CryptoUtils.generate_symmetric_key()
        enc_sk = CryptoUtils.encrypt_asymmetric(rsa_pub_pem, sk)
        self._update_storage_key(f"session_key_for_leader_{actual}", sk.hex())

        app.logger.info(
            "PERF: Phase 2 Verify Leader took %.4fs",
            time.perf_counter() - start
        )
        return {
            "result":              "AUTHENTICATION_SUCCESSFUL",
            "encryptedSessionKey": enc_sk
        }


    def handle_delegate_group_shares(self,
                                     group_member_ids,
                                     group_token_value,
                                     leader_id_requesting):
        start = time.perf_counter()
        app.logger.info(
            f"Phase 3: DELEGATE_GROUP_SHARES from {leader_id_requesting}"
        )

        # 1) auth
        actual = self.storage.get("leader_id")
        if leader_id_requesting != actual:
            return {"result": "FAILED", "reason": "Unauthorized"}

        # 2) session key
        sk_hex = self.storage.get(f"session_key_for_leader_{actual}")
        if not sk_hex:
            return {
                "result": "FAILED",
                "reason": "Leader not authenticated"
            }
        session_key = bytes.fromhex(sk_hex)

        # 3) determine secret
        t_prime = self.delegation_threshold_t_prime
        if group_token_value == "S_from_phase1_placeholder":
            secret = self.storage.get("group_secret_S")
            if secret is None:
                return {"result": "FAILED",
                        "reason": "Group secret S missing"}
        else:
            try:
                secret = float(group_token_value)
            except ValueError:
                secret = int(HASH(str(group_token_value))[:16], 16)

        app.logger.info(f"Secret for delegation: {secret}, t'={t_prime}")

        # 4) build SSS polynomial
        poly = CryptoUtils.construct_sss_polynomial(secret, t_prime - 1)
        self._update_storage_key(
            "group_delegation_poly_coeffs", poly.coeffs.tolist()
        )
        self._update_storage_key(
            "group_delegation_poly_secret_used", secret
        )

        # 5) compute shares
        enrollment = self.storage.get("all_device_enrollment_data", {})
        shares = {}
        for dev_id in group_member_ids:
            data = enrollment.get(dev_id, {})
            x = data.get("x_numeric")
            if x is None:
                app.logger.warning(f"No x_numeric for {dev_id}, skip")
                continue
            y = float(CryptoUtils.evaluate_polynomial(poly, x))
            shares[dev_id] = {"x": x, "y": y}
            app.logger.info(f"Share[{dev_id}] = (x={x},y={y})")

        # 6) persist & return
        self._update_storage_key(
            "member_shares_of_groupToken_pending_dist", shares
        )
        self._update_storage_key(
            "group_delegation_timestamp", current_timestamp()
        )
        app.logger.info(
            f"PERF: Phase 3 Delegate Shares TOTAL "
            f"{time.perf_counter() - start:.4f}s"
        )
        return {"result": "SUCCESS", "shares_for_distribution": shares}

    def handle_verify_group_polynomial(self, request_data_dict,
                                       source_leader_id):
        start = time.perf_counter()
        app.logger.info(
            f"Phase 4: VERIFY_GROUP_POLYNOMIAL from {source_leader_id}"
        )

        # auth
        actual = self.storage.get("leader_id")
        if source_leader_id != actual:
            return {"result": "AUTHENTICATION_FAILED",
                    "reason": "Unauthorized"}

        enrolled = self.storage.get("all_device_enrollment_data", {})
        offsets = self.storage.get("group_poly_P_device_offsets", {})
        t = self.storage.get("group_poly_P_degree", 0) + 1

        valid = []
        suspicious = []
        for dev_id, pkg in request_data_dict["received_from_members"].items():
            coord = pkg["coordinates_pkg"]
            sig   = pkg["signature"]
            rec   = enrolled.get(dev_id, {})

            ok_sig = CryptoUtils.verify_signature(
                rec.get("public_key_pem", ""), sig,
                json.dumps(coord, sort_keys=True)
            )
            coords_ok = (
                coord.get("x") == rec.get("x_numeric")
                and coord.get("y") == rec.get("y_numeric")
            )
            fresh = abs(current_timestamp() - coord.get("timestamp", 0)
                       ) <= MAX_TIME_DRIFT

            if ok_sig and coords_ok and fresh:
                x_i = coord["x"]
                y_i = coord["y"]
                off = offsets.get(dev_id, 0.0)
                y_eff = y_i + off
                valid.append((x_i, y_eff))
                app.logger.info(
                    f"{dev_id}: raw({y_i})+offset({off:.4f})→eff({y_eff:.4f})"
                )
            else:
                suspicious.append(dev_id)
                app.logger.warning(
                    f"Bad pkg from {dev_id}: sig={ok_sig}, coords={coords_ok}, fresh={fresh}"
                )

        self._update_storage_key(
            "last_group_auth_suspicious_devices", suspicious
        )
        if len(valid) < t:
            return {"result": "AUTHENTICATION_FAILED",
                    "reason": "Not enough valid shares"}

        subset = random.sample(valid, t)
        S_prime = CryptoUtils.interpolate_polynomial(subset, 0)
        S_stored = self.storage.get("group_secret_S")

        if np.isclose(S_prime, S_stored):
            sess = generate_random_bits_hex(16)
            self.current_session_id = sess
            info = {
                "sessionID": sess,
                "authenticated_devices_for_S": [
                    d for d in request_data_dict["received_from_members"]
                    if d not in suspicious
                ],
                "timestamp": current_timestamp()
            }
            self._update_storage_key("active_session_info", info)
            app.logger.info(
                f"PERF: Phase 4 Verify GROUP POLY took "
                f"{time.perf_counter() - start:.4f}s"
            )
            return {"result": "AUTHENTICATION_SUCCESSFUL",
                    "sessionID": sess}
        else:
            app.logger.warning(
                f"Secret mismatch: S'={S_prime} != S={S_stored}"
            )
            return {"result": "AUTHENTICATION_FAILED",
                    "reason": "Secret mismatch"}

    def handle_generate_token_polynomial(self, legit_device_ids, requesting_leader_id):
        """
        Phase 5: Build the token polynomial, store per-device points and
        the list of legitimate devices, then return an encrypted package
        for the leader.
        """
        start = time.perf_counter()
        app.logger.info(f"Phase 5: GENERATE_TOKEN_POLYNOMIAL from {requesting_leader_id}")

        # 1) Auth
        actual_leader = self.storage.get("leader_id")
        if requesting_leader_id != actual_leader:
            return {"result": "FAILED", "reason": "Unauthorized"}

        # 2) Active session check
        active = self.storage.get("active_session_info")
        if not active or active.get("sessionID") != self.current_session_id:
            return {"result": "FAILED", "reason": "No active authenticated session"}

        # 3) nonce2, T1, tSecret
        import secrets
        nonce2 = secrets.token_bytes(32).hex()  # 256-bit nonce
        T1     = current_timestamp()
        tsec_str = HASH(f"{self.storage['group_secret_S']}{nonce2}{T1}")
        t_secret = int(tsec_str[:32], 16)      # use 128 bits of the hash

        # 4) Build the list of points
        points = [(0, t_secret)]
        device_points = {}
        enroll = self.storage.get("all_device_enrollment_data", {})
        for dev_id in legit_device_ids:
            data = enroll.get(dev_id, {})
            if "x_numeric" not in data or "y_numeric" not in data:
                app.logger.warning(f"Skipping {dev_id}: incomplete enrollment")
                continue
            cx = data["x_numeric"]
            cy = data["y_numeric"]
            xi = int(HASH(f"{cx}{cy}{nonce2}")[:32], 16)
            yi = int.from_bytes(secrets.token_bytes(32), "big")
            points.append((xi, yi))
            device_points[dev_id] = {"x": xi, "y": yi}
            app.logger.info(f"Token point for {dev_id}: x={xi}, y={yi}")

        if len(points) <= 1:
            return {"result": "FAILED", "reason": "Not enough points for token poly"}

        # 5) Lagrange interpolation
        token_poly = CryptoUtils.get_polynomial_from_points(points)

        # 6) Persist everything in the active session
        active["session_token_nonce2"]           = nonce2
        active["session_token_timestamp_T1"]     = T1
        active["session_token_tSecret_numeric"]  = t_secret
        active["token_polynomial_coeffs"]        = token_poly.coeffs.tolist()
        active["device_token_points"]            = device_points

        # ✦ HERE is the missing piece:
        active["legitimate_devices_for_this_token"] = legit_device_ids

        self._update_storage_key("active_session_info", active)
        app.logger.info(
            f"Token poly deg={len(token_poly.coeffs)-1} built in "
            f"{time.perf_counter()-start:.4f}s"
        )

        # 7) Encrypt and return the package for the leader
        sk_hex = self.storage.get(f"session_key_for_leader_{actual_leader}")
        if not sk_hex:
            return {"result": "FAILED", "reason": "Missing leader session key"}
        sk = bytes.fromhex(sk_hex)
        package = {
            "sessionID": self.current_session_id,
            "deviceTokenPoints": device_points,
            "timestamp": current_timestamp()
        }
        encrypted_pkg = CryptoUtils.encrypt_symmetric(sk, package)
        return {
            "result": "SUCCESS",
            "encrypted_token_package_for_leader": encrypted_pkg
        }



    def handle_authenticate_data(self, data_message, source_id):
        start = time.perf_counter()
        dev_id  = data_message.get("deviceID")
        sess_id = data_message.get("sessionID")
        ts      = data_message.get("timestamp", 0)

        # 1) Session & freshness
        active = self.storage.get("active_session_info") or {}
        if not active or sess_id != active.get("sessionID"):
            return {"result":"VERIFICATION_FAILED","reason":"Invalid session"}

        # 2) Authorization
        legit = active.get("legitimate_devices_for_this_token", [])
        if dev_id not in legit:
            return {"result":"VERIFICATION_FAILED","reason":"Not authorized"}

        # 3) Timestamp
        if abs(current_timestamp() - ts) > MAX_TIME_DRIFT:
            return {"result":"VERIFICATION_FAILED","reason":"Timestamp expired"}

        # 4) Fetch token point & check tokenX
        token_pt = active.get("device_token_points", {}).get(dev_id)
        if not token_pt:
            return {"result":"VERIFICATION_FAILED","reason":"Token point missing"}

        if data_message.get("tokenX") != token_pt["x"]:
            # rogue
            self._update_storage_key("last_auth_rogue_device", dev_id)
            self.current_session_id = None
            self._update_storage_key("active_session_info", None)
            return {"result":"VERIFICATION_FAILED","reason":"tokenX mismatch"}

        # 5) Derive decryption key—either via paddedKeyHex or by recomputing from share
        padded_hex = data_message.get("paddedKeyHex")
        if padded_hex:
            PAD_BYTES = 16
            try:
                padded_bytes = bytes.fromhex(padded_hex)
                # strip off the 16-byte pads
                raw_key_bytes = padded_bytes[PAD_BYTES:-PAD_BYTES]
            except Exception:
                return {"result":"VERIFICATION_FAILED",
                        "reason":"Invalid paddedKeyHex"}
        else:
            # fallback as before
            raw_key_bytes = int(token_pt["y"]).to_bytes(32, "big")

        # 6) Decrypt under ChaCha20-Poly1305
        try:
            plaintext = CryptoUtils.chacha20_decrypt(
                raw_key_bytes,
                data_message["nonce"],
                data_message["ciphertext"]
            )
        except Exception:
            # decryption or tag check failed → rogue
            self._update_storage_key("last_auth_rogue_device", dev_id)
            self.current_session_id = None
            self._update_storage_key("active_session_info", None)
            return {"result":"VERIFICATION_FAILED",
                    "reason":"Decryption/auth failed"}

        # 7) Log the cleartext
        data_logger.info(
            f"From {dev_id} @session={sess_id} ts={ts}: {plaintext!r}"
        )
        app.logger.info(f"Phase 6 Auth SUCCESS for {dev_id}")
        app.logger.info(
            f"PERF: Phase 6 Auth Data took {time.perf_counter() - start:.4f}s"
        )
        return {"result":"VERIFICATION_SUCCESSFUL"}


        
    
    def auto_adjust_thresholds(self):
        enrolled = self.storage.get("all_device_enrollment_data", {})
        # only those with x_numeric,y_numeric
        n = sum(1 for dev in self.device_urls
                if dev in enrolled and "x_numeric" in enrolled[dev])

        # update our in-memory counter
        self.num_total_devices = n

        # security: up to (t−1)-collusion resistant
        t1 = max(1, math.floor(n / 2) + 1)
        t2 = max(1, math.floor(n / 3) + 1)

        self.t_threshold_phase1       = t1
        self.delegation_threshold_t_prime = t2

        params = {
        "total_devices":      n,
        "t_phase1":           t1,
        "delegation_t_prime": t2
        }
        self._update_storage_key("parameters", params)

        return {
        "result":             "AUTO_THRESHOLDS_SET",
        "total_devices":      n,
        "t_phase1":           t1,
        "delegation_t_prime": t2
        }


FOG_NODE_INSTANCE = FogNodeSingleton()

@app.route("/auto_update_thresholds", methods=["POST"])
def route_auto_update_thresholds():
    """
    POST → recompute thresholds and return JSON.
    """
    try:
        result = FOG_NODE_INSTANCE.auto_adjust_thresholds()
        return jsonify(result), 200
    except Exception as e:
        app.logger.exception("auto_update_thresholds failed")
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "FogService is healthy"}), 200

@app.route("/register_device_phase1", methods=["POST"])
def route_register_device_phase1():
    data   = request.json or {}
    dev_id = data.get("id")
    if not dev_id:
        return jsonify({"error": "Device ID missing"}), 400

    # 1) store RSA PK + URL
    FOG_NODE_INSTANCE.devices_public_keys[dev_id] = data["public_key_pem"]
    FOG_NODE_INSTANCE.device_urls[dev_id] = data["url"]

    # 2) store enrollment data
    enroll = FOG_NODE_INSTANCE.storage.setdefault("all_device_enrollment_data", {})
    enroll[dev_id] = {
        "C":             data["enrollment_challenge"],
        "R":             data["puf_response_R"],
        "nonce":         data["enrollment_nonce"],
        "T0_device":     data["enrollment_T0_device"],
        "x_val_str":     data["coord_x_str"],
        "y_val_str":     data["coord_y_str"],
        "x_numeric":     data["coord_x_numeric"],
        "y_numeric":     data["coord_y_numeric"],
        "public_key_pem":data["public_key_pem"],
        "timestamp":     current_timestamp()
    }
    FOG_NODE_INSTANCE._update_storage_key("all_device_enrollment_data", enroll)

    # 3) if this is the configured leader, record its keys
    leader_cfg = FOG_NODE_INSTANCE.storage.get(
        "config_leader_id",
        FOG_NODE_INSTANCE.config_leader_id
    )
    if dev_id == leader_cfg:
        # RSA public key (for encrypting session key)
        FOG_NODE_INSTANCE._update_storage_key(
            "leader_public_key_pem", data["public_key_pem"]
        )
        FOG_NODE_INSTANCE._update_storage_key("leader_id", dev_id)

        # ← NEW: capture the Schnorr EC public key, if supplied
        if "public_key_ec" in data:
            FOG_NODE_INSTANCE._update_storage_key(
                "leader_public_key_ec", data["public_key_ec"]
            )

        app.logger.info(f"Device {dev_id} registered as LEADER")

    return jsonify({"message": f"Device {dev_id} registered"}), 200


@app.route("/trigger_phase1_polynomial_setup", methods=["POST"])
def route_trigger_phase1_setup():
    success, msg = FOG_NODE_INSTANCE.initialize_system_phase1()
    if success:
        return jsonify({
            "message": msg,
            "group_secret_S": FOG_NODE_INSTANCE.storage.get("group_secret_S")
        }), 200
    else:
        return jsonify({"error": msg}), 500

@app.route("/leader_auth_phase2", methods=["POST"])
def route_leader_auth_phase2():
    data = request.json
    res = FOG_NODE_INSTANCE.handle_verify_leader_identity(
        data, data.get("leader_id")
    )
    status = 200 if res.get("result") == "AUTHENTICATION_SUCCESSFUL" else 401
    return jsonify(res), status

@app.route("/delegate_shares_phase3", methods=["POST"])
def route_delegate_shares_phase3():
    data = request.json
    res = FOG_NODE_INSTANCE.handle_delegate_group_shares(
        data["member_ids"], data["group_token_value"], data["leader_id"]
    )
    return jsonify(res)

@app.route("/verify_group_poly_phase4", methods=["POST"])
def route_verify_group_poly_phase4():
    data = request.json
    res = FOG_NODE_INSTANCE.handle_verify_group_polynomial(
        data, data["leader_id"]
    )
    return jsonify(res)

@app.route("/generate_token_poly_phase5", methods=["POST"])
def route_generate_token_poly_phase5():
    data = request.json
    res = FOG_NODE_INSTANCE.handle_generate_token_polynomial(
        data["legit_device_ids"], data["leader_id"]
    )
    return jsonify(res)

@app.route("/authenticate_data_phase6", methods=["POST"])
def route_authenticate_data_phase6():
    data = request.json
    res = FOG_NODE_INSTANCE.handle_authenticate_data(
        data, data["deviceID"]
    )
    return jsonify(res)

@app.route("/get_device_urls", methods=["GET"])
def route_get_device_urls():
    if not FOG_NODE_INSTANCE.device_urls:
        FOG_NODE_INSTANCE._load_storage()
    return jsonify(FOG_NODE_INSTANCE.device_urls), 200

@app.route('/terminate_session', methods=['POST'])
def route_terminate_session():
    # wipes out active_session_info so everybody is forced to re-auth
    FOG_NODE_INSTANCE.current_session_id = None
    FOG_NODE_INSTANCE._update_storage_key('active_session_info', None)
    return jsonify({"result": "SESSION_TERMINATED"}), 200

@app.route('/remove_device', methods=['POST'])
def route_remove_device():
    """
    Remove a device from Fog entirely.  Also revoke its
    Phase-6 token if it’s in the active_session_info.
    """
    data = request.json or {}
    dev_id = data.get("device_id")
    if not dev_id:
        return jsonify({"error": "device_id required"}), 400

    # 0) If there’s an active session, strip this device out of it
    active = FOG_NODE_INSTANCE.storage.get("active_session_info") or {}
    legits = active.get("legitimate_devices_for_this_token", [])
    if dev_id in legits:
        # remove from the legit list
        legits.remove(dev_id)
        active["legitimate_devices_for_this_token"] = legits
        # also drop its token_point
        active.get("device_token_points", {}).pop(dev_id, None)
        FOG_NODE_INSTANCE._update_storage_key(
            "active_session_info", active
        )
        app.logger.info(f"Revoked device {dev_id} from active session")

    # 1) remove PK/URL/enrollment
    FOG_NODE_INSTANCE.devices_public_keys.pop(dev_id, None)
    FOG_NODE_INSTANCE.device_urls.pop(dev_id, None)
    FOG_NODE_INSTANCE.storage.get("all_device_enrollment_data", {})\
                    .pop(dev_id, None)

    # 2) persist removal
    FOG_NODE_INSTANCE._update_storage_key(
        "registered_devices_pks", FOG_NODE_INSTANCE.devices_public_keys
    )
    FOG_NODE_INSTANCE._update_storage_key(
        "registered_devices_urls", FOG_NODE_INSTANCE.device_urls
    )
    FOG_NODE_INSTANCE._update_storage_key(
        "all_device_enrollment_data",
        FOG_NODE_INSTANCE.storage.get("all_device_enrollment_data", {})
    )

    app.logger.info(f"Device {dev_id} fully removed from Fog")
    return jsonify({"result": f"{dev_id} removed"}), 200


@app.route('/status', methods=['GET'])
def route_status():
    fog = FOG_NODE_INSTANCE

    # registered / enrolled / pending
    registered = list(fog.devices_public_keys.keys())
    n = len(registered)
    enrolled_map = fog.storage.get("all_device_enrollment_data", {})
    enrolled   = [d for d in registered if d in enrolled_map]
    pending    = [d for d in registered if d not in enrolled]
    active     = fog.storage.get("active_session_info") or {}

    status = {
        # ← NEW: current parameters
        "parameters": {
            "total_devices": fog.num_total_devices,
            "t_phase1": fog.t_threshold_phase1,
            "delegation_t_prime": fog.delegation_threshold_t_prime
        },
        "registered_devices": registered,
        "enrolled_devices": enrolled,
        "pending_enrollment": pending,
        "active_session_info": active,
        "group_polynomial": {
            "defining_points": fog.storage.get("group_poly_P_defining_points"),
            "coeffs":           fog.storage.get("group_poly_P_coeffs"),
            "degree":           fog.storage.get("group_poly_P_degree"),
            "secret_S":         fog.storage.get("group_secret_S")
        },
        "delegation_poly_coeffs": fog.storage.get("group_delegation_poly_coeffs"),
        "device_offsets":         fog.storage.get("group_poly_P_device_offsets"),
        "suspicious_devices":     fog.storage.get("last_group_auth_suspicious_devices", [])
    }
    return jsonify(status), 200


@app.route("/update_thresholds", methods=["POST"])
def route_update_thresholds():
    """
    POST JSON: { "t_phase1": <int>, "delegation_t_prime": <int> }
    Dynamically change the fog’s Phase 1 threshold and/or delegation threshold.
    """
    data = request.json or {}
    t1 = data.get("t_phase1")
    t2 = data.get("delegation_t_prime")
    if t1 is None and t2 is None:
        return jsonify({
            "error": "Must provide at least one of 't_phase1' or 'delegation_t_prime'"
        }), 400

    # pull existing params
    params = FOG_NODE_INSTANCE.storage.get("parameters", {})

    # update Phase 1 threshold
    if t1 is not None:
        try:
            t1 = int(t1)
        except ValueError:
            return jsonify({"error": "t_phase1 must be an integer"}), 400
        FOG_NODE_INSTANCE.t_threshold_phase1 = t1
        params["t_phase1"] = t1

    # update delegation threshold
    if t2 is not None:
        try:
            t2 = int(t2)
        except ValueError:
            return jsonify({"error": "delegation_t_prime must be an integer"}), 400
        FOG_NODE_INSTANCE.delegation_threshold_t_prime = t2
        params["delegation_t_prime"] = t2

    # persist back
    FOG_NODE_INSTANCE._update_storage_key("parameters", params)

    return jsonify({
        "result": "THRESHOLDS_UPDATED",
        "parameters": params
    }), 200

@app.route("/revoke_device_token", methods=["POST"])
def route_revoke_device_token():
    """
    POST JSON: { "device_id": "<id>" }
    Remove <id> from the current session’s legitimate_devices
    and delete its token_point, so its Phase-6 messages will be rejected.
    """
    data    = request.json or {}
    dev_id  = data.get("device_id")
    if not dev_id:
        return jsonify({"error": "device_id required"}), 400

    active = FOG_NODE_INSTANCE.storage.get("active_session_info")
    if not active:
        return jsonify({"error": "no active session"}), 400

    legits = active.get("legitimate_devices_for_this_token", [])
    if dev_id not in legits:
        return jsonify({"error": f"{dev_id} not in session"}), 400

    # remove from legit‐list
    legits.remove(dev_id)
    active["legitimate_devices_for_this_token"] = legits
    # drop its token‐point entirely
    active.get("device_token_points", {}).pop(dev_id, None)

    FOG_NODE_INSTANCE._update_storage_key("active_session_info", active)
    return jsonify({"result": "DEVICE_REVOKED", "device_id": dev_id}), 200

if __name__ == "__main__":
    app.logger.info("Starting Fog Service…")
    storage_dir = os.path.join(os.getcwd(), "storage")
    os.makedirs(storage_dir, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
