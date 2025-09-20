import os, json, base64
from datetime import datetime
import secrets

LOG_PATH = os.path.join(
    os.getcwd(),
    "storage",
    "unencrypted_phase6.jsonl"
)

def record(device_id: str,
           session_id: str,
           nonce_hex: str,
           ciphertext_hex: str,
           key_padded_hex: str,
           key_unpadded_hex: str,
           key_bytes: bytes):
    """
    Append one JSON line with:
      • timestamp (UTC ISO)
      • device_id, session_id
      • nonce_hex, ciphertext_hex
      • key_padded_hex   (64 hex chars)
      • key_unpadded_hex (no left‐zero padding)
      • key_bytes_list   (list of 32 ints)
      • nonce_bytes_list (list of 12 ints)
    """
    # turn raw bytes into lists of ints
    key_bytes_list   = list(key_bytes)                      # 32 ints
    nonce_bytes_list = list(bytes.fromhex(nonce_hex))       # 12 ints

    entry = {
        "timestamp":         datetime.utcnow().isoformat() + "Z",
        "device_id":         device_id,
        "session_id":        session_id,
        "nonce_hex":         nonce_hex,
        "ciphertext_hex":    ciphertext_hex,
        "key_padded_hex":    key_padded_hex,
        "key_unpadded_hex":  key_unpadded_hex,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
