
import hashlib
import os
import json
import time
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.fernet import Fernet # For symmetric encryption
from scipy.interpolate import lagrange
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import numpy as np
from ecdsa import SigningKey, VerifyingKey, SECP256k1, ellipticcurve
from ecdsa.util import number_to_string, string_to_number

# --- Utility Functions ---
def current_timestamp():
    return int(time.time())

def generate_random_bits_hex(num_bytes):
    return os.urandom(num_bytes).hex()

def HASH(data_string):
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

class SimulatedPUF:
    def __init__(self, device_id):
        self.device_id = device_id
        self._puf_memory = {} # challenge -> response
        # Try to load existing PUF memory if storage is available
        # This part is tricky as PUF is per-device, and this util is shared.
        # PUF state should ideally be managed by the Device class itself using its own storage.
        # For now, keep it in-memory per PUF instance.

    def get_response(self, challenge):
        if challenge not in self._puf_memory:
            puf_material = f"{self.device_id}-{challenge}-{generate_random_bits_hex(4)}"
            self._puf_memory[challenge] = HASH(puf_material)
        return self._puf_memory[challenge]

class CryptoUtils:
    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(pk):
        return pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def serialize_private_key(prk): # For potential storage/debug, not usually done
        return prk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')


    @staticmethod
    def deserialize_public_key(pem_data):
        return serialization.load_pem_public_key(pem_data.encode('utf-8'))

    @staticmethod
    def deserialize_private_key(pem_data):
        return serialization.load_pem_private_key(pem_data.encode('utf-8'), password=None)


    @staticmethod
    def sign_data(private_key, data):
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        return private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()

    @staticmethod
    def verify_signature(public_key_pem, signature_hex, data):
        public_key = CryptoUtils.deserialize_public_key(public_key_pem)
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @staticmethod
    def generate_symmetric_key():
        return Fernet.generate_key()

    @staticmethod
    def encrypt_symmetric(key_bytes, data_dict):
        f = Fernet(key_bytes)
        data_bytes = json.dumps(data_dict).encode('utf-8')
        return f.encrypt(data_bytes).decode('utf-8')

    @staticmethod
    def decrypt_symmetric(key_bytes, encrypted_data_str):
        f = Fernet(key_bytes)
        decrypted_bytes = f.decrypt(encrypted_data_str.encode('utf-8'))
        return json.loads(decrypted_bytes.decode('utf-8'))

    @staticmethod
    def encrypt_asymmetric(public_key_pem, data_bytes):
        public_key = CryptoUtils.deserialize_public_key(public_key_pem)
        ciphertext = public_key.encrypt(
            data_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext.hex()

    @staticmethod
    def decrypt_asymmetric(private_key, encrypted_data_hex):
        data_bytes = bytes.fromhex(encrypted_data_hex)
        plaintext = private_key.decrypt(
            data_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    @staticmethod
    def interpolate_polynomial(points_xy, x_eval):
        x_coords = np.array([p[0] for p in points_xy], dtype=float)
        y_coords = np.array([p[1] for p in points_xy], dtype=float)
        if len(x_coords) != len(set(x_coords)):
            raise ValueError("X coordinates for Lagrange interpolation must be unique.")
        poly = lagrange(x_coords, y_coords)
        return poly(float(x_eval))

    @staticmethod
    def get_polynomial_from_points(points_xy):
        x_coords = np.array([p[0] for p in points_xy], dtype=float)
        y_coords = np.array([p[1] for p in points_xy], dtype=float)
        if len(x_coords) != len(set(x_coords)):
            raise ValueError("X coordinates for Lagrange interpolation must be unique.")
        return lagrange(x_coords, y_coords)

    @staticmethod
    def construct_sss_polynomial(secret_at_zero, degree):
        coeffs = [secret_at_zero] + [random.randint(1, 1000000) for _ in range(degree)]
        poly = np.poly1d(coeffs[::-1])
        return poly

    @staticmethod
    def evaluate_polynomial(poly_obj, x_val):
        return poly_obj(float(x_val))

    @staticmethod
    def generate_hmac(key_hex, message_str):
        key_bytes = bytes.fromhex(key_hex)
        message_bytes = message_str.encode('utf-8')
        import hmac as hmac_lib
        return hmac_lib.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
    
    @staticmethod
    def chacha20_encrypt(key: bytes, plaintext: str, aad: bytes = b"") -> dict:
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext.encode(), aad)
        return {
            "nonce": nonce.hex(),
            "ciphertext": ct.hex()
        }

    @staticmethod
    def chacha20_decrypt(key: bytes,
                         nonce_hex: str,
                         ciphertext_hex: str,
                         aad: bytes = b"") -> str:
        aead = ChaCha20Poly1305(key)
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ciphertext_hex)
        pt = aead.decrypt(nonce, ct, aad)
        return pt.decode()

    @staticmethod
    def generate_schnorr_key_pair():
        """
        Returns a (SigningKey, VerifyingKey) pair on secp256k1.
        """
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        return sk, vk

    @staticmethod
    def serialize_schnorr_vk(vk: VerifyingKey) -> str:
        # compressed form → 33 bytes → hex
        return vk.to_string("compressed").hex()

    @staticmethod
    def deserialize_schnorr_vk(hex_str: str) -> VerifyingKey:
        data = bytes.fromhex(hex_str)
        return VerifyingKey.from_string(data, curve=SECP256k1)

    @staticmethod
    def schnorr_prove(sk: SigningKey, statement: dict) -> dict:
        """
        Non-interactive Schnorr proof of knowledge of sk.
        statement: any dict → JSON-normalized as the “message”.
        Returns { R:hex, s:hex }.
        """
        # 1) hash the statement
        m = json.dumps(statement, sort_keys=True).encode()

        # 2) pick random r in [0, n)
        n = SECP256k1.order
        r = int.from_bytes(os.urandom(32), "big") % n

        # 3) compute R = r·G
        R_point = SECP256k1.generator * r
        # compressed encoding of R
        Rx = number_to_string(R_point.x(), SECP256k1.order)
        prefix = b"\x02" if (R_point.y() % 2)==0 else b"\x03"
        Rb = prefix + Rx

        # 4) get your public key in compressed form
        vk = sk.get_verifying_key()
        P_point = vk.pubkey.point
        Px = number_to_string(P_point.x(), SECP256k1.order)
        prefixP = b"\x02" if (P_point.y() % 2)==0 else b"\x03"
        Pb = prefixP + Px

        # 5) c = H(Rb || Pb || H(m))
        hm = hashlib.sha256(m).digest()
        c = int.from_bytes(hashlib.sha256(Rb + Pb + hm).digest(), "big") % n

        # 6) s = r + c·x  mod n
        x = sk.privkey.secret_multiplier
        s = (r + c * x) % n

        return {
            "R": Rb.hex(),
            "s": hex(s)
        }

    @staticmethod
    def schnorr_verify(vk_hex: str, proof: dict, statement: dict) -> bool:
        """
        Verify a Schnorr proof against the given statement.
        vk_hex: hex of compressed public key
        proof: { "R":hex, "s":hex }
        statement: same dict that prover used.
        """
        vk = CryptoUtils.deserialize_schnorr_vk(vk_hex)
        n = SECP256k1.order

        # decode proof
        Rb = bytes.fromhex(proof["R"])
        s = int(proof["s"], 16)

        # decompress R
        prefix = Rb[0]
        Rx = string_to_number(Rb[1:])
        curve = SECP256k1.curve
        # solve y² = x³ + ax + b  mod p
        p = curve.p()
        a = curve.a()
        b = curve.b()
        y2 = (Rx**3 + a*Rx + b) % p
        # sqrt mod p (p % 4 == 3 for secp256k1)
        y = pow(y2, (p+1)//4, p)
        if (y % 2 == 0 and prefix==3) or (y % 2==1 and prefix==2):
            y = p - y
        R_point = ellipticcurve.Point(curve, Rx, y)

        # recompute challenge
        m = json.dumps(statement, sort_keys=True).encode()
        hm = hashlib.sha256(m).digest()

        # get compressed P
        P_point = vk.pubkey.point
        Px = number_to_string(P_point.x(), n)
        prefixP = b"\x02" if (P_point.y() % 2)==0 else b"\x03"
        Pb = prefixP + Px

        c_prime = int.from_bytes(
            hashlib.sha256(Rb + Pb + hm).digest(), "big"
        ) % n

        # check s·G == R + c'·P
        left  = SECP256k1.generator * s
        right = R_point + (P_point * c_prime)
        return left == right
MAX_TIME_DRIFT = 60 # seconds
# Default config, can be overridden by env vars
FOG_NODE_URL = os.environ.get("FOG_NODE_URL", "http://fog_service:5000")
