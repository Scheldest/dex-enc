import hashlib
import struct
from typing import Optional, Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class DexCrypter:
    _MAGIC = b"DEX1"
    _MAGIC_V2 = b"DEX2"

    def __init__(self, password):
        if isinstance(password, bytes):
            self._password_bytes = password
        else:
            self._password_bytes = str(password).encode("utf-8")

    def _derive_key_v1(self) -> bytes:
        # Legacy: hash password langsung jadi 32 byte (cepat, kurang tahan brute-force)
        return hashlib.sha256(self._password_bytes).digest()

    def _derive_key_v2(self, salt: bytes, iterations: int) -> bytes:
        # PBKDF2-HMAC-SHA256 untuk memperlambat brute-force password
        return hashlib.pbkdf2_hmac("sha256", self._password_bytes, salt, iterations, dklen=32)

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        # V2 format (recommended): per-message salt + PBKDF2 agar lebih kuat terhadap brute-force.
        salt = get_random_bytes(16)
        iterations = 200_000
        key = self._derive_key_v2(salt, iterations)

        # Pakai nonce 12-byte (standar GCM) agar parsing stabil lintas versi/platform.
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)

        # Format: MAGIC(4) + salt_len(1) + nonce_len(1) + tag_len(1) + iter_u32be(4) + salt + nonce + tag + ciphertext
        return (
            self._MAGIC_V2
            + bytes([len(salt), len(nonce), len(tag)])
            + struct.pack(">I", iterations)
            + salt
            + nonce
            + tag
            + ciphertext
        )

    def decrypt(self, raw_data: bytes) -> Optional[bytes]:
        try:
            if not isinstance(raw_data, (bytes, bytearray)):
                return None

            raw = bytes(raw_data)

            # Format V2 (recommended)
            if len(raw) >= 11 and raw[:4] == self._MAGIC_V2:
                salt_len = raw[4]
                nonce_len = raw[5]
                tag_len = raw[6]
                iterations = struct.unpack(">I", raw[7:11])[0]
                header_len = 11

                if salt_len < 8 or salt_len > 64:
                    return None
                if nonce_len < 8 or nonce_len > 32:
                    return None
                if tag_len < 12 or tag_len > 16:
                    return None
                if iterations < 10_000 or iterations > 5_000_000:
                    return None
                if len(raw) < header_len + salt_len + nonce_len + tag_len:
                    return None

                salt_start = header_len
                nonce_start = salt_start + salt_len
                tag_start = nonce_start + nonce_len
                ct_start = tag_start + tag_len

                salt = raw[salt_start:nonce_start]
                nonce = raw[nonce_start:tag_start]
                tag = raw[tag_start:ct_start]
                ciphertext = raw[ct_start:]

                key = self._derive_key_v2(salt, iterations)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=tag_len)
                return cipher.decrypt_and_verify(ciphertext, tag)

            # Format V1 (legacy)
            if len(raw) >= 6 and raw[:4] == self._MAGIC:
                nonce_len = raw[4]
                tag_len = raw[5]
                header_len = 6
                if nonce_len < 8 or nonce_len > 32:
                    return None
                if tag_len < 12 or tag_len > 16:
                    return None
                if len(raw) < header_len + nonce_len + tag_len:
                    return None

                nonce_start = header_len
                tag_start = nonce_start + nonce_len
                ct_start = tag_start + tag_len

                nonce = raw[nonce_start:tag_start]
                tag = raw[tag_start:ct_start]
                ciphertext = raw[ct_start:]

                key = self._derive_key_v1()
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=tag_len)
                return cipher.decrypt_and_verify(ciphertext, tag)

            # Fallback format lama: nonce(16) + tag(16) + ciphertext
            if len(raw) < 32:
                return None
            nonce = raw[:16]
            tag = raw[16:32]
            ciphertext = raw[32:]
            key = self._derive_key_v1()
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return None

    def decrypt_text(self, raw_data: bytes, encoding: str = "utf-8") -> Optional[str]:
        decrypted = self.decrypt(raw_data)
        if decrypted is None:
            return None
        try:
            return decrypted.decode(encoding)
        except UnicodeDecodeError:
            return None
