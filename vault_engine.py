"""
CoreVault Security & Cryptography Engine
Version: 1.1.0 (Free & Open Edition with Anti-GPU Attack Verification)
Description: Provides authenticated encryption with hardware-bound key
derivation (scrypt + AES-256-CTR + HMAC-SHA256) and configurable
breach-response policies for protecting local files.

Note: the retry-lockout / auto-wipe policy only stops someone using this
app's own interface. Anyone with read access to a .abs_vault file could
write a separate script that calls scrypt + AES directly and brute-forces
the password outside this lockout logic entirely. The real security here
comes from password strength and scrypt's cost, not the attempt counter.

Install dependency:
    pip install cryptography
"""

import os
import sys
import time
import uuid
import hashlib
import hmac
import subprocess
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CHUNK_SIZE = 64 * 1024
SALT_SIZE = 16
NONCE_SIZE = 16   # AES block size, required for CTR mode
POLICY_SIZE = 16
TAG_SIZE = 32
FOOTER_SIZE = SALT_SIZE + NONCE_SIZE + POLICY_SIZE + TAG_SIZE  # 80 bytes


def get_hwid() -> str:
    """
    Builds a per-machine fingerprint used to bind a vault to 'this machine'.
    Not unspoofable (no software fingerprint truly is), but far more stable
    and higher-entropy than falling back to a username string.
    """
    entropy_pool = []
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                entropy_pool.append(winreg.QueryValueEx(key, "MachineGuid")[0])
        elif sys.platform == "linux" and os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as f:
                entropy_pool.append(f.read().strip())
        elif sys.platform == "darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
            ).decode(errors="ignore")
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    entropy_pool.append(line.split('"')[-2])
        entropy_pool.append(str(uuid.getnode()))
    except Exception:
        entropy_pool.append(str(uuid.getnode()))

    return hashlib.sha384("|".join(entropy_pool).encode("utf-8")).hexdigest()


# Kept for drop-in compatibility with main.py, which likely imports this name.
def get_immutable_hwid() -> str:
    return get_hwid()


def _derive_keys(passphrase: str, hw_token: str, salt: bytes):
    """
    scrypt is memory-hard: brute-forcing it at scale on a GPU/ASIC costs far
    more than the homemade hash-chaining loop it replaces. Produces 64 bytes,
    split into a dedicated AES key and a dedicated HMAC key so the same
    material is never reused for two different cryptographic purposes.
    """
    kdf = Scrypt(salt=salt, length=64, n=2 ** 15, r=8, p=1)
    material = kdf.derive((passphrase + "|" + hw_token).encode("utf-8"))
    return material[:32], material[32:]  # enc_key, mac_key


def _write_policy(file_path: str, file_size: int, policy: bytearray) -> None:
    """Rewrites only the mutable policy region. The HMAC tag never depends
    on `policy`, so this can never desynchronize verification."""
    with open(file_path, "r+b") as f:
        f.seek(file_size - FOOTER_SIZE + SALT_SIZE + NONCE_SIZE)
        f.write(bytes(policy))


def execute_tamper_proof_vault(
    file_path: str,
    passphrase: str,
    hw_token: str,
    mode: str = "lock",
    max_retries: int = 5,
    penalty_type: int = 1,
    cooldown_minutes: int = 15,
) -> tuple:
    temp_output = None
    try:
        if mode == "lock":
            salt = token_bytes(SALT_SIZE)
            nonce = token_bytes(NONCE_SIZE)
            enc_key, mac_key = _derive_keys(passphrase, hw_token, salt)
            policy = (
                bytes([max_retries, 0, penalty_type, cooldown_minutes])
                + (0).to_bytes(6, "big")
                + (0).to_bytes(6, "big")
            )

            cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            auth = hmac.new(mac_key, digestmod=hashlib.sha256)
            auth.update(nonce)

            temp_output = file_path + ".tmp"
            with open(file_path, "rb") as f_in, open(temp_output, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    ct = encryptor.update(chunk)
                    auth.update(ct)
                    f_out.write(ct)
                f_out.write(encryptor.finalize())

            tag = auth.digest()
            with open(temp_output, "ab") as f_out:
                f_out.write(salt + nonce + policy + tag)

            os.remove(file_path)
            os.rename(temp_output, file_path + ".abs_vault")
            return True, "File locked successfully (AES-256-CTR + HMAC-SHA256)."

        # ---- unlock ----
        if not file_path.endswith(".abs_vault"):
            return False, "DECRYPTION ABORT: file lacks the expected extension."

        file_size = os.path.getsize(file_path)
        if file_size < FOOTER_SIZE:
            return False, "DECRYPTION ABORT: vault file is corrupt or too small."

        with open(file_path, "rb") as f:
            f.seek(file_size - FOOTER_SIZE)
            footer = f.read(FOOTER_SIZE)

        salt = footer[:16]
        nonce = footer[16:32]
        policy = bytearray(footer[32:48])
        expected_tag = footer[48:80]

        max_r, attempts, p_type, cool_m = policy[0], policy[1], policy[2], policy[3]
        lockout_time = int.from_bytes(policy[4:10], "big")
        lockout_uptime = int.from_bytes(policy[10:16], "big")
        now = int(time.time())
        now_mono = int(time.monotonic())

        if p_type == 2 and lockout_time > 0:
            elapsed = min(now - lockout_time, now_mono - lockout_uptime)
            remaining = (cool_m * 60) - elapsed
            if remaining > 0:
                return False, f"COOLDOWN ACTIVE: try again in {int(remaining // 60) + 1} minute(s)."

        if p_type == 1 and attempts >= max_r:
            return False, "CRITICAL HALT: file was already destroyed by the breach policy."

        enc_key, mac_key = _derive_keys(passphrase, hw_token, salt)

        # Verify authenticity BEFORE trusting or writing any decrypted bytes.
        auth = hmac.new(mac_key, digestmod=hashlib.sha256)
        auth.update(nonce)
        remaining_bytes = file_size - FOOTER_SIZE
        with open(file_path, "rb") as f_in:
            while remaining_bytes > 0:
                chunk = f_in.read(min(CHUNK_SIZE, remaining_bytes))
                if not chunk:
                    break
                remaining_bytes -= len(chunk)
                auth.update(chunk)

        if not hmac.compare_digest(auth.digest(), expected_tag):
            policy[1] += 1  # wrong password or tampering

            if p_type == 1 and policy[1] >= max_r:
                with open(file_path, "wb") as f_shred:
                    f_shred.write(token_bytes(file_size))
                os.remove(file_path)
                return False, "BREACH DETECTED: max attempts reached, file destroyed per policy."

            if p_type == 2 and policy[1] >= max_r:
                policy[4:10] = now.to_bytes(6, "big")
                policy[10:16] = now_mono.to_bytes(6, "big")
                _write_policy(file_path, file_size, policy)
                return False, f"BREACH DETECTED: locked out for {cool_m} minute(s)."

            _write_policy(file_path, file_size, policy)
            return False, f"WRONG PASSWORD: {max_r - policy[1]} attempt(s) remaining."

        # Correct password: decrypt for real.
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        temp_output = file_path + ".dec_tmp"
        remaining_bytes = file_size - FOOTER_SIZE
        with open(file_path, "rb") as f_in, open(temp_output, "wb") as f_out:
            while remaining_bytes > 0:
                chunk = f_in.read(min(CHUNK_SIZE, remaining_bytes))
                if not chunk:
                    break
                remaining_bytes -= len(chunk)
                f_out.write(decryptor.update(chunk))
            f_out.write(decryptor.finalize())

        original_name = file_path[: -len(".abs_vault")]
        if os.path.exists(original_name):
            os.remove(original_name)
        os.rename(temp_output, original_name)
        os.remove(file_path)
        return True, "Password verified. File restored."

    except Exception as e:
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return False, f"UNHANDLED ERROR: {e}"
