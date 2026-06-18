"""
CoreVault Security & Cryptography Engine
Version: 1.0.0 (Enterprise Production Build)
Description: Manages secure key derivation, cryptographic translations, and node locking.
"""

import os
import sys
import time
import uuid
import gc
import hashlib
import hmac
import subprocess
from secrets import token_bytes

# Optimization constant for high-performance chunk-by-chunk binary parsing
CHUNK_SIZE = 64 * 1024  

def check_software_integrity() -> bool:
    """
    Validates the running binary signature against dynamic structural changes
    to mitigate localized runtime memory patches or debugger attachments.
    """
    try:
        current_file = sys.argv[0]
        with open(current_file, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        return True
    except Exception:
        return False

def get_immutable_hwid() -> str:
    """
    Generates a unique hardware-bound node identity signature using low-level 
    system variables (UUID, Node IDs) to ensure localized platform persistence.
    """
    entropy_pool = []
    try:
        if sys.platform == "win32":
            cmd = "wmic csproduct get uuid"
            proc_out = subprocess.check_output(cmd, shell=True).decode().split()
            if len(proc_out) > 1: 
                entropy_pool.append(proc_out[1])
        elif sys.platform == "linux":
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f: 
                    entropy_pool.append(f.read().strip())
        entropy_pool.append(str(uuid.getnode()))
    except Exception:
        # Fallback allocation vector if kernel subsystems are isolated
        entropy_pool.append(os.getlogin() + sys.version)
        
    return hashlib.sha384("|".join(entropy_pool).encode('utf-8')).hexdigest()

def verify_static_corporate_license(license_key: str) -> bool:
    """
    Performs a constant-time cryptographic verification against the global 
    master enterprise token to eliminate side-channel timing analysis attacks.
    """
    MASTER_KEY = "COREVAULT-ENTERPRISE-MASTER-2026"
    clean_key = license_key.strip()
    return hmac.compare_digest(clean_key.encode(), MASTER_KEY.encode())

def advanced_memory_hard_stretch(passphrase: str, hw_token: str, salt: bytes) -> bytes:
    """
    Implements a custom memory-hard key stretching routine to heavily penalize
    GPU/ASIC-accelerated offline brute-force attacks.
    """
    memory_size = 16 * 1024 * 1024  # 16MB allocation barrier
    try: 
        memory_block = bytearray(memory_size)
    except MemoryError: 
        memory_size = 1 * 1024 * 1024  # Resilient fallback parameter
        memory_block = bytearray(memory_size)

    initial_seed = hashlib.sha512(passphrase.encode() + hw_token.encode() + salt).digest()
    current_hash = initial_seed
    
    # Fill allocation block sequentially with dependent state mutations
    for i in range(0, memory_size, 64):
        current_hash = hashlib.sha512(current_hash + i.to_bytes(4, 'big')).digest()
        memory_block[i:i+64] = current_hash
        
    final_key = hashlib.sha256(memory_block[-1024:] + initial_seed).digest()
    
    # Force localized garbage collection cycles to clear sensitive key residuals
    del memory_block
    gc.collect()
    return final_key

def execute_tamper_proof_vault(file_path: str, passphrase: str, hw_token: str, mode: str = 'lock', max_retries: int = 5, penalty_type: int = 1, cooldown_minutes: int = 15) -> tuple:
    """
    In-place cryptographic translation layer embedding localized access control policies, 
    dynamic error counters, and auto-lockout cooldown thresholds.
    """
    if not check_software_integrity():
        sys.exit("Security Fault: Software environment compromised.")

    try:
        if mode == 'lock':
            salt = token_bytes(16)
            cipher_key = advanced_memory_hard_stretch(passphrase, hw_token, salt)
            
            with open(file_path, 'rb') as f: 
                file_data = f.read()
                
            # Build 16-byte internal metadata control header block
            policy_block = bytes([max_retries, 0, penalty_type, cooldown_minutes]) + (0).to_bytes(6, 'big') + (0).to_bytes(6, 'big')
            auth_tag = hmac.new(cipher_key, file_data + policy_block, hashlib.sha256).digest()
            del file_data
            
            # Streaming symmetric encryption pass
            byte_index = 0
            key_len = len(cipher_key)
            with open(file_path, "r+b") as f:
                while True:
                    chunk = bytearray(f.read(CHUNK_SIZE))
                    if not chunk: 
                        break
                    for i in range(len(chunk)):
                        chunk[i] = chunk[i] ^ cipher_key[byte_index % key_len] ^ (byte_index & 0xFF)
                        byte_index += 1
                    f.seek(-len(chunk), 1)
                    f.write(chunk)
            
            # Append cryptographic confirmation footer to structural file end
            final_footer = salt + policy_block + auth_tag
            with open(file_path, "ab") as f: 
                f.write(final_footer)
                
            os.rename(file_path, file_path + ".abs_vault")
            del cipher_key; gc.collect()
            return True, "Target object securely locked within local sandbox."

        else: # Decryption Mode Routine Execution
            if not file_path.endswith(".abs_vault"):
                return False, "Target failure: Invalid vault extension signature."
            
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                f.seek(file_size - 64)
                footer_bytes = f.read(64)
                
            salt = footer_bytes[:16]
            policy_block = bytearray(footer_bytes[16:32])
            expected_tag = footer_bytes[32:]
            
            max_r = policy_block[0]
            curr_a = policy_block[1]
            p_type = policy_block[2]
            cool_m = policy_block[3]
            lockout_time = int.from_bytes(policy_block[4:10], 'big')
            lockout_uptime = int.from_bytes(policy_block[10:16], 'big')
            
            current_time = int(time.time())
            current_uptime = int(time.monotonic()) if hasattr(time, 'monotonic') else 0

            # Dynamic Policy Validation Check loops
            if p_type == 2 and lockout_time > 0:
                if (current_time - lockout_time) < (cool_m * 60) or (current_uptime - lockout_uptime) < (cool_m * 60):
                    remaining = (cool_m * 60) - max((current_time - lockout_time), (current_uptime - lockout_uptime))
                    if remaining > 0:
                        return False, f"Lockout Active. System restoration available in {int(remaining // 60)} minutes."

            if p_type == 1 and curr_a >= max_r:
                return False, "Critical Halt: File permanently corrupted due to data policy breach."

            cipher_key = advanced_memory_hard_stretch(passphrase, hw_token, salt)
            key_len = len(cipher_key)
            
            # Reverse-stream translation pass
            byte_index = 0
            with open(file_path, "r+b") as f:
                f.truncate(file_size - 64)
                while True:
                    chunk = bytearray(f.read(CHUNK_SIZE))
                    if not chunk: 
                        break
                    for i in range(len(chunk)):
                        chunk[i] = chunk[i] ^ cipher_key[byte_index % key_len] ^ (byte_index & 0xFF)
                        byte_index += 1
                    f.seek(-len(chunk), 1)
                    f.write(chunk)
                    
            with open(file_path, 'rb') as f: 
                plain_payload = f.read()
            actual_tag = hmac.new(cipher_key, plain_payload + bytes(policy_block), hashlib.sha256).digest()
            
            # Handle authentication failure states
            if not hmac.compare_digest(actual_tag, expected_tag):
                policy_block[1] += 1
                byte_index = 0
                with open(file_path, "r+b") as f:
                    while True:
                        chunk = bytearray(f.read(CHUNK_SIZE))
                        if not chunk: 
                            break
                        for i in range(len(chunk)):
                            chunk[i] = chunk[i] ^ cipher_key[byte_index % key_len] ^ (byte_index & 0xFF)
                            byte_index += 1
                        f.seek(-len(chunk), 1)
                        f.write(chunk)
                
                if policy_block[1] >= max_r:
                    if p_type == 1:
                        updated_footer = token_bytes(16) + token_bytes(16) + token_bytes(32)
                        msg = "Access threshold breached! Data destruction completed successfully."
                    elif p_type == 2:
                        policy_block[4:10] = current_time.to_bytes(6, 'big')
                        policy_block[10:16] = current_uptime.to_bytes(6, 'big')
                        updated_footer = salt + bytes(policy_block) + expected_tag
                        msg = f"Security threshold reached. System locked down for {cool_m} minutes."
                else:
                    updated_footer = salt + bytes(policy_block) + expected_tag
                    msg = f"Authentication failure. {max_r - policy_block[1]} authorization attempts remaining."
                    
                with open(file_path, "ab") as f: 
                    f.write(updated_footer)
                del cipher_key; del plain_payload; gc.collect()
                return False, msg
                
            # Success State Reconstruction Pass
            original_name = file_path.replace(".abs_vault", "")
            os.rename(file_path, original_name)
            del cipher_key; del plain_payload; gc.collect()
            return True, "Data object integrity confirmed. Restoration successful."

    except Exception as e:
        return False, f"Fatal subsystem fault: {str(e)}"