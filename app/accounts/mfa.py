import time
import hmac
import hashlib
import struct
import base64
import secrets

def generate_mfa_secret():
    """
    Generate a secure 16-byte random secret encoded in Base32.
    """
    # 10 random bytes becomes 16 chars in base32 (perfect length for TOTP secrets)
    return base64.b32encode(secrets.token_bytes(10)).decode('utf-8')

def get_hotp_token(secret, intervals_no):
    """
    Compute standard HOTP token for a given intervals counter.
    """
    secret = secret.strip()
    # Ensure correct base32 padding
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
        
    try:
        key = base64.b32decode(secret, casefold=True)
    except Exception:
        # Fallback in case secret is invalid
        return "000000"
        
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"

def verify_totp(secret, code, window=1):
    """
    Verify a TOTP code against the secret, allowing a time window buffer.
    """
    if not secret or not code:
        return False
    # Standard 30-second time interval
    current_time = int(time.time()) // 30
    
    # Check current, previous, and next intervals
    for i in range(-window, window + 1):
        if get_hotp_token(secret, current_time + i) == code:
            return True
    return False
