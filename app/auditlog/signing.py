from django.core import signing
from django.urls import reverse

def generate_signed_url(url_name, args=None, kwargs=None, expiry_seconds=300):
    """
    Generates a cryptographically signed URL with an expiration timestamp.
    """
    base_url = reverse(url_name, args=args, kwargs=kwargs)
    signer = signing.TimestampSigner()
    token = signer.sign(base_url)
    separator = '&' if '?' in base_url else '?'
    return f"{base_url}{separator}sig={token}"

def verify_signed_url(path, sig, max_age=300):
    """
    Verifies that the signature matches the request path and is not expired.
    """
    if not sig:
        return False
    signer = signing.TimestampSigner()
    try:
        unsigned_path = signer.unsign(sig, max_age=max_age)
        # Ensure the signed path matches the request path exactly
        return unsigned_path == path
    except (signing.BadSignature, signing.SignatureExpired):
        return False
