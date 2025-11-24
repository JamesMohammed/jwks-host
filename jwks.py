import json   
import base64   
import sys   
import hashlib   
from cryptography.hazmat.primitives import serialization   
from cryptography.hazmat.primitives.asymmetric import rsa   
from cryptography.hazmat.backends import default_backend

def generate_kid(pem_key: str) -> str:   
    """Generate a 16-character key ID (kid) from SHA-256 hash of the PEM key."""   
    return hashlib.sha256(pem_key.encode()).hexdigest()[:16]   
   
def b64url_encode(data: bytes) -> str:   
    """Base64url encode without padding."""   
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")   
   
def generate_jwk_from_pem(pem_key: str, alg: str = "RS384") -> dict:   
    """Generate a JWK dict from a PEM-encoded RSA public key."""   
    public_key = serialization.load_pem_public_key(pem_key.encode(), backend=default_backend())   
   
    if not isinstance(public_key, rsa.RSAPublicKey):   
        raise ValueError("Provided key is not an RSA public key")   
   
    numbers = public_key.public_numbers()   
   
    # Do NOT add leading 0x00 - jwt.io can't handle it   
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')   
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')   
   
    jwk = {   
        "kty": "RSA",   
        "use": "sig",   
        "alg": alg,   
        "n": b64url_encode(n_bytes),   
        "e": b64url_encode(e_bytes),   
        "key_ops": ["verify"],   
        "ext": True,   
        "kid": generate_kid(pem_key)   
    }   
   
    return jwk   
   
if __name__ == "__main__":   
    if len(sys.argv) != 2:   
        print("Usage: python generate_jwk.py <public_key.pem>")   
        sys.exit(1)   
   
    # Load PEM public key   
    with open(sys.argv[1], "r") as f:   
        pem_key = f.read()   
   
    # Generate JWK and wrap in a JWKS object if needed   
    jwk = generate_jwk_from_pem(pem_key)   
    print(json.dumps(jwk, indent=4))   
   
