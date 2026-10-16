"""Primitives: Ed25519, SHA-256, base64url, canonical JSON, JWK, compact JWS."""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

_RAW = serialization.Encoding.Raw


def generate_key(seed=None):
    if seed is None:
        return Ed25519PrivateKey.generate()
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def private_bytes(priv):
    return priv.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def load_key(raw):
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_bytes(priv):
    return priv.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)


def sign(priv, data):
    return priv.sign(data)


def verify(pub, data, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def ub64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def jwk(pub):
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub), "alg": "EdDSA"}


def jwk_pub(key):
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 keys are supported")
    return ub64u(key["x"])


def thumbprint(key):
    """RFC 7638 JWK thumbprint."""
    return b64u(hashlib.sha256(canonical({k: key[k] for k in ("crv", "kty", "x")})).digest())


def jwt_encode(header, claims, priv):
    signing_input = b64u(canonical(header)) + "." + b64u(canonical(claims))
    return signing_input + "." + b64u(sign(priv, signing_input.encode()))


def jwt_decode(token):
    """Split and parse a compact JWS without checking it. Returns
    (header, claims, signing_input, signature)."""
    h, c, s = token.split(".")
    return json.loads(ub64u(h)), json.loads(ub64u(c)), (h + "." + c).encode(), ub64u(s)


def token_hash(token):
    return b64u(hashlib.sha256(token.encode("ascii")).digest())
