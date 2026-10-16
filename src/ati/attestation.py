"""Attestation plane. The agent's own CA puts the approved runtime (model, tool
list, system-prompt hash) in the agent's WIT. On each request the agent sends an
Entity Attestation Token (EAT, RFC 9711) in JWT form, signed by its key, with
its current runtime and eat_nonce set to the request's WPT jti. The receiving
org checks it against the approved runtime.

The current runtime is reported by the agent's host, so this catches a swapped
model, tool, or prompt on an honest host, not a host that lies about what it runs."""
import time
from . import crypto
from .identity import RUNTIME_CLAIM

PROFILE = "urn:ati:eat-profile:v1"


def measure(model, tools, prompt):
    return {"model": model,
            "tools_sha256": crypto.sha256_hex(crypto.canonical(sorted(tools))),
            "prompt_sha256": crypto.sha256_hex(prompt.encode())}


def sign_attestation(agent, runtime, nonce):
    claims = {"eat_profile": PROFILE, "eat_nonce": nonce, "iat": int(time.time()), "sub": agent.sub,
              RUNTIME_CLAIM: runtime}
    return crypto.jwt_encode({"alg": "EdDSA", "typ": "eat+jwt"}, claims, agent.priv)


def verify_attestation(eat, wit_claims, nonce, allowed_models=None):
    approved = wit_claims.get(RUNTIME_CLAIM)
    if not approved:
        return False, "WIT has no approved runtime"
    try:
        header, claims, signing_input, sig = crypto.jwt_decode(eat)
        if header.get("typ") != "eat+jwt" or claims.get("eat_profile") != PROFILE:
            return False, "not an ATI eat+jwt"
        if not crypto.verify(crypto.jwk_pub(wit_claims["cnf"]["jwk"]), signing_input, sig):
            return False, "attestation not signed by the WIT's key"
        if claims["eat_nonce"] != nonce or claims["sub"] != wit_claims["sub"]:
            return False, "attestation not bound to this agent and request"
        current = claims[RUNTIME_CLAIM]
        for k in ("model", "tools_sha256", "prompt_sha256"):
            if current[k] != approved[k]:
                return False, f"{k.split('_')[0]} differs from the approved runtime"
    except (KeyError, TypeError, ValueError) as e:
        return False, f"malformed attestation ({e})"
    if allowed_models and current["model"] not in allowed_models:
        return False, f"model '{current['model']}' not accepted here"
    return True, "runtime matches approved"
