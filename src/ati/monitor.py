"""The reference monitor: every inbound request and every tool call passes here.
Order: identity and trust, attestation, policy. Every decision is logged.

Request headers (lower-case):
    workload-identity-token   the caller's WIT
    authorization             "WPT <proof token>"
    ati-attestation           the caller's EAT (when attestation is used)
"""
from urllib.parse import unquote, urlsplit
from . import crypto
from .identity import RUNTIME_CLAIM, ReplayCache, verify_wit, verify_wpt, split_id
from .attestation import verify_attestation

WIT, AUTH, ATTESTATION = "workload-identity-token", "authorization", "ati-attestation"


class Monitor:
    def __init__(self, trust, policy, audit, require_attestation=False, allowed_models=None, replay=None):
        self.trust = trust
        self.policy = policy
        self.audit = audit
        self.require_attestation = require_attestation
        self.allowed_models = allowed_models
        self.replay = replay or ReplayCache()

    def check_request(self, headers, method, target, body):
        """`target` is the full URL as this org publishes it, with query.
        Returns (allowed, http_status, reason, peer) where peer is the verified
        {"aid", "org", "role", "sub"} or None."""
        try:
            ok, status, why, peer = self._check(headers, method, target, body)
        except Exception as e:
            ok, status, why, peer = False, 401, f"[identity] malformed token ({type(e).__name__})", None
        self.audit.record(kind="request", decision="allow" if ok else "deny", reason=why,
                          method=method, target=target, body_sha256=crypto.sha256_hex(body),
                          peer=peer)
        return ok, status, why, peer

    def _check(self, headers, method, target, body):
        path = urlsplit(target).path or "/"
        if not _normal(path):
            return False, 400, "[policy] path has '.', '..', '//', ';', an encoded slash or non-ASCII", None
        wit, auth = headers.get(WIT), headers.get(AUTH, "")
        if not wit or not auth.startswith("WPT "):
            return False, 401, "[identity] no credential presented", None
        ok, why, claims = verify_wit(wit, self.trust)
        if not ok:
            return False, 401, f"[trust] {why}", None
        wpt = auth[4:].strip()
        ok, why = verify_wpt(wpt, wit, claims, method, target, body, self.replay)
        if not ok:
            return False, 401, f"[identity] {why}", None
        org, role = split_id(claims["sub"])
        peer = {"aid": crypto.thumbprint(claims["cnf"]["jwk"]), "org": org, "role": role, "sub": claims["sub"]}
        if self.require_attestation or self.allowed_models or RUNTIME_CLAIM in claims or ATTESTATION in headers:
            if ATTESTATION not in headers:
                return False, 403, "[attestation] no attestation presented", peer
            ok, why = verify_attestation(headers[ATTESTATION], claims, crypto.jwt_decode(wpt)[1]["jti"],
                                         self.allowed_models)
            if not ok:
                return False, 403, f"[attestation] {why}", peer
        ok, why = self.policy.check(org, role, f"{method.upper()} {unquote(path)}")
        if not ok:
            return False, 403, f"[policy] {why}", peer
        return True, 200, "allowed", peer

    def check_tool(self, peer, tool):
        """Per-tool-call check for a request that already passed check_request."""
        ok, why = self.policy.check(peer["org"], peer["role"], f"tool:{tool}")
        self.audit.record(kind="tool", decision="allow" if ok else "deny", reason=why, tool=tool, peer=peer)
        return ok, why


def _normal(path):
    """True when the path means the same thing before and after an upstream
    decodes and normalizes it, so policy and the agent see the same path."""
    p = unquote(path)
    return p.isascii() and "//" not in p and "\\" not in p and ";" not in p and "%2f" not in path.lower() and "%5c" not in path.lower() \
        and not any(s in (".", "..") for s in p.split("/"))
