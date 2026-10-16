"""Identity and trust planes. Each org is a trust domain (a DNS name such as
org1.example) with its own CA (AgentCA). The CA issues each agent a WIMSE
Workload Identity Token (WIT, draft-ietf-wimse-workload-creds-02):

    header  {"alg": "EdDSA", "typ": "wit+jwt", "kid": <CA key thumbprint>}
    claims  {"iss": "wimse://org1.example", "sub": "wimse://org1.example/advising",
             "iat", "exp", "jti", "cnf": {"jwk": <agent key>},
             "urn:ati:runtime": <approved model/tools/prompt, optional>}

Each request carries a Workload Proof Token (WPT, draft-ietf-wimse-wpt-02)
signed by the agent key, with one extra claim binding the method, path with
query, and body hash. Receivers keep a trust list of partner CAs; a CA may only
issue for its own trust domain."""
import hashlib
import heapq
import json
import os
import re
import time
from urllib.parse import urlsplit
from . import crypto

DEFAULT_TTL = 24 * 3600
WINDOW = 300
WPT_TTL = 60
RUNTIME_CLAIM = "urn:ati:runtime"
REQUEST_CLAIM = "urn:ati:req"
_ROLE = re.compile(r"^[A-Za-z0-9_-]+$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def check_domain(domain):
    if not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
        raise ValueError(f"'{domain}' is not a trust domain (use a DNS name such as org1.example)")
    return domain


def check_role(role):
    if not _ROLE.fullmatch(role):
        raise ValueError(f"'{role}' is not a role (use letters, digits, '_' and '-')")
    return role


def split_id(uri):
    """wimse://org1.example/advising -> ("org1.example", "advising")"""
    u = urlsplit(uri)
    if u.scheme != "wimse" or not u.netloc:
        raise ValueError(f"not a WIMSE identifier: {uri}")
    role = u.path.lstrip("/")
    return u.netloc, role and check_role(role)


class CA:
    """An org's certificate authority. It only issues for its own trust domain."""

    def __init__(self, domain, priv):
        self.domain = check_domain(domain)
        self.priv = priv
        self.jwk = crypto.jwk(crypto.public_bytes(priv))

    @classmethod
    def generate(cls, domain, seed=None):
        return cls(domain, crypto.generate_key(seed))

    def bundle(self):
        """What a partner org adds to its trust list."""
        return {"trust_domain": self.domain, "jwk": self.jwk}

    def issue(self, enroll_req, ttl=DEFAULT_TTL, runtime=None, now=None):
        """`runtime` is the approved measurement (attestation.measure) the agent must match."""
        key = enroll_req["jwk"]
        unsigned = {k: v for k, v in enroll_req.items() if k != "sig"}
        if not crypto.verify(crypto.jwk_pub(key), crypto.canonical(unsigned), crypto.ub64u(enroll_req["sig"])):
            raise ValueError("enrollment not signed by the key")
        domain, role = split_id(enroll_req["sub"])
        if domain != self.domain or not role:
            raise ValueError(f"this CA issues only for wimse://{self.domain}/<role>")
        iat = int(now or time.time())
        claims = {"iss": f"wimse://{self.domain}", "sub": enroll_req["sub"], "iat": iat, "exp": iat + ttl,
                  "jti": crypto.b64u(os.urandom(16)), "cnf": {"jwk": key}}
        if runtime:
            claims[RUNTIME_CLAIM] = runtime
        return self.sign(claims)

    def sign(self, claims):
        """Sign claims as-is (tests use this to build what a misbehaving CA could issue)."""
        return crypto.jwt_encode({"alg": "EdDSA", "typ": "wit+jwt", "kid": crypto.thumbprint(self.jwk)},
                                 claims, self.priv)


class Agent:
    def __init__(self, priv, domain, role, wit=None):
        self.priv = priv
        self.jwk = crypto.jwk(crypto.public_bytes(priv))
        self.aid = crypto.thumbprint(self.jwk)
        self.domain = check_domain(domain)
        self.role = check_role(role)
        self.wit = wit

    @property
    def sub(self):
        return f"wimse://{self.domain}/{self.role}"

    @classmethod
    def generate(cls, domain, role, seed=None):
        return cls(crypto.generate_key(seed), domain, role)

    def enroll_request(self):
        req = {"sub": self.sub, "jwk": self.jwk, "nonce": crypto.b64u(os.urandom(16)),
               "timestamp": int(time.time())}
        req["sig"] = crypto.b64u(crypto.sign(self.priv, crypto.canonical(req)))
        return req

    def sign_request(self, method, url, body=b"", now=None):
        """WPT for one HTTP request. `url` is the full target URL including query."""
        u = urlsplit(url)
        now = int(now or time.time())
        claims = {"aud": f"{u.scheme}://{u.netloc}{u.path or '/'}", "exp": now + WPT_TTL,
                  "jti": crypto.b64u(os.urandom(16)), "wth": crypto.token_hash(self.wit),
                  REQUEST_CLAIM: {"htm": method.upper(), "path": _path(u), "bh": _body_hash(body)}}
        return crypto.jwt_encode({"alg": "EdDSA", "typ": "wpt+jwt"}, claims, self.priv)


def _path(u):
    return (u.path or "/") + (f"?{u.query}" if u.query else "")


def _body_hash(body):
    return crypto.b64u(hashlib.sha256(body).digest())


def enroll(agent, ca, ttl=DEFAULT_TTL, runtime=None):
    agent.wit = ca.issue(agent.enroll_request(), ttl=ttl, runtime=runtime)
    return agent.wit


class TrustList:
    """Partner CAs (trust domain -> CA public key) plus revoked agent key thumbprints."""

    def __init__(self, cas=None, revoked=None):
        self.cas = dict(cas or {})
        self.revoked = set(revoked or [])

    def add(self, bundle):
        self.cas[check_domain(bundle["trust_domain"])] = bundle["jwk"]
        return self

    def to_json(self):
        return {"cas": self.cas, "revoked": sorted(self.revoked)}

    @classmethod
    def from_json(cls, d):
        return cls(d.get("cas"), d.get("revoked"))


class ReplayCache:
    """Proof token IDs seen so far, kept until the token expires. With a path,
    they are also written to a file so a restarted proxy still refuses them."""

    def __init__(self, path=None):
        self.path, self.seen, self.heap, self.lines = path, {}, [], 0
        if path and os.path.exists(path):
            now = time.time()
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        jti, exp = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if isinstance(jti, str) and type(exp) is int and exp >= now:
                        self._add(jti, exp)
            self._rewrite()

    def _rewrite(self):
        with open(self.path + ".tmp", "w", encoding="utf-8") as f:
            f.writelines(json.dumps([j, e]) + "\n" for j, e in self.seen.items())
        os.replace(self.path + ".tmp", self.path)
        self.lines = len(self.seen)

    def _add(self, jti, exp):
        self.seen[jti] = exp
        heapq.heappush(self.heap, (exp, jti))

    def check_and_add(self, jti, exp, now):
        while self.heap and self.heap[0][0] < now:
            del self.seen[heapq.heappop(self.heap)[1]]
        if jti in self.seen:
            return False
        self._add(jti, exp)
        if self.path and self.lines > 2 * len(self.seen) + 1000:
            self._rewrite()
        elif self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps([jti, exp]) + "\n")
            self.lines += 1
        return True


def verify_wit(wit, trust, now=None):
    """Returns (ok, reason, claims)."""
    now = int(now or time.time())
    try:
        header, claims, signing_input, sig = crypto.jwt_decode(wit)
        if header.get("typ") != "wit+jwt" or header.get("alg") != "EdDSA":
            return False, "not an EdDSA wit+jwt", None
        domain, _ = split_id(claims["iss"])
        ca_key = trust.cas.get(domain)
        if ca_key is None:
            return False, f"issuer '{domain}' is not federated", None
        if not crypto.verify(crypto.jwk_pub(ca_key), signing_input, sig):
            return False, "bad WIT signature", None
        sub_domain, role = split_id(claims["sub"])
        if sub_domain != domain or not role:
            return False, f"issuer '{domain}' not authoritative for '{claims['sub']}'", None
        if now > claims["exp"] or now < claims["iat"] - WINDOW:
            return False, "WIT expired or not yet valid", None
        crypto.jwk_pub(claims["cnf"]["jwk"])
        if crypto.thumbprint(claims["cnf"]["jwk"]) in trust.revoked:
            return False, "agent key revoked", None
    except (KeyError, TypeError, ValueError) as e:
        return False, f"malformed WIT ({e})", None
    return True, f"trusted via {domain}", claims


def verify_wpt(wpt, wit, wit_claims, method, target, body, replay=None, now=None):
    """`target` is the full URL the request was sent to, as this receiver is
    reachable (its public URL), including query."""
    now = int(now or time.time())
    try:
        header, claims, signing_input, sig = crypto.jwt_decode(wpt)
        key = wit_claims["cnf"]["jwk"]
        if header.get("typ") != "wpt+jwt" or header.get("alg") != key.get("alg", "EdDSA"):
            return False, "not a wpt+jwt matching the WIT key"
        if not crypto.verify(crypto.jwk_pub(key), signing_input, sig):
            return False, "request not signed by the WIT's key"
        u = urlsplit(target)
        if claims["aud"] != f"{u.scheme}://{u.netloc}{u.path or '/'}":
            return False, f"wrong audience '{claims['aud']}'"
        if not isinstance(claims["jti"], str) or type(claims["exp"]) is not int:
            return False, "proof token jti or exp has the wrong type"
        if now > claims["exp"] or claims["exp"] > now + WINDOW:
            return False, "proof token expired or too long-lived"
        if claims["wth"] != crypto.token_hash(wit):
            return False, "proof token is for a different WIT"
        req = claims[REQUEST_CLAIM]
        if (req["htm"], req["path"], req["bh"]) != (method.upper(), _path(u), _body_hash(body)):
            return False, "signed request does not match the HTTP request"
        if replay is not None and not replay.check_and_add(claims["jti"], claims["exp"], now):
            return False, "replayed request"
    except (KeyError, TypeError, ValueError) as e:
        return False, f"malformed proof token ({e})"
    return True, "request verified"
