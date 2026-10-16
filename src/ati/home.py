"""An org's ATI directory:

    org.json        {"trust_domain": "org1.example"}
    ca.key          CA private key (keep offline in production)
    audit.key       key that signs the audit log
    trust.json      federated CAs and revoked agent IDs
    policy.json     policy rules
    agents/<role>.json   agent key + credential
    audit.jsonl     the audit log
    replay.jsonl    proof token IDs seen recently (so a restart does not allow replays)
"""
import json
import os
from . import crypto
from .identity import CA, Agent, ReplayCache, TrustList, check_role
from .policy import Policy
from .audit import AuditLog
from .monitor import Monitor


class Home:
    def __init__(self, path):
        self.path = path

    def _p(self, *parts):
        return os.path.join(self.path, *parts)

    def _read(self, name):
        with open(self._p(name), encoding="utf-8") as f:
            return json.load(f)

    def _write(self, name, obj, private=False):
        os.makedirs(os.path.dirname(self._p(name)), exist_ok=True)
        fd = os.open(self._p(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)

    def _key(self, name):
        return crypto.load_key(crypto.ub64u(self._read(name)["key"]))

    def init(self, domain):
        if os.path.exists(self._p("org.json")):
            raise SystemExit(f"{self.path} is already set up")
        ca = CA.generate(domain)
        self._write("org.json", {"trust_domain": ca.domain})
        self._write("ca.key", {"key": crypto.b64u(crypto.private_bytes(ca.priv))}, private=True)
        self._write("audit.key", {"key": crypto.b64u(crypto.private_bytes(crypto.generate_key()))}, private=True)
        self.save_trust(TrustList().add(ca.bundle()))
        self.save_policy(Policy())
        return ca

    @property
    def domain(self):
        return self._read("org.json")["trust_domain"]

    def ca(self):
        return CA(self.domain, self._key("ca.key"))

    def audit_pub(self):
        return crypto.public_bytes(self._key("audit.key"))

    def trust(self):
        return TrustList.from_json(self._read("trust.json"))

    def save_trust(self, trust):
        self._write("trust.json", trust.to_json())

    def policy(self):
        return Policy.from_json(self._read("policy.json"))

    def save_policy(self, policy):
        self._write("policy.json", policy.to_json())

    def agent(self, role):
        d = self._read(os.path.join("agents", f"{check_role(role)}.json"))
        return Agent(crypto.load_key(crypto.ub64u(d["key"])), d["trust_domain"], d["role"], d.get("wit"))

    def save_agent(self, agent):
        self._write(os.path.join("agents", f"{agent.role}.json"),
                    {"trust_domain": agent.domain, "role": agent.role, "aid": agent.aid,
                     "key": crypto.b64u(crypto.private_bytes(agent.priv)), "wit": agent.wit},
                    private=True)

    def monitor(self, require_attestation=False, allowed_models=None):
        return Monitor(self.trust(), self.policy(),
                       AuditLog(self._p("audit.jsonl"), self._key("audit.key")),
                       require_attestation, allowed_models, ReplayCache(self._p("replay.jsonl")))
