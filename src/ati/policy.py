"""Policy plane: first matching rule wins, default deny. An action is a string
such as "POST /a2a" for an inbound request or "tool:db_write" for a tool call.
Fields use shell-style wildcards and ignore case. "*" also matches "/", so
"POST /a2a*" matches /a2a/tasks and /a2abc; use "POST /a2a" and "POST /a2a/*"
to allow only /a2a and what is under it.

    {"rules": [{"allow": true, "orgs": ["org1.example"], "roles": ["advising"],
                "actions": ["POST /a2a", "tool:db_read"]}]}
"""
from fnmatch import fnmatchcase


def _match(patterns, value):
    return any(fnmatchcase(value.lower(), p.lower()) for p in patterns)


class Policy:
    def __init__(self, rules=None):
        self.rules = list(rules or [])

    @classmethod
    def from_json(cls, d):
        return cls(d.get("rules"))

    def to_json(self):
        return {"rules": self.rules}

    def check(self, org, role, action):
        for i, r in enumerate(self.rules):
            if _match(r.get("orgs", ["*"]), org) and _match(r.get("roles", ["*"]), role) \
                    and _match(r.get("actions", ["*"]), action):
                return bool(r.get("allow")), f"rule {i} {'allows' if r.get('allow') else 'denies'} {action}"
        return False, f"no rule allows {action} for {org}/{role}"
