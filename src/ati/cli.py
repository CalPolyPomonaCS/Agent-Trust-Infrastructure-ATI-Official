"""ati command line. Every command works on one org directory (--home, default ./ati-home)."""
import argparse
import json
import os
import sys

from .home import Home
from .identity import Agent, enroll
from .attestation import measure
from .audit import verify_log


def _runtime(a):
    if not a.model:
        return None
    with open(a.prompt_file, encoding="utf-8") as f:
        return measure(a.model, a.tool or [], f.read())


def cmd_init(h, a):
    ca = h.init(a.domain)
    print(f"created {h.path} for '{a.domain}'. Share this with partner orgs:")
    print(json.dumps(ca.bundle()))


def cmd_ca_bundle(h, a):
    print(json.dumps(h.ca().bundle()))


def cmd_trust_add(h, a):
    with open(a.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    h.save_trust(h.trust().add(bundle))
    print(f"now federating with '{bundle['trust_domain']}'")


def cmd_trust_revoke(h, a):
    t = h.trust()
    t.revoked.add(a.aid)
    h.save_trust(t)
    print(f"revoked {a.aid}")


def cmd_trust_list(h, a):
    print(json.dumps(h.trust().to_json(), indent=2))


def cmd_agent_issue(h, a):
    try:
        agent = h.agent(a.role)
    except FileNotFoundError:
        agent = Agent.generate(h.domain, a.role)
    enroll(agent, h.ca(), ttl=a.ttl, runtime=_runtime(a))
    h.save_agent(agent)
    print(f"issued {agent.sub} aid={agent.aid} (expires in {a.ttl}s)")


def cmd_policy_add(h, a):
    p = h.policy()
    p.rules.append({"allow": not a.deny, "orgs": a.org or ["*"], "roles": a.role or ["*"],
                    "actions": a.action or ["*"]})
    h.save_policy(p)
    print(json.dumps(p.rules[-1]))


def cmd_serve(h, a):
    import uvicorn
    from .proxy import create_app
    m = h.monitor(require_attestation=a.require_attestation, allowed_models=a.allow_model)
    uvicorn.run(create_app(m, a.upstream, a.public_url, a.public_path or (), max_body=a.max_body),
                host=a.host, port=a.port)


def cmd_call(h, a):
    import httpx
    from .client import ATIAuth
    body = a.data.encode() if a.data else b""
    auth = ATIAuth(h.agent(a.role), _runtime(a))
    r = httpx.request(a.method, a.url, content=body, auth=auth,
                      headers={"Content-Type": "application/json"} if a.data else None, timeout=120)
    print(r.status_code, r.text)
    sys.exit(0 if r.is_success else 1)


def cmd_audit_verify(h, a):
    ok, why = verify_log(a.log or os.path.join(h.path, "audit.jsonl"), h.audit_pub())
    print(("OK " if ok else "FAIL ") + why)
    sys.exit(0 if ok else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="ati")
    p.add_argument("--home", default=os.environ.get("ATI_HOME", "ati-home"))
    sub = p.add_subparsers(dest="cmd", required=True)

    def runtime_args(sp):
        sp.add_argument("--model", help="approved/running model, e.g. openai/gpt-4o-mini")
        sp.add_argument("--tool", action="append", help="tool identifier (repeat)")
        sp.add_argument("--prompt-file", help="system prompt file")

    s = sub.add_parser("init", help="create this org's CA, audit key, trust list, policy")
    s.add_argument("--domain", required=True, help="this org's trust domain, e.g. org1.example")
    s.set_defaults(f=cmd_init)
    sub.add_parser("ca-bundle", help="print this org's CA bundle for partners").set_defaults(f=cmd_ca_bundle)

    s = sub.add_parser("trust-add", help="federate with an org (its CA bundle file)")
    s.add_argument("bundle")
    s.set_defaults(f=cmd_trust_add)
    s = sub.add_parser("trust-revoke", help="revoke an agent ID")
    s.add_argument("aid")
    s.set_defaults(f=cmd_trust_revoke)
    sub.add_parser("trust-list").set_defaults(f=cmd_trust_list)

    s = sub.add_parser("agent-issue", help="create or renew an agent credential")
    s.add_argument("--role", required=True)
    s.add_argument("--ttl", type=int, default=24 * 3600)
    runtime_args(s)
    s.set_defaults(f=cmd_agent_issue)

    s = sub.add_parser("policy-add", help="append a policy rule (first match wins, default deny)")
    s.add_argument("--org", action="append", help="trust domain pattern")
    s.add_argument("--role", action="append")
    s.add_argument("--action", action="append", help='e.g. "POST /a2a", "POST /a2a/*" or "tool:db_read"')
    s.add_argument("--deny", action="store_true")
    s.set_defaults(f=cmd_policy_add)

    s = sub.add_parser("serve", help="run the checking proxy in front of an agent")
    s.add_argument("--upstream", required=True, help="the agent's own URL")
    s.add_argument("--public-url", required=True, help="how callers reach this proxy, e.g. https://agents.org2.example")
    s.add_argument("--public-path", action="append", help="path served without checks, e.g. /.well-known/agent-card.json")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--require-attestation", action="store_true")
    s.add_argument("--allow-model", action="append")
    s.add_argument("--max-body", type=int, default=10 * 2**20, help="largest request body in bytes")
    s.set_defaults(f=cmd_serve)

    s = sub.add_parser("call", help="send a signed request as one of this org's agents")
    s.add_argument("--role", required=True)
    s.add_argument("method")
    s.add_argument("url")
    s.add_argument("--data")
    runtime_args(s)
    s.set_defaults(f=cmd_call)

    s = sub.add_parser("audit-verify", help="check the audit log's chain and signatures")
    s.add_argument("--log")
    s.set_defaults(f=cmd_audit_verify)

    a = p.parse_args(argv)
    if getattr(a, "model", None) and not a.prompt_file:
        p.error("--model needs --prompt-file")
    a.f(Home(a.home), a)


if __name__ == "__main__":
    main()
