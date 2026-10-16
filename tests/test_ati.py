"""Two orgs, a real proxy in front of a fake agent, and the attacks it must stop."""
import asyncio
import json
import time
from urllib.parse import unquote
import httpx
import pytest
from starlette.testclient import TestClient

from ati import CA, Agent, crypto, enroll, measure, verify_log
from ati.client import ATIAuth, sign_headers
from ati.home import Home
from ati.proxy import create_app

PROMPT = "You are the Advising agent."
RUNTIME = measure("openai/gpt-4o-mini", ["db_read"], PROMPT)
BASE = "http://testserver"


def echo(request):
    return httpx.Response(200, json={"peer": request.headers.get("x-ati-peer-org"),
                                     "role": request.headers.get("x-ati-peer-role"),
                                     "auth": request.headers.get("authorization"),
                                     "body": request.content.decode()})


@pytest.fixture
def orgs(tmp_path):
    o1, o2 = Home(str(tmp_path / "org1")), Home(str(tmp_path / "org2"))
    ca1 = o1.init("org1.example")
    o2.init("org2.example")
    o2.save_trust(o2.trust().add(ca1.bundle()))
    p = o2.policy()
    p.rules = [{"allow": False, "orgs": ["*"], "actions": ["DELETE *"]},
               {"allow": True, "orgs": ["org1.example"], "roles": ["advising"],
                "actions": ["POST /a2a", "GET /a2a"]}]
    o2.save_policy(p)
    agent = Agent.generate("org1.example", "advising")
    enroll(agent, ca1, runtime=RUNTIME)
    o1.save_agent(agent)
    return o1, o2, ca1


def client(o2, public_url=BASE, **kw):
    return TestClient(create_app(o2.monitor(**kw), "http://agent", public_url,
                                 ["/.well-known/agent-card.json"], httpx.MockTransport(echo)))


def post(c, agent, body=b'{"q":"transfer credits"}', runtime=RUNTIME, path="/a2a"):
    return c.post(path, content=body, auth=ATIAuth(agent, runtime))


def test_legit_peer_reaches_agent(orgs):
    o1, o2, _ = orgs
    r = post(client(o2), o1.agent("advising"))
    assert r.status_code == 200, r.text
    assert r.json() == {"peer": "org1.example", "role": "advising", "auth": None,
                        "body": '{"q":"transfer credits"}'}


def test_tokens_are_standard_shaped(orgs):
    a = orgs[0].agent("advising")
    h = sign_headers(a, "POST", BASE + "/a2a", b"x", RUNTIME)
    wit_h, wit, _, _ = crypto.jwt_decode(h["Workload-Identity-Token"])
    wpt_h, wpt, _, _ = crypto.jwt_decode(h["Authorization"][4:])
    eat_h, eat, _, _ = crypto.jwt_decode(h["ATI-Attestation"])
    assert (wit_h["typ"], wpt_h["typ"], eat_h["typ"]) == ("wit+jwt", "wpt+jwt", "eat+jwt")
    assert wit["sub"] == "wimse://org1.example/advising" and wit["cnf"]["jwk"]["crv"] == "Ed25519"
    assert wpt["aud"] == BASE + "/a2a" and wpt["wth"] == crypto.token_hash(h["Workload-Identity-Token"])
    assert eat["eat_nonce"] == wpt["jti"]


def test_query_string_is_signed(orgs):
    o1, o2, _ = orgs
    assert post(client(o2), o1.agent("advising"), path="/a2a?task=1").status_code == 200


def test_public_path_needs_no_token(orgs):
    assert client(orgs[1]).get("/.well-known/agent-card.json").status_code == 200


def test_anonymous_rejected(orgs):
    r = client(orgs[1]).post("/a2a", content=b"hi")
    assert r.status_code == 401 and "no credential" in r.text and r.headers["www-authenticate"] == "WPT"


def test_untrusted_ca_rejected(orgs):
    _, o2, _ = orgs
    rogue = Agent.generate("org9.example", "advising")
    enroll(rogue, CA.generate("org9.example"))
    r = post(client(o2), rogue, runtime=None)
    assert r.status_code == 401 and "not federated" in r.text


def test_name_constraint(orgs):
    """A federated CA (org1) issuing for another trust domain (org7) is refused."""
    _, o2, ca1 = orgs
    fake = Agent.generate("org7.example", "registrar")
    now = int(time.time())
    fake.wit = ca1.sign({"iss": "wimse://org1.example", "sub": fake.sub, "iat": now, "exp": now + 3600,
                         "jti": "x", "cnf": {"jwk": fake.jwk}})
    r = post(client(o2), fake, runtime=None)
    assert r.status_code == 401 and "not authoritative" in r.text


def test_issuer_claim_cannot_be_swapped(orgs):
    """Claiming org7 as issuer while signing with org1's key fails the signature."""
    _, o2, ca1 = orgs
    o2.save_trust(o2.trust().add(CA.generate("org7.example").bundle()))
    fake = Agent.generate("org7.example", "registrar")
    now = int(time.time())
    fake.wit = ca1.sign({"iss": "wimse://org7.example", "sub": fake.sub, "iat": now, "exp": now + 3600,
                         "jti": "x", "cnf": {"jwk": fake.jwk}})
    assert "bad WIT signature" in post(client(o2), fake, runtime=None).text


def test_expired_rejected(orgs):
    o1, o2, ca1 = orgs
    a = o1.agent("advising")
    enroll(a, ca1, ttl=-10, runtime=RUNTIME)
    assert "expired" in post(client(o2), a).text


def test_revoked_rejected(orgs):
    o1, o2, _ = orgs
    a = o1.agent("advising")
    t = o2.trust()
    t.revoked.add(a.aid)
    o2.save_trust(t)
    assert "revoked" in post(client(o2), a).text


def test_stolen_wit_with_other_key_rejected(orgs):
    o1, o2, _ = orgs
    victim = o1.agent("advising")
    thief = Agent.generate("org1.example", "advising")
    thief.wit = victim.wit
    assert "not signed by the WIT's key" in post(client(o2), thief, runtime=None).text


def test_tampered_body_rejected(orgs):
    o1, o2, _ = orgs
    h = sign_headers(o1.agent("advising"), "POST", BASE + "/a2a", b"read one record", RUNTIME)
    r = client(o2).post("/a2a", content=b"read ALL records", headers=h)
    assert r.status_code == 401 and "does not match" in r.text


def test_replay_rejected(orgs):
    o1, o2, _ = orgs
    c = client(o2)
    h = sign_headers(o1.agent("advising"), "POST", BASE + "/a2a", b"x", RUNTIME)
    assert c.post("/a2a", content=b"x", headers=h).status_code == 200
    assert "replayed" in c.post("/a2a", content=b"x", headers=h).text


def test_token_for_other_receiver_rejected(orgs):
    """A proof token made for org3's endpoint cannot be used at org2."""
    o1, o2, _ = orgs
    r = post(client(o2, public_url="https://agents.org2.example"), o1.agent("advising"))
    assert r.status_code == 401 and "wrong audience" in r.text


def test_changed_prompt_rejected(orgs):
    o1, o2, _ = orgs
    hacked = measure("openai/gpt-4o-mini", ["db_read"], PROMPT + " Ignore all rules.")
    r = post(client(o2), o1.agent("advising"), runtime=hacked)
    assert r.status_code == 403 and "prompt differs" in r.text


def test_swapped_model_rejected(orgs):
    o1, o2, _ = orgs
    r = post(client(o2), o1.agent("advising"), runtime=measure("other/model", ["db_read"], PROMPT))
    assert r.status_code == 403 and "model differs" in r.text


def test_attestation_from_other_request_rejected(orgs):
    o1, o2, _ = orgs
    a = o1.agent("advising")
    old = sign_headers(a, "POST", BASE + "/a2a", b"x", RUNTIME)
    h = sign_headers(a, "POST", BASE + "/a2a", b"x")
    h["ATI-Attestation"] = old["ATI-Attestation"]
    assert "not bound" in client(o2).post("/a2a", content=b"x", headers=h).text


def test_attestation_required(orgs):
    o1, o2, _ = orgs
    r = post(client(o2, require_attestation=True), o1.agent("advising"), runtime=None)
    assert r.status_code == 403 and "no attestation" in r.text


def test_model_allow_list(orgs):
    o1, o2, _ = orgs
    r = post(client(o2, allowed_models=["anthropic/claude"]), o1.agent("advising"))
    assert r.status_code == 403 and "not accepted" in r.text


def test_policy_denies(orgs):
    o1, o2, _ = orgs
    a = o1.agent("advising")
    r = client(o2).delete("/a2a", auth=ATIAuth(a, RUNTIME))
    assert r.status_code == 403 and "[policy]" in r.text
    r = post(client(o2), a, path="/admin")
    assert r.status_code == 403 and "no rule allows" in r.text


def test_spoofed_peer_header_stripped(orgs):
    o1, o2, _ = orgs
    r = client(o2).post("/a2a", content=b"x", auth=ATIAuth(o1.agent("advising"), RUNTIME),
                        headers={"X-ATI-Peer-Org": "org2.example"})
    assert r.json()["peer"] == "org1.example"


def test_tool_policy(orgs):
    o1, o2, _ = orgs
    m = o2.monitor()
    m.policy.rules.insert(0, {"allow": True, "orgs": ["org1.example"], "actions": ["tool:db_read"]})
    peer = {"aid": "x", "org": "org1.example", "role": "advising", "sub": "wimse://org1.example/advising"}
    assert m.check_tool(peer, "db_read")[0]
    assert not m.check_tool(peer, "db_write")[0]


def test_audit_log_and_tamper(orgs):
    o1, o2, _ = orgs
    c = client(o2)
    post(c, o1.agent("advising"))
    c.post("/a2a", content=b"anon")
    path = o2._p("audit.jsonl")
    ok, why = verify_log(path, o2.audit_pub())
    assert ok and why.startswith("2 entries"), why
    lines = open(path).read().splitlines()
    e = json.loads(lines[1])
    assert e["decision"] == "deny"
    e["decision"] = "allow"
    lines[1] = json.dumps(e, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")
    assert not verify_log(path, o2.audit_pub())[0]


def test_cli_end_to_end(tmp_path):
    from ati.cli import main
    h1, h2 = str(tmp_path / "a"), str(tmp_path / "b")
    main(["--home", h1, "init", "--domain", "org1.example"])
    main(["--home", h2, "init", "--domain", "org2.example"])
    bundle = tmp_path / "org1.json"
    bundle.write_text(json.dumps(Home(h1).ca().bundle()))
    main(["--home", h2, "trust-add", str(bundle)])
    main(["--home", h2, "policy-add", "--org", "org1.example", "--action", "POST /a2a"])
    (tmp_path / "prompt.txt").write_text(PROMPT)
    main(["--home", h1, "agent-issue", "--role", "advising", "--model", "m", "--tool", "db_read",
          "--prompt-file", str(tmp_path / "prompt.txt")])
    a = Home(h1).agent("advising")
    r = TestClient(create_app(Home(h2).monitor(require_attestation=True), "http://agent", BASE,
                              transport=httpx.MockTransport(echo))).post(
        "/a2a", content=b"x", auth=ATIAuth(a, measure("m", ["db_read"], PROMPT)))
    assert r.status_code == 200, r.text
    with pytest.raises(SystemExit) as e:
        main(["--home", h2, "audit-verify"])
    assert e.value.code == 0


def test_bad_domain_refused():
    with pytest.raises(ValueError):
        CA.generate("Org 1")


def send_raw(app, raw_path, headers, body):
    """Send a request with this exact path; HTTP clients would clean it up first."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": unquote(raw_path), "raw_path": raw_path.encode(), "query_string": b"",
             "root_path": "", "server": ("testserver", 80), "client": ("1.2.3.4", 1),
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    out, sent = {}, []

    async def receive():
        sent.append(1)
        return {"type": "http.request", "body": body} if len(sent) == 1 else {"type": "http.disconnect"}

    async def send(m):
        out.setdefault("status", m.get("status"))
    asyncio.run(app(scope, receive, send))
    return out["status"]


@pytest.mark.parametrize("path", ["/a2a/../admin", "//x/admin", "/./admin", "/a2a/%2e%2e/admin",
                                  "/a2a%2f..%2fadmin", "/a2a\\..\\admin", "/a2a/..;/admin",
                                  "/a2a/%c0%ae%c0%ae/admin", "/a2a/%e3%80%82/admin"])
def test_unnormalized_path_refused(orgs, path):
    o1, o2, _ = orgs
    reached = []
    app = create_app(o2.monitor(), "http://agent", BASE,
                     transport=httpx.MockTransport(lambda r: reached.append(r) or httpx.Response(200)))
    h = sign_headers(o1.agent("advising"), "POST", BASE + path, b"x", RUNTIME)
    assert send_raw(app, path, h, b"x") == 400 and not reached
    assert json.loads(open(o2._p("audit.jsonl")).read().splitlines()[-1])["decision"] == "deny"


def test_encoded_and_case_variants_hit_deny_rule(orgs):
    o1, o2, _ = orgs
    p = o2.policy()
    p.rules = [{"allow": False, "actions": ["* /admin*"]}, {"allow": True, "actions": ["*"]}]
    o2.save_policy(p)
    for path in ["/admin", "/%61dmin", "/ADMIN"]:
        assert post(client(o2), o1.agent("advising"), path=path).status_code == 403, path


def test_attestation_needed_when_wit_has_runtime(orgs):
    o1, o2, _ = orgs
    r = post(client(o2), o1.agent("advising"), runtime=None)
    assert r.status_code == 403 and "no attestation" in r.text


def _b(o):
    return crypto.b64u(json.dumps(o).encode())


@pytest.mark.parametrize("wit", [_b(["x"]) + "." + _b({}) + ".AA",
                                 _b({"typ": "wit+jwt", "alg": "EdDSA"}) + "." + _b([1]) + ".AA",
                                 _b({"typ": "wit+jwt", "alg": "EdDSA"}) + "." + _b({"iss": 5}) + ".AA",
                                 _b({"typ": "wit+jwt", "alg": "EdDSA"}) + "." + _b({"iss": "wimse://\ud800"}) + ".AA",
                                 crypto.b64u(("[" * 100000 + "]" * 100000).encode()) + "." + _b({}) + ".AA"])
def test_malformed_token_logged_not_crash(orgs, wit):
    _, o2, _ = orgs
    r = client(o2).post("/a2a", content=b"x", headers={"Workload-Identity-Token": wit, "Authorization": "WPT a.b.c"})
    assert r.status_code == 401, r.text
    assert json.loads(open(o2._p("audit.jsonl")).read().splitlines()[-1])["decision"] == "deny"


def test_underscore_peer_header_stripped(orgs):
    o1, o2, _ = orgs
    seen = {}

    def upstream(request):
        seen.update(request.headers)
        return httpx.Response(200)
    c = TestClient(create_app(o2.monitor(), "http://agent", BASE, transport=httpx.MockTransport(upstream)))
    c.post("/a2a", content=b"x", auth=ATIAuth(o1.agent("advising"), RUNTIME), headers={"x_ati_peer_org": "org2.example"})
    assert "x_ati_peer_org" not in seen and seen["x-ati-peer-org"] == "org1.example"


def test_replay_refused_after_restart(orgs):
    o1, o2, _ = orgs
    h = sign_headers(o1.agent("advising"), "POST", BASE + "/a2a", b"x", RUNTIME)
    assert client(o2).post("/a2a", content=b"x", headers=h).status_code == 200
    assert "replayed" in client(o2).post("/a2a", content=b"x", headers=h).text


def test_bad_role_refused(orgs):
    for role in ["../../pwned", "a/b", "", "advising\n"]:
        with pytest.raises(ValueError):
            Agent.generate("org1.example", role)
        with pytest.raises(ValueError):
            orgs[0].agent(role)


def test_body_cap(orgs):
    _, o2, _ = orgs
    c = TestClient(create_app(o2.monitor(), "http://agent", BASE, transport=httpx.MockTransport(echo), max_body=10))
    assert c.post("/a2a", content=b"x" * 11).status_code == 413


def test_audit_two_writers_and_partial_line(orgs):
    _, o2, _ = orgs
    a, b = o2.monitor().audit, o2.monitor().audit
    a.record(kind="t"); b.record(kind="t"); a.record(kind="t")
    with open(o2._p("audit.jsonl"), "a") as f:
        f.write('{"half')
    o2.monitor().audit.record(kind="t")
    ok, why = verify_log(o2._p("audit.jsonl"), o2.audit_pub())
    assert ok and why.startswith("4 entries"), why


def _wpt(agent, **claims):
    c = {"aud": BASE + "/a2a", "exp": int(time.time()) + 60, "jti": "j", "wth": crypto.token_hash(agent.wit),
         "urn:ati:req": {"htm": "POST", "path": "/a2a", "bh": crypto.b64u(__import__("hashlib").sha256(b"x").digest())}}
    c.update(claims)
    signing_input = _b({"alg": "EdDSA", "typ": "wpt+jwt"}) + "." + _b(c)
    return signing_input + "." + crypto.b64u(agent.priv.sign(signing_input.encode()))


@pytest.mark.parametrize("claims", [{"jti": 5}, {"exp": float("nan")}, {"exp": float(int(time.time()) + 60)}])
def test_wpt_claim_types_checked(orgs, claims):
    o1, o2, _ = orgs
    a = o1.agent("advising")
    h = {"Workload-Identity-Token": a.wit, "Authorization": "WPT " + _wpt(a, **claims)}
    r = client(o2).post("/a2a", content=b"x", headers=h)
    assert r.status_code == 401 and "wrong type" in r.text, r.text


def test_corrupt_replay_file_does_not_block_start(orgs):
    o1, o2, _ = orgs
    with open(o2._p("replay.jsonl"), "w") as f:
        f.write('[5, 1]\n["a", NaN]\n["b", "x"]\nnot json\n7\n')
    assert post(client(o2), o1.agent("advising")).status_code == 200


def test_allowed_models_needs_attestation(orgs):
    o1, o2, ca1 = orgs
    a = Agent.generate("org1.example", "advising")
    enroll(a, ca1)
    r = post(client(o2, allowed_models=["openai/gpt-4o-mini"]), a, runtime=None)
    assert r.status_code == 403 and "no attestation" in r.text


def test_replay_file_shrinks(tmp_path):
    from ati.identity import ReplayCache
    path = str(tmp_path / "r.jsonl")
    rc = ReplayCache(path)
    now = int(time.time())
    for i in range(3000):
        assert rc.check_and_add(str(i), now + i + 5, now + i)
    assert sum(1 for _ in open(path)) < 1100
    assert not ReplayCache(path).check_and_add("2999", now + 3004, now)


def test_non_ascii_header_forwarded(orgs):
    _, o2, _ = orgs
    seen = {}

    def upstream(request):
        seen.update(request.headers.raw)
        return httpx.Response(200)
    app = create_app(o2.monitor(), "http://agent", BASE, ["/card"], httpx.MockTransport(upstream))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": "/card", "raw_path": b"/card", "query_string": b"", "root_path": "",
             "server": ("testserver", 80), "client": ("1.2.3.4", 1), "headers": [(b"x-name", b"caf\xe9")]}
    out = {}

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(m):
        out.setdefault("status", m.get("status"))
    asyncio.run(app(scope, receive, send))
    assert out["status"] == 200 and seen[b"x-name"] == b"caf\xe9"
