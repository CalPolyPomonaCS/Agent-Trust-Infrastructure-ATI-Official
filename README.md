# ati

Checks for AI agents that call agents in other organizations. Each org runs its
own certificate authority, keeps a list of partner orgs it trusts, and puts a
small proxy in front of each agent. The proxy checks every incoming request
before the agent sees it:

1. **Identity and trust.** The caller's credential comes from a trusted partner's
   CA, for that partner's own agents, and this exact request was signed by the
   caller and is not a replay.
2. **Attestation.** The caller's model, tools, and system prompt match what its
   own org approved.
3. **Policy.** A rule allows this org and role to take this action. Default deny.
4. **Audit.** Every decision goes into a signed, hash-chained log.

The agent behind the proxy needs no changes.

## Quickstart

Install from a clone:

```
git clone https://github.com/CalPolyPomonaCS/Agent-Trust-Infrastructure-ATI-Official.git && cd Agent-Trust-Infrastructure-ATI-Official
python3 -m venv .venv && . .venv/bin/activate
pip install ".[server]"

ati --home org2 init --domain org2.example
ati --home org1 init --domain org1.example | tail -1 > org1.json
ati --home org2 trust-add org1.json
ati --home org2 policy-add --org org1.example --role advising --action "POST /a2a"

echo "You are the Advising agent." > prompt.txt
ati --home org1 agent-issue --role advising \
    --model openai/gpt-4o-mini --tool db_read --prompt-file prompt.txt
```

Any HTTP agent works behind the proxy. For a test, save this as `agent.py`:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

async def a2a(request):
    return JSONResponse({"agent": "Org 2 registrar", "caller": request.headers.get("x-ati-peer-org"),
                         "role": request.headers.get("x-ati-peer-role"), "request": await request.json()})

app = Starlette(routes=[Route("/a2a", a2a, methods=["POST"])])
```

In two more terminals, start org2's agent and the proxy in front of it:

```
uvicorn agent:app --port 9000
ati --home org2 serve --upstream http://127.0.0.1:9000 --port 8443 \
    --public-url http://127.0.0.1:8443 --require-attestation
```

Then org1 calls org2, and org2 checks its log:

```
ati --home org1 call --role advising POST http://127.0.0.1:8443/a2a \
    --data '{"q":"transfer credits"}' \
    --model openai/gpt-4o-mini --tool db_read --prompt-file prompt.txt
ati --home org2 audit-verify
```

The call returns the agent's reply. A changed prompt or a caller with no
identity is refused before the agent sees it.

## Formats

ATI uses existing token formats, all Ed25519-signed JWTs:

- `Workload-Identity-Token`: the agent's identity, a WIMSE WIT ([draft-ietf-wimse-workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/)) that also records the approved runtime.
- `Authorization: WPT ...`: a per-request proof, a WIMSE WPT ([draft-ietf-wimse-wpt](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/)) bound to the receiver, method, path, and body.
- `ATI-Attestation`: the agent's current model, tools, and prompt hash, an EAT ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711)) bound to that request.

For **A2A**, declare `urn:ati:a2a-extension:v1` as a required extension in the
agent card and leave the card public with `--public-path /.well-known/agent-card.json`.
For **MCP**, put the proxy in front of a Streamable HTTP server; the server should
not also require its own OAuth token, since the WPT uses the `Authorization` header.

## Repository

- `src/ati/`: the package. `tests/`: unit tests (`pip install -e ".[server,test]" && pytest`).

License: Apache-2.0. The software is provided "as is", without warranty of any kind; you use it at your own risk. See [LICENSE](LICENSE).
