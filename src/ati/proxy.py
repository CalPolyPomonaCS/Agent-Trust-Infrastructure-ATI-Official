"""Reverse proxy that sits in front of an agent. Each request goes through the
monitor; allowed ones are forwarded with the verified peer in X-ATI-Peer-*
headers, so the agent behind it needs no ATI code. Paths in `public_paths`
(such as an A2A agent card) are forwarded without checks."""
import json
import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "upgrade",
       "proxy-authorization", "te", "trailer"}
STRIP = {"authorization", "workload-identity-token"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _dropped(name):
    name = name.lower().replace("_", "-")
    return name in HOP | STRIP or name.startswith(("ati-", "x-ati-"))


def create_app(monitor, upstream, public_url, public_paths=(), transport=None, max_body=10 * 2**20):
    """public_url is how callers reach this proxy (e.g. https://agents.org2.example);
    proof tokens must name it as their audience."""
    client = httpx.AsyncClient(base_url=upstream, transport=transport, timeout=120)
    public_url = public_url.rstrip("/")

    async def handle(request):
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > max_body:
                return JSONResponse({"error": f"body over {max_body} bytes"}, status_code=413)
        body = bytes(body)
        path = request.scope.get("raw_path", request.url.path.encode()).decode()
        if request.url.query:
            path += "?" + request.url.query
        headers = {k: v for k, v in request.headers.items() if not _dropped(k)}
        if request.url.path not in public_paths:
            ok, status, why, peer = monitor.check_request(
                {k.lower(): v for k, v in request.headers.items()}, request.method, public_url + path, body)
            if not ok:
                return Response(json.dumps({"error": why}), status, media_type="application/json",
                                headers={"WWW-Authenticate": "WPT"} if status == 401 else None)
            headers.update({"X-ATI-Peer-AID": peer["aid"], "X-ATI-Peer-Org": peer["org"],
                            "X-ATI-Peer-Role": peer["role"], "X-ATI-Peer-Sub": peer["sub"]})
        try:
            r = await client.request(request.method, path, content=body,
                                     headers=[(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()])
        except httpx.TransportError as e:
            return JSONResponse({"error": f"agent unreachable ({type(e).__name__})"}, status_code=502)
        return Response(r.content, r.status_code,
                        {k: v for k, v in r.headers.items() if k.lower() not in HOP | {"content-encoding"}})

    return Starlette(routes=[Route("/{p:path}", handle, methods=METHODS)])
