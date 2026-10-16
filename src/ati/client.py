"""Sender side: sign an outgoing HTTP request so the receiving org's monitor accepts it."""
import httpx

from .attestation import sign_attestation
from . import crypto


def sign_headers(agent, method, url, body, runtime=None):
    """url is the full target URL, including query, exactly as sent."""
    wpt = agent.sign_request(method, url, body)
    headers = {"Workload-Identity-Token": agent.wit, "Authorization": f"WPT {wpt}"}
    if runtime:
        headers["ATI-Attestation"] = sign_attestation(agent, runtime, crypto.jwt_decode(wpt)[1]["jti"])
    return headers


class ATIAuth(httpx.Auth):
    """httpx.Client(auth=ATIAuth(agent, runtime=measure(...)))"""
    requires_request_body = True

    def __init__(self, agent, runtime=None):
        self.agent, self.runtime = agent, runtime

    def auth_flow(self, request):
        request.headers.update(sign_headers(self.agent, request.method, str(request.url),
                                            request.content, self.runtime))
        yield request
