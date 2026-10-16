"""Accountability plane: an append-only JSONL log. Each entry holds the hash of
the previous one and is signed by the org's audit key, so editing, reordering, or
deleting entries breaks verification. Truncating the tail is not detected
unless the latest hash is kept somewhere else."""
import json
import time
from . import crypto

try:
    import fcntl
except ImportError:
    fcntl = None


def _digest(entry):
    body = {k: v for k, v in entry.items() if k not in ("hash", "sig")}
    return crypto.sha256_hex(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


class AuditLog:
    """Each write locks the file and continues from its last entry, so several
    processes can share one log. A half-written last line (from a crash) is cut off."""

    def __init__(self, path, priv):
        self.path = path
        self.priv = priv

    def record(self, **fields):
        with open(self.path, "a+b") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            seq, prev = _last(f)
            entry = dict(fields, seq=seq, ts=time.time(), prev=prev)
            entry["hash"] = _digest(entry)
            entry["sig"] = crypto.b64u(crypto.sign(self.priv, entry["hash"].encode()))
            f.write((json.dumps(entry, sort_keys=True) + "\n").encode())
        return entry


def _last(f):
    end = pos = f.seek(0, 2)
    buf = b""
    while pos and buf.count(b"\n") < 2:
        n = min(65536, pos)
        pos -= n
        f.seek(pos)
        buf = f.read(n) + buf
    if not buf.endswith(b"\n"):
        cut = buf.rfind(b"\n") + 1
        f.truncate(pos + cut)
        buf = buf[:cut]
    lines = buf.splitlines()
    if not lines:
        return 0, "GENESIS"
    last = json.loads(lines[-1])
    return last["seq"] + 1, last["hash"]


def verify_log(path, pub):
    prev, n = "GENESIS", 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e["seq"] != n or e["prev"] != prev or _digest(e) != e["hash"]:
                return False, f"chain broken at entry {n}"
            if not crypto.verify(pub, e["hash"].encode(), crypto.ub64u(e["sig"])):
                return False, f"bad signature at entry {n}"
            prev, n = e["hash"], n + 1
    return True, f"{n} entries verified"
