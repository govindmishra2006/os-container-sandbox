"""Browser dashboard: ``sandbox web`` serves a live demo of every subsystem.

Standard library only (``http.server``).  The server keeps one in-memory
kernel state (file system, access matrix, capabilities) shared by all
browser tabs, and exposes it as a small JSON API that the single-page
dashboard in ``assets/dashboard.html`` calls.  It binds to 127.0.0.1 by
default; this is a demo, not a multi-user service.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Tuple

from . import __version__
from .disk_scheduler import compare_all
from .filesystem import AllocationMethod, FileSystemError, SimulatedCrash, VirtualFileSystem
from .protection import AccessDenied, CapabilitySystem, Process, demo_policy
from .security import ResourceLimits, SecurityMonitor, python_cmd, run_limited
from .virtualization import (ContainerRuntime, ContainerSpec, HeartbeatMonitor, PrivilegeViolation,
                             VirtualCPU, detect_capabilities)

ASSET = os.path.join(os.path.dirname(__file__), "assets", "dashboard.html")


class ApiError(Exception):
    def __init__(self, message: str, status: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def _ts(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


class DashboardState:
    """The demo kernel behind the dashboard."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset_fs()
        self.reset_protection()

    # -- file system -----------------------------------------------------------
    def reset_fs(self) -> None:
        fs = VirtualFileSystem(num_blocks=64, block_size=16, journal_blocks=4, index_capacity=16)
        fs.create("kernel.img", "K" * 60, "contiguous", owner_id="root", protection="r--r--r--", ftype="binary")
        fs.create("app.log", "L" * 90, "linked", owner_id="svc", protection="rw-r-----", ftype="text")
        fs.create("db.dat", "D" * 120, "indexed", owner_id="alice", protection="rw-------")
        self.fs = fs

    def fs_state(self) -> dict:
        fs = self.fs
        owner: Dict[int, Tuple[str, str]] = {}
        for e in fs.directory.values():
            for b in e.blocks:
                owner[b] = ("used", e.name)
            if e.index_block is not None:
                owner[e.index_block] = ("index", e.name)
        blocks = []
        for i in range(fs.num_blocks):
            if i in fs.journal.reserved_blocks:
                blocks.append({"i": i, "kind": "journal", "file": None})
            elif i in owner:
                blocks.append({"i": i, "kind": owner[i][0], "file": owner[i][1]})
            else:
                blocks.append({"i": i, "kind": "used" if fs.bit_table.is_allocated(i) else "free", "file": None})
        pending = set(fs.journal.pending_txids())
        journal = [{"txid": r.txid, "kind": r.kind, "op": r.op, "name": r.name,
                    "uncommitted": r.kind == "BEGIN" and r.txid in pending} for r in fs.journal.records]
        files = []
        for e in fs.listdir():
            files.append({"name": e.name, "type": e.type, "method": e.method.value, "address": e.address,
                          "current_length": e.current_length, "maximum_length": e.maximum_length,
                          "accessed": _ts(e.date_last_accessed), "updated": _ts(e.date_last_updated),
                          "owner": e.owner_id, "protection": e.protection, "blocks": e.blocks,
                          "index_block": e.index_block,
                          "access_cost": fs.read_block(e.name, len(e.blocks) - 1)[1]})
        bt = fs.bit_table
        return {"blocks": blocks, "bits": bt.to_bitstring(), "files": files, "journal": journal,
                "summary": {"total": fs.num_blocks, "used": bt.used_count, "free": bt.free_count,
                            "block_size": fs.block_size,
                            "fragmentation": round(bt.external_fragmentation() * 100)}}

    # -- protection ------------------------------------------------------------
    def reset_protection(self) -> None:
        self.matrix = demo_policy()
        self.caps = CapabilitySystem()
        self.caps.issue("D1", "F1", {"read"}, scheme="key")
        self.caps.issue("D4", "F1", {"read", "write"}, scheme="key")
        self.caps.issue("D3", "F2", {"read"}, scheme="indirection")

    def protection_state(self) -> dict:
        m = self.matrix
        cells = {d: {o: sorted(m.entry(d, o)) for o in m.objects} for d in m.domains}
        caps = []
        for domain, lst in self.caps.lists.items():
            for c in lst:
                caps.append({"id": c.cap_id, "domain": domain, "obj": c.obj, "rights": sorted(c.rights),
                             "scheme": c.scheme, "key": c.key, "entry": c.entry_id,
                             "valid": self.caps.is_valid(c)})
        return {"domains": m.domains, "objects": m.objects, "cells": cells, "caps": caps,
                "audit": m.audit[-12:]}


# --------------------------------------------------------------------------- #
# API handlers: (state, body) -> JSON-serialisable result
# --------------------------------------------------------------------------- #

def _req(body: dict, *keys: str):
    missing = [k for k in keys if body.get(k) in (None, "")]
    if missing:
        raise ApiError(f"missing field(s): {', '.join(missing)}")
    return [body[k] for k in keys]


def api_info(s: DashboardState, body: dict) -> dict:
    caps = detect_capabilities()
    return {"version": __version__, "system": caps.system, "root": caps.is_root,
            "unshare": caps.has_unshare, "isolation": caps.isolation_mode}


def api_disk(s: DashboardState, body: dict) -> dict:
    try:
        requests = [int(x) for x in body.get("requests", [98, 183, 37, 122, 14, 124, 65, 67])]
        head = int(body.get("head", 53))
        size = int(body.get("size", 200))
    except (TypeError, ValueError):
        raise ApiError("requests, head and size must be whole numbers") from None
    if len(requests) > 200:
        raise ApiError("use 200 requests or fewer")
    try:
        results = compare_all(requests, head, size, body.get("direction", "up"))
    except ValueError as exc:
        raise ApiError(str(exc)) from None
    return {"head": head, "size": size, "requests": requests,
            "results": [{"algorithm": r.algorithm, "path": r.path, "total": r.total_head_movement,
                         "average": round(r.average_seek, 1), "return": r.return_distance} for r in results]}


def api_fs(s, body): return s.fs_state()


def api_fs_create(s, body):
    name, = _req(body, "name")
    try:
        s.fs.create(str(name)[:24], str(body.get("data", "")), AllocationMethod(body.get("method", "indexed")),
                    owner_id=str(body.get("owner") or "guest")[:12], size=int(body.get("size") or 0) or None)
    except (FileSystemError, ValueError) as exc:
        raise ApiError(str(exc)) from None
    return s.fs_state()


def api_fs_delete(s, body):
    name, = _req(body, "name")
    try:
        s.fs.delete(name)
    except FileSystemError as exc:
        raise ApiError(str(exc)) from None
    return s.fs_state()


def api_fs_crash(s, body):
    s.fs.crash_after_log = True
    message = ""
    try:
        s.fs.create(str(body.get("name") or "torn.tmp")[:24], "T" * 40, AllocationMethod.INDEXED)
    except SimulatedCrash as exc:
        message = str(exc)
    except FileSystemError as exc:
        s.fs.crash_after_log = False
        raise ApiError(str(exc)) from None
    journal_before = s.fs_state()["journal"]
    s.fs.crash()
    state = s.fs_state()
    state["journal"] = journal_before        # the log survives; show what recovery will read
    state["crashed"] = True
    state["message"] = message
    return state


def api_fs_recover(s, body):
    report = s.fs.recover()
    state = s.fs_state()
    state["recovery"] = report
    return state


def api_fs_reset(s, body):
    s.reset_fs()
    return s.fs_state()


def api_protection(s, body): return s.protection_state()


def api_check(s, body):
    d, o, op = _req(body, "domain", "obj", "op")
    allowed = s.matrix.check(d, o, op)
    state = s.protection_state()
    state["result"] = {"allowed": allowed, "text": f"{d} {op} {o}: {'allowed' if allowed else 'denied'}"}
    return state


def _protect_action(s: DashboardState, fn: Callable[[], str]) -> dict:
    try:
        text, allowed = fn(), True
    except (AccessDenied, KeyError, ValueError) as exc:
        text, allowed = str(exc).strip("'\""), False
    state = s.protection_state()
    state["result"] = {"allowed": allowed, "text": text}
    return state


def api_switch(s, body):
    frm, to = _req(body, "from", "to")

    def go():
        s.matrix.switch(Process(4242, "shell", frm), to)
        return f"process 4242 switched from {frm} to {to}"
    return _protect_action(s, go)


def api_copy(s, body):
    actor, obj, right, target = _req(body, "actor", "obj", "right", "target")
    mode = body.get("mode", "copy")

    def go():
        s.matrix.copy_right(actor, obj, right, target, mode)
        return f"{actor} gave {right} on {obj} to {target} ({mode})"
    return _protect_action(s, go)


def api_revoke(s, body):
    d, o, right = _req(body, "domain", "obj", "right")

    def go():
        removed = s.matrix.remove(d, o, right)
        return f"removed {right} on {o} from {d}; takes effect on the next check" if removed \
            else f"{d} held no {right} on {o}"
    return _protect_action(s, go)


def api_cap_issue(s, body):
    d, o, right = _req(body, "domain", "obj", "right")
    scheme = body.get("scheme", "key")
    return _protect_action(s, lambda: f"issued cap#{s.caps.issue(d, o, {right}, scheme=scheme).cap_id} to {d}")


def api_cap_rekey(s, body):
    o, = _req(body, "obj")
    return _protect_action(s, lambda: f"{o} re-keyed to {s.caps.revoke_by_key(o)}; its key capabilities are revoked")


def api_cap_entry(s, body):
    entry, = _req(body, "entry")
    s.caps.revoke_indirection(int(entry))
    return _protect_action(s, lambda: f"indirection entry {entry} deleted")


def api_protection_reset(s, body):
    s.reset_protection()
    return s.protection_state()


def api_modes(s, body):
    cpu = VirtualCPU()
    cpu.register_syscall("sethostname", lambda name: cpu.execute("sethostname", lambda: name))
    steps = [{"mode": cpu.mode.name.lower(), "text": "guest starts in user mode"}]
    try:
        cpu.execute("sethostname", lambda: "evil")
    except PrivilegeViolation as exc:
        steps.append({"mode": "user", "fault": True, "text": str(exc)})
    cpu.syscall("sethostname", "guest-01")
    for t in cpu.transitions:
        steps.append({"mode": "supervisor" if t.startswith("user->") else "user", "text": t})
    steps.append({"mode": cpu.mode.name.lower(), "text": "hostname set to 'guest-01' through the system call"})
    return {"steps": steps}


def api_ha(s, body):
    runtime = ContainerRuntime(force_simulation=True)
    events = []
    monitor = HeartbeatMonitor(interval=0.1, on_event=lambda e: events.append(
        {"time": _ts(e.timestamp), "container": e.container, "kind": e.kind, "detail": e.detail}))
    try:
        web = runtime.run(ContainerSpec(name="web", max_restarts=2,
                                        command=python_cmd("import time,sys; time.sleep(0.25); sys.exit(1)")))
        db = runtime.run(ContainerSpec(name="db", command=python_cmd("import time; time.sleep(5)")))
        for c in (web, db):
            monitor.watch(c)
            events.append({"time": _ts(time.time()), "container": c.name, "kind": "start",
                           "detail": f"started, host pid {c.pid}, guest pid 1"})
        monitor.start()
        deadline = time.time() + 4
        while time.time() < deadline and "web" in monitor.watched:
            time.sleep(0.05)
        monitor.stop()
        final = [{"name": c.name, "state": c.state.value, "restarts": c.restarts} for c in (web, db)]
    finally:
        runtime.shutdown()
    return {"isolation": runtime.isolation_mode, "events": events, "containers": final}


def api_threats(s, body):
    mon = SecurityMonitor(request_rate=10, burst=20)
    m = demo_policy()
    for d, o, op in (("D3", "F1", "read"), ("D1", "F3", "write"), ("D2", "F1", "execute")):
        mon.inspect_access(d, o, op, m.check(d, o, op))
    for _ in range(300):
        mon.record_request("container-flooder")
    mon.set_quota("container-miner", 10)
    mon.check_usage("container-miner", 42.5)
    mon.auth.register("alice", "correct horse battery staple")
    for guess in ("123456", "password", "alice"):
        mon.login("10.0.0.66", "alice", guess)
    mon.check_identity("pid 777", "D1", "D3")
    return {"events": [{"time": _ts(e.timestamp), "category": e.category.value, "severity": e.severity.value,
                        "subject": e.subject, "detail": e.detail} for e in mon.events],
            "summary": {c.value: n for c, n in mon.summary().items()}}


def api_cpu_limit(s, body):
    res = run_limited(python_cmd("while True: pass"), ResourceLimits(cpu_seconds=1), timeout=20)
    return {"killed": res.killed_by_limit, "signal": res.signal_name, "elapsed": round(res.elapsed, 2)}


ROUTES: Dict[Tuple[str, str], Callable[[DashboardState, dict], dict]] = {
    ("GET", "/api/info"): api_info,
    ("POST", "/api/disk"): api_disk,
    ("GET", "/api/fs"): api_fs,
    ("POST", "/api/fs/create"): api_fs_create,
    ("POST", "/api/fs/delete"): api_fs_delete,
    ("POST", "/api/fs/crash"): api_fs_crash,
    ("POST", "/api/fs/recover"): api_fs_recover,
    ("POST", "/api/fs/reset"): api_fs_reset,
    ("GET", "/api/protection"): api_protection,
    ("POST", "/api/protection/check"): api_check,
    ("POST", "/api/protection/switch"): api_switch,
    ("POST", "/api/protection/copy"): api_copy,
    ("POST", "/api/protection/revoke"): api_revoke,
    ("POST", "/api/protection/reset"): api_protection_reset,
    ("POST", "/api/caps/issue"): api_cap_issue,
    ("POST", "/api/caps/rekey"): api_cap_rekey,
    ("POST", "/api/caps/revoke-entry"): api_cap_entry,
    ("POST", "/api/containers/modes"): api_modes,
    ("POST", "/api/containers/ha"): api_ha,
    ("POST", "/api/security/threats"): api_threats,
    ("POST", "/api/security/cpu-limit"): api_cpu_limit,
}


class DashboardHandler(BaseHTTPRequestHandler):
    state: DashboardState  # set by make_server
    server_version = f"os-container-sandbox/{__version__}"

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        if method == "GET" and path in ("/", "/index.html"):
            with open(ASSET, "rb") as fh:
                self._send(HTTPStatus.OK, fh.read(), "text/html; charset=utf-8")
            return
        handler = ROUTES.get((method, path))
        if handler is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": f"no such endpoint: {method} {path}"})
            return
        body = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64 * 1024:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body too large"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is not valid JSON"})
                return
        try:
            with self.state.lock:
                result = handler(self.state, body)
            self._json(HTTPStatus.OK, result)
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")


def make_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (DashboardHandler,), {"state": DashboardState()})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = False) -> None:
    server = make_server(host, port)
    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{server.server_address[1]}"
    print(f"os-container-sandbox dashboard running at {url}  (Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
