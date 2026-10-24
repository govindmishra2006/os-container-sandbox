import json
import sys
import threading
import urllib.error
import urllib.request

import pytest

from container_sandbox.web import make_server


@pytest.fixture(scope="module")
def base_url():
    server = make_server("127.0.0.1", 0)          # port 0 = any free port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def call(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_serves_dashboard_page(base_url):
    with urllib.request.urlopen(base_url + "/", timeout=10) as resp:
        html = resp.read().decode()
    assert resp.headers["Content-Type"].startswith("text/html")
    assert "Where the disk head goes" in html


def test_info(base_url):
    status, info = call(base_url, "/api/info")
    assert status == 200 and info["isolation"] in ("namespace", "simulation")


def test_disk_textbook_totals(base_url):
    status, data = call(base_url, "/api/disk", {"requests": [98, 183, 37, 122, 14, 124, 65, 67], "head": 53})
    totals = {r["algorithm"]: r["total"] for r in data["results"]}
    assert status == 200 and totals["FCFS"] == 640 and totals["SSTF"] == 236


def test_disk_rejects_bad_input(base_url):
    status, data = call(base_url, "/api/disk", {"requests": [500], "head": 0, "size": 200})
    assert status == 400 and "outside disk" in data["error"]
    status, data = call(base_url, "/api/disk", {"requests": ["x"]})
    assert status == 400


def test_fs_create_crash_recover(base_url):
    call(base_url, "/api/fs/reset", {})
    status, state = call(base_url, "/api/fs/create", {"name": "web.txt", "data": "hello", "method": "linked"})
    assert status == 200 and "web.txt" in [f["name"] for f in state["files"]]
    assert sum(b["kind"] == "journal" for b in state["blocks"]) == 4
    status, crashed = call(base_url, "/api/fs/crash", {"name": "torn"})
    assert crashed["crashed"] and crashed["files"] == []
    assert any(r["uncommitted"] for r in crashed["journal"])
    status, recovered = call(base_url, "/api/fs/recover", {})
    names = {f["name"] for f in recovered["files"]}
    assert "web.txt" in names and "torn" not in names
    assert recovered["recovery"]["discarded"]


def test_fs_errors_are_reported(base_url):
    call(base_url, "/api/fs/reset", {})
    status, data = call(base_url, "/api/fs/create", {"name": "kernel.img"})
    assert status == 400 and "kernel.img" in data["error"]
    status, data = call(base_url, "/api/fs/create", {})
    assert status == 400 and "name" in data["error"]


def test_protection_check_switch_and_revoke(base_url):
    call(base_url, "/api/protection/reset", {})
    _, s = call(base_url, "/api/protection/check", {"domain": "D1", "obj": "F1", "op": "read"})
    assert s["result"]["allowed"]
    _, s = call(base_url, "/api/protection/switch", {"from": "D1", "to": "D3"})
    assert not s["result"]["allowed"]
    _, s = call(base_url, "/api/protection/revoke", {"domain": "D4", "obj": "F3", "right": "write"})
    assert "write" not in s["cells"]["D4"]["F3"]
    _, s = call(base_url, "/api/protection/copy",
                {"actor": "D2", "obj": "F2", "right": "read", "target": "D1", "mode": "limited"})
    assert s["result"]["allowed"] and s["cells"]["D1"]["F2"] == ["read"]


def test_capability_revocation(base_url):
    _, s = call(base_url, "/api/protection/reset", {})
    assert all(c["valid"] for c in s["caps"])
    _, s = call(base_url, "/api/caps/rekey", {"obj": "F1"})
    assert [c["valid"] for c in s["caps"] if c["obj"] == "F1"] == [False, False]
    assert [c["valid"] for c in s["caps"] if c["obj"] == "F2"] == [True]


def test_modes_and_threats(base_url):
    _, m = call(base_url, "/api/containers/modes", {})
    assert any(step.get("fault") for step in m["steps"])
    _, t = call(base_url, "/api/security/threats", {})
    assert all(n >= 1 for n in t["summary"].values())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process model required")
def test_ha_demo_endpoint(base_url):
    _, r = call(base_url, "/api/containers/ha", {})
    kinds = [e["kind"] for e in r["events"]]
    assert "crash" in kinds and "restart" in kinds and "gave-up" in kinds
    assert {c["name"]: c["state"] for c in r["containers"]} == {"web": "failed", "db": "running"}


def test_unknown_endpoint_and_bad_json(base_url):
    status, data = call(base_url, "/api/nope")
    assert status == 404
    req = urllib.request.Request(base_url + "/api/disk", data=b"{not json", method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=10)
    assert err.value.code == 400
