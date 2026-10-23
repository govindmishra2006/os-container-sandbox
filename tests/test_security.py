import platform
import sys

import pytest

from container_sandbox.security import (MB, ResourceLimits, SecurityMonitor, ThreatCategory, TokenBucket,
                                        apply_rlimits, python_cmd, run_limited)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="setrlimit is POSIX-only")


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_token_bucket_refills():
    clock = FakeClock()
    tb = TokenBucket(rate=2, capacity=2, clock=clock)
    assert tb.allow() and tb.allow()
    assert not tb.allow()
    clock.t = 1.0
    assert tb.allow() and tb.allow()
    assert not tb.allow()


def test_dos_flood_detected_and_throttled():
    mon = SecurityMonitor(request_rate=1, burst=5, clock=FakeClock())
    results = [mon.record_request("evil") for _ in range(20)]
    assert results.count(True) == 5
    assert mon.summary()[ThreatCategory.AVAILABILITY] >= 1
    assert all(mon.record_request("good") for _ in range(5))     # other guests unaffected


def test_access_violations_classified():
    mon = SecurityMonitor()
    assert mon.inspect_access("D3", "F1", "read", allowed=True) is None
    assert mon.inspect_access("D3", "F1", "read", allowed=False).category is ThreatCategory.CONFIDENTIALITY
    assert mon.inspect_access("D3", "F1", "write", allowed=False).category is ThreatCategory.INTEGRITY


def test_theft_of_service():
    mon = SecurityMonitor()
    mon.set_quota("miner", 5)
    assert mon.check_usage("miner", 4) is None
    assert mon.check_usage("miner", 9).category is ThreatCategory.THEFT_OF_SERVICE


def test_masquerading_detection():
    mon = SecurityMonitor(failed_login_threshold=2)
    mon.auth.register("alice", "s3cret")
    assert mon.login("tty1", "alice", "s3cret")
    assert not mon.login("tty9", "alice", "guess1")
    assert not mon.login("tty9", "alice", "guess2")
    masq = [e for e in mon.events if e.category is ThreatCategory.MASQUERADING]
    assert len(masq) == 2 and masq[-1].severity.value == "critical"
    assert mon.check_identity("pid 5", "D1", "D1") is None
    assert mon.check_identity("pid 5", "D1", "D3").category is ThreatCategory.MASQUERADING


def test_all_five_categories_reportable():
    mon = SecurityMonitor(request_rate=0.001, burst=1, clock=FakeClock())
    mon.inspect_access("x", "f", "read", False)
    mon.inspect_access("x", "f", "write", False)
    mon.record_request("x"); mon.record_request("x")
    mon.set_quota("x", 1); mon.check_usage("x", 2)
    mon.check_identity("x", "a", "b")
    assert all(n >= 1 for n in mon.summary().values())
    assert "Summary" in mon.render()


def test_fork_bomb_check():
    mon = SecurityMonitor()
    assert mon.check_process_limit_exceeded("c", 10, 50) is None
    assert mon.check_process_limit_exceeded("c", 5000, 50).category is ThreatCategory.AVAILABILITY


@posix_only
def test_cpu_limit_kills_spinner():
    res = run_limited(python_cmd("while True: pass"), ResourceLimits(cpu_seconds=1), timeout=30)
    assert res.killed_by_limit
    assert res.signal_name in ("SIGXCPU", "SIGKILL")


@posix_only
def test_file_size_limit():
    code = "import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n" \
           "import tempfile\n" \
           "f = tempfile.TemporaryFile()\n" \
           "try:\n    f.write(b'x' * 200000); f.flush(); print('wrote')\n" \
           "except OSError: print('blocked')"
    res = run_limited(python_cmd(code), ResourceLimits(max_file_size=1024), timeout=30)
    assert "blocked" in res.stdout


@pytest.mark.skipif(platform.system() != "Linux", reason="RLIMIT_AS is only enforced on Linux")
def test_memory_limit_on_linux():
    res = run_limited(python_cmd("x = bytearray(512 * 1024 * 1024)"),
                      ResourceLimits(memory_bytes=128 * MB), timeout=30)
    assert res.killed_by_limit


@posix_only
def test_apply_rlimits_reports_outcome_without_crashing():
    # Run in a child so the test process keeps its own limits.
    code = ("from container_sandbox.security import apply_rlimits, ResourceLimits\n"
            "r = apply_rlimits(ResourceLimits(memory_bytes=1<<40, max_open_files=64))\n"
            "print(sorted(r))")
    import os
    import subprocess
    src = os.path.join(os.path.dirname(__file__), "..", "src")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": src}, timeout=30)
    assert "RLIMIT_NOFILE" in out.stdout and "RLIMIT_AS" in out.stdout


def test_empty_limits():
    assert ResourceLimits().is_empty()
    assert not ResourceLimits(cpu_seconds=1).is_empty()
    assert apply_rlimits(ResourceLimits()) == {}
