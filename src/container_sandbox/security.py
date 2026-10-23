"""Module D -- Security & Threat Mitigation.

Protection (Module C) is the *mechanism* that controls access inside the
system; security is about defending that system against a hostile
environment.  This module provides:

* **Resource limits against Denial of Service.**  A DoS attack tries to
  overload the machine so it cannot do useful work (fork bombs, memory hogs,
  CPU spinners).  Limits are applied per container with POSIX
  ``setrlimit`` (portable) or Linux **cgroups v2** (``memory.max``,
  ``cpu.max``, ``pids.max``) when running as root on Linux.

* **Threat detection** for the five classic security-violation categories:

    ======================  ==============================================
    Breach of confidentiality  unauthorised *reading* of data
    Breach of integrity        unauthorised *modification* of data
    Breach of availability     unauthorised *destruction* / denial of use
    Theft of service           unauthorised *use of resources*
    Masquerading               pretending to be someone else (authentication)
    ======================  ==============================================
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import platform
import secrets
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Sequence

try:  # resource is POSIX-only
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

MB = 1024 * 1024


# --------------------------------------------------------------------------- #
# Resource limits
# --------------------------------------------------------------------------- #

@dataclass
class ResourceLimits:
    memory_bytes: Optional[int] = None      # address space (RLIMIT_AS / memory.max)
    cpu_seconds: Optional[int] = None       # RLIMIT_CPU / cpu.max quota
    max_processes: Optional[int] = None     # RLIMIT_NPROC / pids.max (fork-bomb guard)
    max_open_files: Optional[int] = None    # RLIMIT_NOFILE
    max_file_size: Optional[int] = None     # RLIMIT_FSIZE

    def is_empty(self) -> bool:
        return all(v is None for v in vars(self).values())


def _rlimit_map(limits: ResourceLimits) -> Dict[str, Optional[int]]:
    return {
        "RLIMIT_AS": limits.memory_bytes,
        "RLIMIT_CPU": limits.cpu_seconds,
        "RLIMIT_NPROC": limits.max_processes,
        "RLIMIT_NOFILE": limits.max_open_files,
        "RLIMIT_FSIZE": limits.max_file_size,
    }


def apply_rlimits(limits: ResourceLimits) -> Dict[str, str]:
    """Apply limits to the *current* process.  Returns name -> outcome.

    Some limits are not enforceable on every kernel (e.g. macOS refuses to
    lower ``RLIMIT_AS``); those are reported as ``skipped`` instead of
    failing, so the sandbox still starts with the limits that *can* apply.
    """
    report: Dict[str, str] = {}
    if resource is None:
        return {"*": "skipped (resource module unavailable)"}
    for name, value in _rlimit_map(limits).items():
        if value is None:
            continue
        const = getattr(resource, name, None)
        if const is None:
            report[name] = "skipped (unsupported)"
            continue
        try:
            _soft, hard = resource.getrlimit(const)
            if hard != resource.RLIM_INFINITY and hard < value:
                soft_new = hard_new = hard
            else:
                # Lower the hard limit too so the guest cannot raise it back.
                # For CPU keep 1s of headroom: SIGXCPU (soft) arrives before SIGKILL (hard).
                soft_new = value
                hard_new = value + 1 if name == "RLIMIT_CPU" else value
                if hard != resource.RLIM_INFINITY:
                    hard_new = min(hard_new, hard)
            resource.setrlimit(const, (soft_new, hard_new))
            report[name] = f"set to {soft_new}"
        except (ValueError, OSError) as exc:
            report[name] = f"skipped ({exc})"
    return report


def make_preexec(limits: ResourceLimits) -> Callable[[], None]:
    """Build a ``preexec_fn`` that applies limits inside the child process."""
    def _preexec() -> None:
        apply_rlimits(limits)
    return _preexec


@dataclass
class LimitedRun:
    returncode: int
    signal_name: Optional[str]
    stdout: str
    stderr: str
    elapsed: float

    @property
    def killed_by_limit(self) -> bool:
        return self.signal_name in ("SIGXCPU", "SIGKILL", "SIGXFSZ") or "MemoryError" in self.stderr


def run_limited(argv: Sequence[str], limits: ResourceLimits, timeout: float = 30.0) -> LimitedRun:
    """Run a command under resource limits and report how it ended."""
    import signal as _signal
    start = time.monotonic()
    proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout,
                          preexec_fn=make_preexec(limits) if os.name == "posix" else None)
    sig = None
    if proc.returncode < 0:
        try:
            sig = _signal.Signals(-proc.returncode).name
        except ValueError:
            sig = f"signal {-proc.returncode}"
    return LimitedRun(proc.returncode, sig, proc.stdout, proc.stderr, time.monotonic() - start)


class CgroupController:
    """Minimal cgroup v2 driver (Linux + root only)."""

    ROOT = "/sys/fs/cgroup"

    def __init__(self, name: str, root: str = ROOT):
        self.name = name
        self.path = os.path.join(root, "os-sandbox", name)
        self._root = root

    @classmethod
    def available(cls, root: str = ROOT) -> bool:
        return (platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() == 0
                and os.path.exists(os.path.join(root, "cgroup.controllers")))

    def _write(self, fname: str, value: str) -> None:
        with open(os.path.join(self.path, fname), "w") as fh:
            fh.write(value)

    def create(self, limits: ResourceLimits) -> None:
        parent = os.path.dirname(self.path)
        os.makedirs(self.path, exist_ok=True)
        try:  # delegate controllers to our subtree
            with open(os.path.join(parent, "cgroup.subtree_control"), "w") as fh:
                fh.write("+memory +cpu +pids")
        except OSError:
            pass
        if limits.memory_bytes:
            self._write("memory.max", str(limits.memory_bytes))
        if limits.cpu_seconds:
            # interpret cpu_seconds as "% of one CPU" quota for cgroups: 50ms per 100ms
            self._write("cpu.max", "50000 100000")
        if limits.max_processes:
            self._write("pids.max", str(limits.max_processes))

    def add(self, pid: int) -> None:
        self._write("cgroup.procs", str(pid))

    def destroy(self) -> None:
        try:
            os.rmdir(self.path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Threat detection
# --------------------------------------------------------------------------- #

class ThreatCategory(str, enum.Enum):
    CONFIDENTIALITY = "breach of confidentiality"
    INTEGRITY = "breach of integrity"
    AVAILABILITY = "breach of availability"
    THEFT_OF_SERVICE = "theft of service"
    MASQUERADING = "masquerading (breach of authentication)"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    category: ThreatCategory
    subject: str            # container / domain / user that caused it
    detail: str
    severity: Severity = Severity.MEDIUM
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] {self.severity.value.upper():<8} {self.category.value:<40} {self.subject}: {self.detail}"


class TokenBucket:
    """Rate limiter: ``rate`` tokens/s, burst ``capacity``."""

    def __init__(self, rate: float, capacity: int, clock: Callable[[], float] = time.monotonic):
        self.rate, self.capacity, self._clock = rate, capacity, clock
        self.tokens = float(capacity)
        self._last = clock()

    def allow(self) -> bool:
        now = self._clock()
        self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
        self._last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Authenticator:
    """Salted PBKDF2 credential store used to detect masquerading."""

    def __init__(self) -> None:
        self._users: Dict[str, tuple] = {}

    def register(self, user: str, password: str) -> None:
        salt = secrets.token_bytes(16)
        self._users[user] = (salt, self._hash(password, salt))

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 50_000)

    def verify(self, user: str, password: str) -> bool:
        rec = self._users.get(user)
        if rec is None:
            return False
        salt, digest = rec
        return hmac.compare_digest(digest, self._hash(password, salt))


class SecurityMonitor:
    """Central intrusion-detection log fed by the other subsystems."""

    def __init__(self, request_rate: float = 50.0, burst: int = 100,
                 clock: Callable[[], float] = time.monotonic,
                 failed_login_threshold: int = 3):
        self.events: List[SecurityEvent] = []
        self._rate, self._burst, self._clock = request_rate, burst, clock
        self._buckets: Dict[str, TokenBucket] = {}
        self._throttled: Dict[str, int] = {}
        self._failed_logins: Dict[str, Deque[float]] = {}
        self.failed_login_threshold = failed_login_threshold
        self.auth = Authenticator()
        self.quotas: Dict[str, float] = {}

    def log(self, category: ThreatCategory, subject: str, detail: str,
            severity: Severity = Severity.MEDIUM) -> SecurityEvent:
        ev = SecurityEvent(category, subject, detail, severity)
        self.events.append(ev)
        return ev

    # -- confidentiality / integrity ----------------------------------------
    def inspect_access(self, subject: str, obj: str, op: str, allowed: bool) -> Optional[SecurityEvent]:
        """Classify a *denied* access attempt."""
        if allowed:
            return None
        if op in ("read", "print"):
            return self.log(ThreatCategory.CONFIDENTIALITY, subject, f"denied {op} on {obj}", Severity.HIGH)
        if op in ("write", "delete", "chmod"):
            return self.log(ThreatCategory.INTEGRITY, subject, f"denied {op} on {obj}", Severity.HIGH)
        if op == "execute":
            return self.log(ThreatCategory.THEFT_OF_SERVICE, subject, f"denied execute of {obj}", Severity.MEDIUM)
        return self.log(ThreatCategory.INTEGRITY, subject, f"denied {op} on {obj}", Severity.MEDIUM)

    # -- availability (DoS) -------------------------------------------------
    def record_request(self, subject: str) -> bool:
        """Rate-limit a container's requests; floods are logged as DoS."""
        bucket = self._buckets.setdefault(subject, TokenBucket(self._rate, self._burst, self._clock))
        if bucket.allow():
            return True
        count = self._throttled.get(subject, 0) + 1
        self._throttled[subject] = count
        if count == 1 or count % 100 == 0:
            self.log(ThreatCategory.AVAILABILITY, subject,
                     f"request flood throttled ({count} dropped)", Severity.CRITICAL)
        return False

    def check_process_limit_exceeded(self, subject: str, attempted: int, limit: int) -> Optional[SecurityEvent]:
        if attempted > limit:
            return self.log(ThreatCategory.AVAILABILITY, subject,
                            f"fork bomb blocked: {attempted} processes > limit {limit}", Severity.CRITICAL)
        return None

    # -- theft of service ----------------------------------------------------
    def set_quota(self, subject: str, cpu_seconds: float) -> None:
        self.quotas[subject] = cpu_seconds

    def check_usage(self, subject: str, cpu_seconds_used: float) -> Optional[SecurityEvent]:
        quota = self.quotas.get(subject)
        if quota is not None and cpu_seconds_used > quota:
            return self.log(ThreatCategory.THEFT_OF_SERVICE, subject,
                            f"used {cpu_seconds_used:.1f}s CPU, quota {quota:.1f}s", Severity.HIGH)
        return None

    # -- masquerading --------------------------------------------------------
    def login(self, source: str, claimed_user: str, password: str) -> bool:
        if self.auth.verify(claimed_user, password):
            self._failed_logins.pop(source, None)
            return True
        window = self._failed_logins.setdefault(source, deque(maxlen=50))
        window.append(self._clock())
        sev = Severity.CRITICAL if len(window) >= self.failed_login_threshold else Severity.MEDIUM
        self.log(ThreatCategory.MASQUERADING, source,
                 f"failed authentication as {claimed_user!r} (attempt {len(window)})", sev)
        return False

    def check_identity(self, source: str, claimed_domain: str, actual_domain: str) -> Optional[SecurityEvent]:
        if claimed_domain != actual_domain:
            return self.log(ThreatCategory.MASQUERADING, source,
                            f"claims {claimed_domain} but runs in {actual_domain}", Severity.CRITICAL)
        return None

    # -- reporting -----------------------------------------------------------
    def summary(self) -> Dict[ThreatCategory, int]:
        counts = {c: 0 for c in ThreatCategory}
        for ev in self.events:
            counts[ev.category] += 1
        return counts

    def render(self) -> str:
        if not self.events:
            return "(no security events)"
        lines = [str(e) for e in self.events]
        lines.append("")
        lines.append("Summary:")
        for cat, n in self.summary().items():
            lines.append(f"  {cat.value:<42} {n}")
        return "\n".join(lines)


def python_cmd(code: str) -> List[str]:
    """argv that runs a snippet with the current interpreter (used by demos/tests)."""
    return [sys.executable, "-c", code]
