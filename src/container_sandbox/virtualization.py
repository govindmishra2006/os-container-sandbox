"""Module A -- OS-Level Virtualization Runtime.

OS-level virtualization (containers) runs many isolated guests on **one
shared kernel**.  Unlike a hypervisor there is no guest kernel and no
hardware emulation, so overhead is close to zero: a container is just a
process tree that the kernel shows a *restricted view* of the system:

* ``CLONE_NEWPID``  -- its own PID numbering; the guest's init is PID 1.
* ``CLONE_NEWUTS``  -- its own hostname / domain name.
* ``CLONE_NEWNS``   -- its own mount table (private ``/proc``, ``chroot`` root).
* ``CLONE_NEWIPC``  -- its own System V IPC objects.

Combined with resource limits (Module D) each guest gets the illusion of its
own processor, memory and machine.

Two back ends implement the same :class:`Container` interface:

* :class:`NamespaceBackend` -- real kernel namespaces via ``os.unshare`` +
  ``os.fork`` + ``os.chroot``.  Requires Linux and root.
* :class:`SimulationBackend` -- portable user-space simulation: the guest runs
  in its own session/process group, its own working-directory "rootfs",
  a virtual hostname and a virtual PID table, under ``setrlimit`` limits.

The runtime also models the hardware **dual-mode** bit with
:class:`VirtualCPU`: guests execute in *user mode*; privileged operations
(``mount``, ``sethostname``, ``chroot`` ...) are only legal in *supervisor
mode*, reached exclusively through a ``syscall`` trap that validates the
request and drops back to user mode afterwards.

Finally :class:`HeartbeatMonitor` provides **high availability**: it polls
every guest, detects crashes and restarts them according to a restart policy.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import enum
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence

from .security import ResourceLimits, apply_rlimits, make_preexec


# --------------------------------------------------------------------------- #
# Dual-mode operation: user vs supervisor
# --------------------------------------------------------------------------- #

class CPUMode(enum.Enum):
    USER = 1          # mode bit = 1
    SUPERVISOR = 0    # mode bit = 0 (kernel / monitor / privileged mode)


class PrivilegeViolation(PermissionError):
    """A privileged instruction was attempted in user mode (a 'GP fault')."""


PRIVILEGED_INSTRUCTIONS = frozenset({
    "unshare", "chroot", "mount", "umount", "sethostname", "setrlimit",
    "kill_foreign", "load_module", "set_timer", "raw_io", "create_container",
    "destroy_container",
})


class VirtualCPU:
    """Software model of the mode bit, traps and a seccomp-style syscall filter."""

    def __init__(self, allowed_syscalls: Optional[Sequence[str]] = None):
        self.mode = CPUMode.USER
        self.transitions: List[str] = []
        self.faults: List[str] = []
        self._syscalls: Dict[str, Callable] = {}
        self.allowed_syscalls = set(allowed_syscalls) if allowed_syscalls is not None else None
        self._lock = threading.RLock()

    def register_syscall(self, name: str, handler: Callable) -> None:
        self._syscalls[name] = handler

    def execute(self, instruction: str, fn: Optional[Callable] = None, *args, **kwargs):
        """Execute an instruction in the *current* mode."""
        if instruction in PRIVILEGED_INSTRUCTIONS and self.mode is CPUMode.USER:
            self.faults.append(instruction)
            raise PrivilegeViolation(f"privileged instruction {instruction!r} in user mode -> trap to OS")
        return fn(*args, **kwargs) if fn else None

    @contextmanager
    def _supervisor(self, reason: str) -> Iterator[None]:
        with self._lock:
            prev = self.mode
            self.mode = CPUMode.SUPERVISOR
            self.transitions.append(f"user->supervisor ({reason})")
            try:
                yield
            finally:
                self.mode = prev
                self.transitions.append(f"supervisor->user ({reason})")

    def syscall(self, name: str, *args, **kwargs):
        """Trap into supervisor mode, run the handler, return to user mode."""
        if name not in self._syscalls:
            raise PrivilegeViolation(f"unknown system call {name!r}")
        if self.allowed_syscalls is not None and name not in self.allowed_syscalls:
            self.faults.append(name)
            raise PrivilegeViolation(f"system call {name!r} blocked by sandbox policy")
        with self._supervisor(name):
            return self._syscalls[name](*args, **kwargs)


# --------------------------------------------------------------------------- #
# Host capability detection
# --------------------------------------------------------------------------- #

@dataclass
class HostCapabilities:
    system: str
    is_linux: bool
    is_root: bool
    has_unshare: bool
    has_chroot: bool

    @property
    def namespaces_available(self) -> bool:
        return self.is_linux and self.is_root and self.has_unshare

    @property
    def isolation_mode(self) -> str:
        return "namespace" if self.namespaces_available else "simulation"


def detect_capabilities() -> HostCapabilities:
    system = platform.system()
    return HostCapabilities(
        system=system,
        is_linux=system == "Linux",
        is_root=hasattr(os, "geteuid") and os.geteuid() == 0,
        has_unshare=hasattr(os, "unshare") and hasattr(os, "CLONE_NEWPID"),
        has_chroot=hasattr(os, "chroot"),
    )


# --------------------------------------------------------------------------- #
# Container description and state
# --------------------------------------------------------------------------- #

class ContainerState(str, enum.Enum):
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"
    CRASHED = "crashed"
    STOPPED = "stopped"
    FAILED = "failed"         # crashed and out of restarts


class RestartPolicy(str, enum.Enum):
    NEVER = "never"
    ON_FAILURE = "on-failure"
    ALWAYS = "always"


@dataclass
class ContainerSpec:
    name: str
    command: List[str]
    hostname: Optional[str] = None
    rootfs: Optional[str] = None
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    restart_policy: RestartPolicy = RestartPolicy.ON_FAILURE
    max_restarts: int = 3
    interactive: bool = False
    env: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = self.name


class ProcessHandle:
    """Uniform wrapper over a Popen object or a raw forked pid."""

    def __init__(self, pid: int, popen: Optional[subprocess.Popen] = None):
        self.pid = pid
        self._popen = popen
        self._status: Optional[int] = None

    def poll(self) -> Optional[int]:
        if self._status is not None:
            return self._status
        if self._popen is not None:
            self._status = self._popen.poll()
            return self._status
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self._status = -1
            return self._status
        if pid == 0:
            return None
        self._status = os.waitstatus_to_exitcode(status)
        return self._status

    def wait(self, timeout: Optional[float] = None) -> int:
        if self._popen is not None:
            self._status = self._popen.wait(timeout)
            return self._status
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline and time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(str(self.pid), timeout)
            time.sleep(0.02)
        return self._status  # type: ignore[return-value]

    def signal(self, sig: int) -> None:
        try:
            os.killpg(os.getpgid(self.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(self.pid, sig)
            except ProcessLookupError:
                pass


class Container:
    """A guest environment: spec + backend handle + lifecycle bookkeeping."""

    def __init__(self, spec: ContainerSpec, backend: "Backend"):
        self.spec = spec
        self.backend = backend
        self.state = ContainerState.CREATED
        self.handle: Optional[ProcessHandle] = None
        self.restarts = 0
        self.exit_code: Optional[int] = None
        self.started_at: Optional[float] = None
        self.events: List[str] = []
        # virtual PID namespace: guest sees its init as PID 1
        self.vpid_table: Dict[int, int] = {}

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def pid(self) -> Optional[int]:
        return self.handle.pid if self.handle else None

    def _log(self, msg: str) -> None:
        self.events.append(f"{time.strftime('%H:%M:%S')} {msg}")

    def start(self) -> "Container":
        self.handle = self.backend.launch(self)
        self.vpid_table = {1: self.handle.pid}
        self.state = ContainerState.RUNNING
        self.exit_code = None
        self.started_at = time.time()
        self._log(f"started ({self.backend.name}) host-pid={self.handle.pid} guest-pid=1")
        return self

    def is_alive(self) -> bool:
        if self.handle is None or self.state is not ContainerState.RUNNING:
            return False
        code = self.handle.poll()
        if code is None:
            return True
        self.exit_code = code
        self.state = ContainerState.EXITED if code == 0 else ContainerState.CRASHED
        self._log(f"{self.state.value} with code {code}")
        return False

    def wait(self, timeout: Optional[float] = None) -> int:
        if self.handle is None:
            raise RuntimeError("container not started")
        code = self.handle.wait(timeout)
        self.is_alive()
        return code

    def stop(self, timeout: float = 3.0) -> None:
        if self.handle and self.handle.poll() is None:
            self.handle.signal(signal.SIGTERM)
            try:
                self.handle.wait(timeout)
            except subprocess.TimeoutExpired:
                self.handle.signal(signal.SIGKILL)
                self.handle.wait(timeout)
        self.state = ContainerState.STOPPED
        self._log("stopped")

    def describe(self) -> Dict[str, object]:
        uptime = time.time() - self.started_at if self.started_at and self.state is ContainerState.RUNNING else 0
        return {
            "name": self.name,
            "hostname": self.spec.hostname,
            "isolation": self.backend.name,
            "state": self.state.value,
            "host_pid": self.pid,
            "guest_pid": 1 if self.handle else None,
            "rootfs": self.backend.rootfs_of(self),
            "restarts": self.restarts,
            "uptime_s": round(uptime, 1),
            "exit_code": self.exit_code,
        }


# --------------------------------------------------------------------------- #
# Back ends
# --------------------------------------------------------------------------- #

class Backend:
    name = "abstract"

    def launch(self, container: Container) -> ProcessHandle:  # pragma: no cover
        raise NotImplementedError

    def rootfs_of(self, container: Container) -> Optional[str]:
        return container.spec.rootfs


class SimulationBackend(Backend):
    """Portable user-space isolation (no root required).

    * Own **session & process group** (``setsid``) -> signals are contained.
    * Own **rootfs directory** used as the working dir, with ``/etc/hostname``.
    * **Virtual hostname** exported via ``HOSTNAME`` and the prompt.
    * **Resource limits** applied with ``setrlimit`` in the child.
    * Scrubbed environment (no host secrets leak into the guest).
    """

    name = "simulation"

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.join(tempfile.gettempdir(), "os-sandbox-rootfs")

    def rootfs_of(self, container: Container) -> str:
        return container.spec.rootfs or os.path.join(self.base_dir, container.name)

    def prepare_rootfs(self, container: Container) -> str:
        root = self.rootfs_of(container)
        for sub in ("etc", "tmp", "home", "proc"):
            os.makedirs(os.path.join(root, sub), exist_ok=True)
        with open(os.path.join(root, "etc", "hostname"), "w") as fh:
            fh.write(f"{container.spec.hostname}\n")
        return root

    def guest_env(self, container: Container, root: str) -> Dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.path.join(root, "home"),
            "TMPDIR": os.path.join(root, "tmp"),
            "HOSTNAME": container.spec.hostname or container.name,
            "SANDBOX_CONTAINER": container.name,
            "SANDBOX_ROOT": root,
            "SANDBOX_MODE": "simulation",
            "PS1": f"[{container.spec.hostname} (sim)]$ ",
            "TERM": os.environ.get("TERM", "xterm"),
        }
        env.update(container.spec.env)
        return env

    def launch(self, container: Container) -> ProcessHandle:
        root = self.prepare_rootfs(container)
        limits = container.spec.limits
        kwargs = dict(cwd=root, env=self.guest_env(container, root))
        if os.name == "posix":
            kwargs["start_new_session"] = not container.spec.interactive
            if not limits.is_empty():
                kwargs["preexec_fn"] = make_preexec(limits)
        proc = subprocess.Popen(container.spec.command, **kwargs)
        return ProcessHandle(proc.pid, proc)


class NamespaceBackend(Backend):
    """Real Linux namespaces: unshare(2) + fork(2) + chroot(2)."""

    name = "namespace"
    MS_REC = 16384
    MS_PRIVATE = 1 << 18

    def __init__(self) -> None:
        caps = detect_capabilities()
        if not caps.namespaces_available:
            raise PrivilegeViolation("namespace isolation needs Linux, root and os.unshare (Python 3.12+)")
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    def _mount(self, source, target, fstype, flags=0, data=None) -> None:
        res = self._libc.mount(
            source.encode() if source else None, target.encode(),
            fstype.encode() if fstype else None, flags, data)
        if res != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"mount {target}: {os.strerror(err)}")

    def _child_setup(self, spec: ContainerSpec) -> None:  # pragma: no cover - needs root
        socket.sethostname(spec.hostname)
        # stop mount events propagating back to the host
        self._mount(None, "/", None, self.MS_REC | self.MS_PRIVATE)
        if spec.rootfs:
            os.chroot(spec.rootfs)
        os.chdir("/")
        os.makedirs("/proc", exist_ok=True)
        try:
            self._mount("proc", "/proc", "proc")       # ps/top now see only the guest
        except OSError:
            pass
        apply_rlimits(spec.limits)

    def launch(self, container: Container) -> ProcessHandle:  # pragma: no cover - needs root
        spec = container.spec
        flags = os.CLONE_NEWUTS | os.CLONE_NEWNS | os.CLONE_NEWPID | os.CLONE_NEWIPC
        pid = os.fork()
        if pid == 0:
            try:
                if not spec.interactive:
                    os.setsid()
                os.unshare(flags)
                inner = os.fork()                   # first child of a new PID ns is PID 1
                if inner == 0:
                    self._child_setup(spec)
                    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME": spec.hostname,
                           "PS1": f"[{spec.hostname}]# ", "TERM": os.environ.get("TERM", "xterm"),
                           "SANDBOX_MODE": "namespace", **spec.env}
                    os.execvpe(spec.command[0], spec.command, env)
                _, status = os.waitpid(inner, 0)
                os._exit(os.waitstatus_to_exitcode(status) & 0xFF)
            except BaseException as exc:  # never return into the parent's code
                sys.stderr.write(f"container init failed: {exc}\n")
                os._exit(127)
        return ProcessHandle(pid)


# --------------------------------------------------------------------------- #
# Runtime
# --------------------------------------------------------------------------- #

class ContainerRuntime:
    """Creates and manages containers; privileged steps go through the VirtualCPU."""

    def __init__(self, force_simulation: bool = False, rootfs_base: Optional[str] = None):
        self.capabilities = detect_capabilities()
        self.cpu = VirtualCPU()
        if self.capabilities.namespaces_available and not force_simulation:
            self.backend: Backend = NamespaceBackend()
        else:
            self.backend = SimulationBackend(rootfs_base)
        self.containers: Dict[str, Container] = {}
        self.cpu.register_syscall("create_container", self._sys_create)
        self.cpu.register_syscall("destroy_container", self._sys_destroy)

    @property
    def isolation_mode(self) -> str:
        return self.backend.name

    # -- supervisor-mode handlers ------------------------------------------
    def _sys_create(self, spec: ContainerSpec) -> Container:
        self.cpu.execute("create_container")          # legal: we are in supervisor mode
        if spec.name in self.containers:
            raise ValueError(f"container {spec.name!r} already exists")
        if not spec.command:
            raise ValueError("container needs a command")
        if spec.rootfs and not os.path.isdir(spec.rootfs) and self.backend.name == "namespace":
            raise FileNotFoundError(f"rootfs {spec.rootfs} does not exist")
        c = Container(spec, self.backend)
        self.containers[spec.name] = c
        return c

    def _sys_destroy(self, name: str) -> None:
        self.cpu.execute("destroy_container")
        c = self.containers.pop(name)
        c.stop()
        if isinstance(self.backend, SimulationBackend) and not c.spec.rootfs:
            shutil.rmtree(self.backend.rootfs_of(c), ignore_errors=True)

    # -- user-facing API ----------------------------------------------------
    def create(self, spec: ContainerSpec) -> Container:
        return self.cpu.syscall("create_container", spec)

    def run(self, spec: ContainerSpec) -> Container:
        return self.create(spec).start()

    def destroy(self, name: str) -> None:
        self.cpu.syscall("destroy_container", name)

    def get(self, name: str) -> Container:
        return self.containers[name]

    def list(self) -> List[Container]:
        return list(self.containers.values())

    def shutdown(self) -> None:
        for name in list(self.containers):
            self.destroy(name)


# --------------------------------------------------------------------------- #
# High availability
# --------------------------------------------------------------------------- #

@dataclass
class HAEvent:
    timestamp: float
    container: str
    kind: str        # crash | restart | exit | gave-up
    detail: str

    def __str__(self) -> str:
        return f"{time.strftime('%H:%M:%S', time.localtime(self.timestamp))} [{self.kind:<7}] {self.container}: {self.detail}"


class HeartbeatMonitor:
    """Polls guests every ``interval`` seconds and restarts failed ones."""

    def __init__(self, interval: float = 0.5, backoff: float = 0.0,
                 on_event: Optional[Callable[[HAEvent], None]] = None):
        self.interval = interval
        self.backoff = backoff
        self.on_event = on_event
        self.watched: Dict[str, Container] = {}
        self.events: List[HAEvent] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def watch(self, container: Container) -> None:
        with self._lock:
            self.watched[container.name] = container

    def unwatch(self, name: str) -> None:
        with self._lock:
            self.watched.pop(name, None)

    def _emit(self, container: str, kind: str, detail: str) -> HAEvent:
        ev = HAEvent(time.time(), container, kind, detail)
        self.events.append(ev)
        if self.on_event:
            self.on_event(ev)
        return ev

    def _should_restart(self, c: Container) -> bool:
        policy = c.spec.restart_policy
        if policy is RestartPolicy.NEVER:
            return False
        if policy is RestartPolicy.ON_FAILURE and c.state is not ContainerState.CRASHED:
            return False
        return c.restarts < c.spec.max_restarts

    def check_once(self) -> List[HAEvent]:
        """One heartbeat round (deterministic; used by tests and the thread)."""
        new: List[HAEvent] = []
        with self._lock:
            targets = list(self.watched.values())
        for c in targets:
            if c.state is not ContainerState.RUNNING or c.is_alive():
                continue
            kind = "crash" if c.state is ContainerState.CRASHED else "exit"
            new.append(self._emit(c.name, kind, f"heartbeat lost, exit code {c.exit_code}"))
            if self._should_restart(c):
                if self.backoff:
                    time.sleep(self.backoff * (2 ** c.restarts))
                c.restarts += 1
                c.start()
                new.append(self._emit(c.name, "restart",
                                      f"restart {c.restarts}/{c.spec.max_restarts} host-pid={c.pid}"))
            elif kind == "crash":
                c.state = ContainerState.FAILED
                new.append(self._emit(c.name, "gave-up", "restart budget exhausted"))
                self.unwatch(c.name)
            else:
                self.unwatch(c.name)
        return new

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.check_once()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ha-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 4 + 1)
