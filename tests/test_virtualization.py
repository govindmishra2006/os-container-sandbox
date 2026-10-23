import os
import sys
import time

import pytest

from container_sandbox.security import ResourceLimits, python_cmd
from container_sandbox.virtualization import (CPUMode, ContainerRuntime, ContainerSpec, ContainerState,
                                              HeartbeatMonitor, NamespaceBackend, PrivilegeViolation,
                                              RestartPolicy, SimulationBackend, VirtualCPU,
                                              detect_capabilities)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process model required")


@pytest.fixture
def runtime(tmp_path):
    rt = ContainerRuntime(force_simulation=True, rootfs_base=str(tmp_path))
    yield rt
    rt.shutdown()


# --------------------------------------------------------------------------- dual mode

def test_cpu_starts_in_user_mode_and_blocks_privileged():
    cpu = VirtualCPU()
    assert cpu.mode is CPUMode.USER
    with pytest.raises(PrivilegeViolation):
        cpu.execute("mount")
    assert cpu.faults == ["mount"]
    assert cpu.execute("add", lambda a, b: a + b, 2, 3) == 5     # unprivileged is fine


def test_syscall_traps_to_supervisor_and_returns():
    cpu = VirtualCPU()
    seen = []
    cpu.register_syscall("sethostname", lambda n: (seen.append(cpu.mode), cpu.execute("sethostname"), n)[-1])
    assert cpu.syscall("sethostname", "box") == "box"
    assert seen == [CPUMode.SUPERVISOR]
    assert cpu.mode is CPUMode.USER
    assert cpu.transitions == ["user->supervisor (sethostname)", "supervisor->user (sethostname)"]


def test_mode_restored_when_handler_raises():
    cpu = VirtualCPU()
    cpu.register_syscall("boom", lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        cpu.syscall("boom")
    assert cpu.mode is CPUMode.USER


def test_syscall_filter_blocks_unlisted_calls():
    cpu = VirtualCPU(allowed_syscalls=["getpid"])
    cpu.register_syscall("getpid", lambda: 1)
    cpu.register_syscall("mount", lambda: None)
    assert cpu.syscall("getpid") == 1
    with pytest.raises(PrivilegeViolation):
        cpu.syscall("mount")
    with pytest.raises(PrivilegeViolation):
        cpu.syscall("does_not_exist")


# --------------------------------------------------------------------------- isolation fallback

def test_capability_detection_consistent():
    caps = detect_capabilities()
    assert caps.isolation_mode in ("namespace", "simulation")
    if not (caps.is_linux and caps.is_root):
        assert caps.isolation_mode == "simulation"


def test_runtime_falls_back_to_simulation_without_root(runtime):
    assert runtime.isolation_mode == "simulation"
    assert isinstance(runtime.backend, SimulationBackend)


@pytest.mark.skipif(detect_capabilities().namespaces_available, reason="host can create namespaces")
def test_namespace_backend_refuses_without_privileges():
    with pytest.raises(PrivilegeViolation):
        NamespaceBackend()


def test_guest_sees_virtual_hostname_and_private_root(runtime, tmp_path):
    out = tmp_path / "out.txt"
    code = (f"import os; open({str(out)!r}, 'w').write("
            "os.environ['HOSTNAME'] + '|' + os.getcwd() + '|' + open('etc/hostname').read().strip() + '|' "
            "+ str(os.getsid(0) == os.getpid()))")
    c = runtime.run(ContainerSpec(name="iso", hostname="guest-a", command=python_cmd(code)))
    assert c.wait(10) == 0
    hostname, cwd, etc_hostname, own_session = out.read_text().split("|")
    assert hostname == "guest-a" and etc_hostname == "guest-a"
    assert os.path.realpath(cwd) == os.path.realpath(str(tmp_path / "iso"))
    assert own_session == "True"                  # own session / process group
    assert c.vpid_table[1] == c.pid               # guest PID 1 maps to host pid


def test_guest_environment_is_scrubbed(runtime, tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_SECRET", "hunter2")
    out = tmp_path / "env.txt"
    c = runtime.run(ContainerSpec(name="env", command=python_cmd(
        f"import os; open({str(out)!r}, 'w').write(os.environ.get('HOST_SECRET', 'absent'))")))
    c.wait(10)
    assert out.read_text() == "absent"


def test_two_containers_are_independent(runtime):
    a = runtime.run(ContainerSpec(name="a", command=python_cmd("import time; time.sleep(5)")))
    b = runtime.run(ContainerSpec(name="b", command=python_cmd("import sys; sys.exit(3)")))
    assert b.wait(10) == 3
    assert b.state is ContainerState.CRASHED
    assert a.is_alive()
    a.stop()
    assert a.state is ContainerState.STOPPED


def test_limits_applied_inside_guest(runtime):
    c = runtime.run(ContainerSpec(name="cpu", command=python_cmd("while True: pass"),
                                  limits=ResourceLimits(cpu_seconds=1)))
    code = c.wait(30)
    assert code < 0 and c.state is ContainerState.CRASHED   # killed by SIGXCPU/SIGKILL


def test_duplicate_container_name_rejected(runtime):
    runtime.create(ContainerSpec(name="dup", command=["true"]))
    with pytest.raises(ValueError):
        runtime.create(ContainerSpec(name="dup", command=["true"]))


def test_container_creation_goes_through_supervisor(runtime):
    runtime.create(ContainerSpec(name="x", command=["true"]))
    assert "user->supervisor (create_container)" in runtime.cpu.transitions
    assert runtime.cpu.mode is CPUMode.USER


def test_destroy_removes_rootfs(runtime, tmp_path):
    c = runtime.run(ContainerSpec(name="gone", command=["true"]))
    c.wait(10)
    runtime.destroy("gone")
    assert not (tmp_path / "gone").exists()
    assert "gone" not in runtime.containers


# --------------------------------------------------------------------------- high availability

def _wait_dead(c, timeout=10):
    deadline = time.time() + timeout
    while c.handle.poll() is None and time.time() < deadline:
        time.sleep(0.02)


def test_heartbeat_restarts_crashed_container(runtime):
    c = runtime.run(ContainerSpec(name="flaky", command=python_cmd("import sys; sys.exit(1)"), max_restarts=2))
    mon = HeartbeatMonitor()
    mon.watch(c)
    first_pid = c.pid
    _wait_dead(c)
    events = mon.check_once()
    assert [e.kind for e in events] == ["crash", "restart"]
    assert c.restarts == 1 and c.pid != first_pid and c.state is ContainerState.RUNNING
    _wait_dead(c); mon.check_once()
    _wait_dead(c); events = mon.check_once()
    assert [e.kind for e in events] == ["crash", "gave-up"]
    assert c.state is ContainerState.FAILED and c.restarts == 2
    assert "flaky" not in mon.watched


def test_clean_exit_not_restarted_on_failure_policy(runtime):
    c = runtime.run(ContainerSpec(name="job", command=["true"]))
    mon = HeartbeatMonitor()
    mon.watch(c)
    _wait_dead(c)
    assert [e.kind for e in mon.check_once()] == ["exit"]
    assert c.state is ContainerState.EXITED and c.restarts == 0


def test_always_policy_restarts_clean_exit(runtime):
    c = runtime.run(ContainerSpec(name="svc", command=["true"], restart_policy=RestartPolicy.ALWAYS,
                                  max_restarts=1))
    mon = HeartbeatMonitor()
    mon.watch(c)
    _wait_dead(c)
    assert [e.kind for e in mon.check_once()] == ["exit", "restart"]


def test_healthy_container_untouched(runtime):
    c = runtime.run(ContainerSpec(name="ok", command=python_cmd("import time; time.sleep(5)")))
    mon = HeartbeatMonitor()
    mon.watch(c)
    assert mon.check_once() == []
    assert c.restarts == 0


def test_background_monitor_thread(runtime):
    c = runtime.run(ContainerSpec(name="bg", command=python_cmd("import sys; sys.exit(2)"), max_restarts=1))
    mon = HeartbeatMonitor(interval=0.05)
    mon.watch(c)
    mon.start()
    deadline = time.time() + 10
    while time.time() < deadline and c.state is not ContainerState.FAILED:
        time.sleep(0.05)
    mon.stop()
    assert c.state is ContainerState.FAILED
    assert [e.kind for e in mon.events] == ["crash", "restart", "crash", "gave-up"]


# --------------------------------------------------------------------------- real namespaces (Linux + root)

@pytest.mark.skipif(not detect_capabilities().namespaces_available, reason="needs Linux, root and os.unshare")
def test_real_namespace_isolation(tmp_path):
    import socket
    rt = ContainerRuntime()
    assert rt.isolation_mode == "namespace"
    out = tmp_path / "ns.txt"
    c = rt.run(ContainerSpec(name="ns", hostname="ns-guest",
                             command=["sh", "-c", f"echo $(hostname) $$ $(ls /proc | grep -c '^[0-9]') > {out}"]))
    assert c.wait(10) == 0
    hostname, pid, nprocs = out.read_text().split()
    assert hostname == "ns-guest" and pid == "1"          # UTS + PID namespace
    assert int(nprocs) < 10                               # private /proc only shows the guest
    assert socket.gethostname() != "ns-guest"             # host hostname untouched
    rt.shutdown()
