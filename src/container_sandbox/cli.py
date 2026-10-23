"""Command-line interface: ``sandbox <subsystem> <action> ...``.

State for the file system and the protection engine is persisted as JSON in
``--state-dir`` (default ``./.sandbox_state`` or ``$SANDBOX_STATE_DIR``) so a
sequence of commands behaves like a long-running kernel.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Callable, List, Optional

from . import __version__
from .disk_scheduler import (ALGORITHMS, ContainerIOQueue, DiskGeometry, compare_all,
                             render_benchmark, render_trace)
from .filesystem import AllocationMethod, FileSystemError, SimulatedCrash, VirtualFileSystem
from .protection import (ACLStore, AccessDenied, AccessMatrix, CapabilitySystem, Process,
                         RBACEngine, demo_policy)
from .security import MB, ResourceLimits, SecurityMonitor, python_cmd, run_limited
from .virtualization import (ContainerRuntime, ContainerSpec, HeartbeatMonitor, PrivilegeViolation,
                             RestartPolicy, VirtualCPU, detect_capabilities)

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(t: str) -> str: return _c("1", t)
def green(t: str) -> str: return _c("32", t)
def red(t: str) -> str: return _c("31", t)
def yellow(t: str) -> str: return _c("33", t)
def cyan(t: str) -> str: return _c("36", t)


def header(title: str) -> None:
    print()
    print(bold(cyan(f"== {title} " + "=" * max(0, 66 - len(title)))))


def ok(msg: str) -> None:
    print(green("  [ok] ") + msg)


def fail(msg: str) -> None:
    print(red("  [x]  ") + msg)


# --------------------------------------------------------------------------- #
# State persistence
# --------------------------------------------------------------------------- #

class StateStore:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _file(self, name: str) -> str:
        return os.path.join(self.path, f"{name}.json")

    def load(self, name: str) -> Optional[dict]:
        try:
            with open(self._file(name)) as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None

    def save(self, name: str, data: dict) -> None:
        tmp = self._file(name) + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self._file(name))          # atomic rename

    # -- typed helpers ----------------------------------------------------
    def fs(self) -> VirtualFileSystem:
        data = self.load("fs")
        return VirtualFileSystem.from_dict(data) if data else VirtualFileSystem()

    def save_fs(self, fs: VirtualFileSystem) -> None:
        self.save("fs", fs.to_dict())

    def protection(self):
        data = self.load("protection")
        if not data:
            return demo_policy(), CapabilitySystem()
        return AccessMatrix.from_dict(data["matrix"]), CapabilitySystem.from_dict(data["caps"])

    def save_protection(self, matrix: AccessMatrix, caps: CapabilitySystem) -> None:
        self.save("protection", {"matrix": matrix.to_dict(), "caps": caps.to_dict()})


# --------------------------------------------------------------------------- #
# Container commands
# --------------------------------------------------------------------------- #

def _limits(args) -> ResourceLimits:
    return ResourceLimits(
        memory_bytes=args.memory * MB if args.memory else None,
        cpu_seconds=args.cpu,
        max_processes=args.nproc,
    )


def cmd_info(args) -> int:
    caps = detect_capabilities()
    header("Host capabilities")
    print(f"  os-container-sandbox {__version__}  |  python {sys.version.split()[0]}")
    print(f"  system           : {caps.system}")
    print(f"  root privileges  : {caps.is_root}")
    print(f"  os.unshare       : {caps.has_unshare}")
    print(f"  chroot           : {caps.has_chroot}")
    mode = caps.isolation_mode
    print(f"  isolation mode   : {bold(green(mode) if mode == 'namespace' else yellow(mode))}")
    if mode == "simulation":
        print("  (run as root on Linux with Python >= 3.12 for real kernel namespaces)")
    return 0


def cmd_run(args) -> int:
    command = args.command or ["/bin/sh"]
    if command and command[0] == "--":
        command = command[1:]
    runtime = ContainerRuntime(force_simulation=args.simulate)
    interactive = sys.stdin.isatty() and not args.ha
    spec = ContainerSpec(
        name=args.name, command=command, hostname=args.hostname, rootfs=args.rootfs,
        limits=_limits(args), interactive=interactive,
        restart_policy=RestartPolicy(args.restart), max_restarts=args.max_restarts,
    )
    header(f"Launching container '{spec.name}' [{runtime.isolation_mode}]")
    print(f"  hostname={spec.hostname} command={' '.join(command)}")
    if not spec.limits.is_empty():
        print(f"  limits: mem={args.memory or '-'}MB cpu={args.cpu or '-'}s nproc={args.nproc or '-'}")
    try:
        container = runtime.run(spec)
    except (PrivilegeViolation, OSError, ValueError) as exc:
        fail(str(exc))
        return 1
    for k, v in container.describe().items():
        print(f"  {k:<10}: {v}")
    try:
        if args.ha:
            monitor = HeartbeatMonitor(interval=args.interval, on_event=lambda e: print("  " + str(e)))
            monitor.watch(container)
            monitor.start()
            while container.name in monitor.watched:
                time.sleep(args.interval)
            monitor.stop()
        else:
            container.wait()
    except KeyboardInterrupt:
        print()
    finally:
        code = container.exit_code
        runtime.shutdown()
    if code is not None and code < 0:
        import signal as _signal
        print(f"  container killed by {_signal.Signals(-code).name}")
        return 128 - code                      # shell convention for signal deaths
    print(f"  container exited (code {code})")
    return 0 if code in (0, None) else code


def cmd_ha_demo(args) -> int:
    header("High-availability heartbeat monitor")
    runtime = ContainerRuntime(force_simulation=True)
    crasher = ContainerSpec(name="web", command=python_cmd("import time,sys; time.sleep(0.3); sys.exit(1)"),
                            max_restarts=args.restarts)
    healthy = ContainerSpec(name="db", command=python_cmd("import time; time.sleep(5)"))
    monitor = HeartbeatMonitor(interval=0.1, on_event=lambda e: print("  " + str(e)))
    for spec in (crasher, healthy):
        c = runtime.run(spec)
        monitor.watch(c)
        print(f"  started {c.name:<4} host-pid={c.pid}")
    monitor.start()
    deadline = time.time() + 0.6 * (args.restarts + 2)
    while time.time() < deadline and "web" in monitor.watched:
        time.sleep(0.1)
    monitor.stop()
    web, db = runtime.get("web"), runtime.get("db")
    print(f"  web: state={web.state.value} restarts={web.restarts}")
    print(f"  db : state={db.state.value} (never crashed, never restarted)")
    runtime.shutdown()
    return 0


def cmd_modes(args) -> int:
    header("Dual-mode operation (user vs supervisor)")
    cpu = VirtualCPU()
    cpu.register_syscall("sethostname", lambda name: cpu.execute("sethostname", lambda: name))
    print(f"  current mode: {cpu.mode.name}")
    try:
        cpu.execute("sethostname", lambda: "evil")
    except PrivilegeViolation as exc:
        fail(f"direct attempt: {exc}")
    result = cpu.syscall("sethostname", "guest-01")
    ok(f"via syscall trap: hostname set to {result!r}")
    for t in cpu.transitions:
        print(f"    mode switch: {t}")
    print(f"  back in mode: {cpu.mode.name}; faults recorded: {cpu.faults}")
    return 0


# --------------------------------------------------------------------------- #
# File-system commands
# --------------------------------------------------------------------------- #

def _print_ls(fs: VirtualFileSystem) -> None:
    print(f"  {'NAME':<12}{'TYPE':<9}{'METHOD':<11}{'ADDR':>5}{'LEN':>6}{'MAX':>7}  "
          f"{'OWNER':<7}{'PROT':<10}{'UPDATED':<9}BLOCKS")
    for e in fs.listdir():
        upd = time.strftime("%H:%M:%S", time.localtime(e.date_last_updated))
        blocks = ",".join(map(str, e.blocks))
        if e.index_block is not None:
            blocks = f"idx={e.index_block} -> [{blocks}]"
        print(f"  {e.name:<12}{e.type:<9}{e.method.value:<11}{e.address:>5}{e.current_length:>6}"
              f"{e.maximum_length:>7}  {e.owner_id:<7}{e.protection:<10}{upd:<9}{blocks}")
    if not fs.directory:
        print("  (empty)")


def cmd_fs(args) -> int:
    store = StateStore(args.state_dir)
    if args.fs_cmd == "init":
        fs = VirtualFileSystem(num_blocks=args.blocks, block_size=args.block_size,
                               journal_blocks=args.journal_blocks)
        store.save_fs(fs)
        ok(f"formatted virtual disk: {fs.usage_summary()}")
        return 0
    fs = store.fs()
    try:
        if args.fs_cmd == "create":
            data = args.data or ""
            e = fs.create(args.name, data, AllocationMethod(args.method), owner_id=args.owner,
                          protection=args.protection, size=args.size)
            ok(f"created {e.name} ({e.method.value}) address={e.address} blocks={e.blocks}"
               + (f" index-block={e.index_block}" if e.index_block is not None else ""))
        elif args.fs_cmd == "write":
            e = fs.write(args.name, args.data)
            ok(f"wrote {e.current_length} bytes to {e.name} blocks={e.blocks}")
        elif args.fs_cmd == "cat":
            print(fs.read(args.name).decode(errors="replace"))
        elif args.fs_cmd == "rm":
            fs.delete(args.name)
            ok(f"deleted {args.name}")
        elif args.fs_cmd == "ls":
            header("Directory")
            _print_ls(fs)
        elif args.fs_cmd == "stat":
            for k, v in fs.stat(args.name).to_dict().items():
                if k.startswith("date_"):
                    v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v))
                print(f"  {k:<18}: {v}")
        elif args.fs_cmd == "bitmap":
            header("Bit table (0 = free, 1 = used)")
            print(fs.bit_table.render())
            print()
            print("  Ownership view (J=journal, I=index block, letter=file initial, 0=free)")
            print(fs.bit_table.render(labels=fs.block_labels()))
            print(f"\n  {fs.usage_summary()}")
            print(f"  free runs (start,len): {fs.bit_table.free_runs()}")
        elif args.fs_cmd == "access":
            header(f"Direct access to logical block {args.block} of {args.name}")
            data, cost = fs.read_block(args.name, args.block)
            print(f"  method={fs.stat(args.name).method.value} disk accesses={cost} data={data[:32]!r}")
        elif args.fs_cmd == "journal":
            header("Journal (reserved recovery-log area, blocks "
                   f"{fs.journal.reserved_blocks[0]}-{fs.journal.reserved_blocks[-1]})")
            print(fs.journal.render())
        elif args.fs_cmd == "checkpoint":
            fs.checkpoint()
            ok("checkpoint written, journal truncated")
        elif args.fs_cmd == "crash":
            fs.crash_after_log = True
            try:
                fs.create(args.name, args.data or "lost", AllocationMethod.INDEXED)
            except SimulatedCrash as exc:
                fail(str(exc))
            fs.crash()
            ok("volatile metadata wiped (directory + bit table). Run `sandbox fs recover`.")
        elif args.fs_cmd == "recover":
            report = fs.recover()
            ok(f"replayed committed tx {report['replayed']}; discarded uncommitted tx {report['discarded']}")
            _print_ls(fs)
    except (FileSystemError, ValueError) as exc:
        fail(str(exc))
        return 1
    store.save_fs(fs)
    return 0


# --------------------------------------------------------------------------- #
# Protection commands
# --------------------------------------------------------------------------- #

def cmd_matrix(args) -> int:
    store = StateStore(args.state_dir)
    if args.m_cmd == "init":
        store.save_protection(demo_policy(), CapabilitySystem())
        ok("loaded the textbook demo policy (domains D1-D4, objects F1-F3, printer)")
        return 0
    m, caps = store.protection()
    try:
        if args.m_cmd == "show":
            header("Access matrix  (rows = domains, columns = objects)")
            print(m.render())
        elif args.m_cmd == "add-domain":
            m.add_domain(args.name); ok(f"domain {args.name} added")
        elif args.m_cmd == "add-object":
            m.add_object(args.name); ok(f"object {args.name} added")
        elif args.m_cmd == "grant":
            m.grant(args.domain, args.obj, *args.rights); ok(f"Access({args.domain},{args.obj}) = {sorted(m.entry(args.domain, args.obj))}")
        elif args.m_cmd == "check":
            allowed = m.check(args.domain, args.obj, args.op)
            (ok if allowed else fail)(f"{args.domain} {args.op} {args.obj}: {'ALLOWED' if allowed else 'DENIED'}")
            store.save_protection(m, caps)
            return 0 if allowed else 2
        elif args.m_cmd == "copy":
            m.copy_right(args.actor, args.obj, args.right, args.target, args.mode)
            ok(f"{args.actor} copied {args.right} on {args.obj} to {args.target} ({args.mode})")
        elif args.m_cmd == "owner-grant":
            m.owner_grant(args.actor, args.obj, args.target, args.right); ok("granted by owner")
        elif args.m_cmd == "owner-revoke":
            m.owner_revoke(args.actor, args.obj, args.target, args.right); ok("revoked by owner")
        elif args.m_cmd == "control":
            m.control_modify(args.actor, args.target, args.obj, args.right, add=args.add)
            ok(f"{args.actor} {'added' if args.add else 'removed'} {args.right} on {args.obj} in row {args.target}")
        elif args.m_cmd == "switch":
            p = Process(pid=4242, name="proc", domain=args.frm)
            m.switch(p, args.to)
            ok(f"process 4242 switched {args.frm} -> {p.domain}")
    except (AccessDenied, KeyError, ValueError) as exc:
        fail(str(exc))
        return 2
    store.save_protection(m, caps)
    return 0


def cmd_acl(args) -> int:
    store = StateStore(args.state_dir)
    m, caps = store.protection()
    if args.acl_cmd == "show":
        acls = ACLStore.from_matrix(m)
        header("Access control lists (column-wise view)")
        for obj in ([args.obj] if args.obj else m.objects):
            print("  " + acls.render(obj))
        return 0
    if args.acl_cmd == "revoke":
        before = m.has(args.domain, args.obj, args.right)
        m.remove(args.domain, args.obj, args.right)
        after = m.has(args.domain, args.obj, args.right)
        store.save_protection(m, caps)
        ok(f"immediate revocation: {args.domain} {args.right} {args.obj}: {before} -> {after}")
    return 0


def cmd_cap(args) -> int:
    store = StateStore(args.state_dir)
    m, caps = store.protection()
    try:
        if args.cap_cmd == "issue":
            cap = caps.issue(args.domain, args.obj, args.rights, scheme=args.scheme, entry_id=args.entry)
            ok(f"cap#{cap.cap_id} -> {args.domain}: {sorted(cap.rights)} on {args.obj} "
               f"({cap.scheme}{' key=' + cap.key if cap.key else ' entry=' + str(cap.entry_id)})")
        elif args.cap_cmd == "list":
            header("Capability lists (row-wise)")
            print(caps.render())
        elif args.cap_cmd == "check":
            allowed = caps.check(args.domain, args.obj, args.op)
            (ok if allowed else fail)(f"{args.domain} {args.op} {args.obj}: {'ALLOWED' if allowed else 'DENIED'}")
        elif args.cap_cmd == "revoke-key":
            new = caps.revoke_by_key(args.obj)
            ok(f"object {args.obj} re-keyed to {new}: all key-scheme capabilities revoked")
        elif args.cap_cmd == "revoke-entry":
            caps.revoke_indirection(args.entry)
            ok(f"indirection entry {args.entry} destroyed")
    except (AccessDenied, ValueError) as exc:
        fail(str(exc))
        return 2
    store.save_protection(m, caps)
    return 0


def cmd_rbac(args) -> int:
    header("Role-based access control (least privilege)")
    rbac = RBACEngine()
    rbac.define_role("reader", {("logs", "read"), ("config", "read")})
    rbac.define_role("operator", {("service", "execute"), ("logs", "write")})
    rbac.define_role("admin", {("config", "write"), ("shadow", "read")})
    pid = 101
    for r in ("reader", "operator", "admin"):
        rbac.assign(pid, r)
    print("  pid 101 is *authorised* for reader, operator, admin but activates only 'reader'")
    rbac.activate(pid, "reader")
    for obj, op in (("logs", "read"), ("config", "write"), ("shadow", "read")):
        allowed = rbac.check(pid, obj, op)
        (ok if allowed else fail)(f"{op:<7} {obj:<7} -> {'ALLOWED' if allowed else 'DENIED'}")
    print("  activating 'admin' for a maintenance window ...")
    rbac.activate(pid, "admin")
    allowed = rbac.check(pid, "config", "write")
    (ok if allowed else fail)(f"write   config  -> {'ALLOWED' if allowed else 'DENIED'}")
    rbac.deactivate(pid, "admin")
    ok("admin role dropped again; effective privileges: " + str(sorted(rbac.effective_privileges(pid))))
    try:
        rbac.activate(202, "admin")
    except AccessDenied as exc:
        fail(str(exc))
    return 0


# --------------------------------------------------------------------------- #
# Security commands
# --------------------------------------------------------------------------- #

def cmd_security(args) -> int:
    header("Threat detection")
    mon = SecurityMonitor(request_rate=10, burst=20)
    m = demo_policy()
    for dom, obj, op in (("D3", "F1", "read"), ("D1", "F3", "write"), ("D2", "F1", "execute")):
        mon.inspect_access(dom, obj, op, m.check(dom, obj, op))
    for _ in range(500):
        mon.record_request("container-flooder")
    mon.set_quota("container-miner", 10)
    mon.check_usage("container-miner", 42.5)
    mon.auth.register("alice", "correct horse battery staple")
    for guess in ("123456", "password", "alice"):
        mon.login("10.0.0.66", "alice", guess)
    mon.check_identity("pid 777", claimed_domain="D1", actual_domain="D3")
    print(mon.render())

    if args.limits:
        header("Resource limits vs. DoS (live)")
        res = run_limited(python_cmd("while True: pass"), ResourceLimits(cpu_seconds=1), timeout=20)
        (ok if res.killed_by_limit else fail)(
            f"CPU spinner with 1s RLIMIT_CPU ended by {res.signal_name or res.returncode} after {res.elapsed:.1f}s")
        res = run_limited(python_cmd("x = bytearray(512 * 1024 * 1024); print('allocated')"),
                          ResourceLimits(memory_bytes=128 * MB), timeout=20)
        if res.killed_by_limit:
            ok("512MB allocation under 128MB RLIMIT_AS -> MemoryError")
        else:
            print(yellow("  [!]  ") + "RLIMIT_AS not enforced on this kernel (macOS ignores it); "
                  "use Linux cgroups memory.max")
    return 0


# --------------------------------------------------------------------------- #
# Disk scheduler commands
# --------------------------------------------------------------------------- #

TEXTBOOK_QUEUE = [98, 183, 37, 122, 14, 124, 65, 67]


def cmd_disk(args) -> int:
    if args.random:
        rng = random.Random(args.seed)
        requests = [rng.randrange(args.size) for _ in range(args.random)]
    elif args.containers:
        q = ContainerIOQueue(DiskGeometry(cylinders=args.size, blocks_per_cylinder=16), head=args.head)
        rng = random.Random(args.seed)
        for i in range(args.containers):
            for _ in range(3):
                q.submit(f"ctr-{i}", rng.randrange(args.size * 16))
        print("  pending container requests:")
        for r in q.pending:
            print(f"    {r.container:<6} block {r.block:>5} -> cylinder {q.geometry.cylinder_of(r.block)}")
        requests = q.cylinders()
    else:
        requests = args.requests or TEXTBOOK_QUEUE
    header(f"Disk scheduling benchmark  head={args.head} cylinders=0..{args.size - 1} dir={args.direction}")
    print(f"  queue: {requests}\n")
    results = compare_all(requests, args.head, args.size, args.direction)
    print(render_benchmark(results))
    print()
    for r in results:
        extra = f"  (incl. {r.return_distance} return jump)" if r.return_distance else ""
        print(f"  {r.algorithm:<7} {args.head} -> " + " -> ".join(map(str, r.path)) + extra)
    if args.trace:
        for r in results:
            if args.trace.upper() in ("ALL", r.algorithm):
                print()
                print(render_trace(r, args.size))
    return 0


# --------------------------------------------------------------------------- #
# Guided demo
# --------------------------------------------------------------------------- #

def cmd_demo(args) -> int:
    print(bold("os-container-sandbox guided tour  (safe user-space mode, no root needed)"))
    cmd_info(args)
    cmd_modes(args)

    header("Container isolation (simulation backend)")
    rt = ContainerRuntime(force_simulation=True)
    c = rt.run(ContainerSpec(name="guest-01", hostname="guest-01",
                             command=python_cmd("import os; print('  inside guest: HOSTNAME=%s cwd=%s' % "
                                                "(os.environ['HOSTNAME'], os.getcwd()))")))
    c.wait(10)
    ok(f"guest exited with code {c.exit_code}; guest PID 1 == host PID {c.vpid_table[1]}")
    rt.shutdown()
    args.restarts = 2
    cmd_ha_demo(args)

    header("Virtual file system")
    fs = VirtualFileSystem(num_blocks=48, block_size=16, journal_blocks=4, index_capacity=16)
    fs.create("alpha", "A" * 40, "contiguous", owner_id="u1")
    fs.create("beta", "B" * 50, "linked", owner_id="u2")
    fs.create("gamma", "G" * 70, "indexed", owner_id="u1", protection="rw-------")
    fs.delete("alpha")
    fs.create("delta", "D" * 20, "contiguous")
    _print_ls(fs)
    print()
    print(fs.bit_table.render(per_row=48, labels=fs.block_labels()))
    print(f"  {fs.usage_summary()}")
    for name in ("delta", "beta", "gamma"):
        _, cost = fs.read_block(name, 1 if name == "delta" else 3)
        print(f"  direct access to block {1 if name == 'delta' else 3} of {name:<6}: {cost} disk access(es)")
    header("Journaling crash recovery")
    fs.crash_after_log = True
    try:
        fs.create("epsilon", "E" * 10)
    except SimulatedCrash as exc:
        fail(str(exc))
    print(fs.journal.render())
    fs.crash()
    print(f"  after crash: {len(fs.directory)} files visible")
    report = fs.recover()
    ok(f"recovered {len(fs.directory)} files; replayed {report['replayed']} discarded {report['discarded']}")

    header("Access matrix")
    m = demo_policy()
    print(m.render())
    p = Process(1, "editor", "D1")
    for step in ("D2", "D3"):
        m.switch(p, step)
        ok(f"switch -> {step}")
    try:
        m.switch(p, "D1")
    except AccessDenied as exc:
        fail(str(exc))
    m.copy_right("D2", "F2", "read", "D1", "limited")
    ok("D2 copied read (limited) on F2 to D1 using read*")
    try:
        m.copy_right("D3", "F2", "read", "D4")
    except AccessDenied as exc:
        fail(str(exc))
    m.control_modify("D2", "D4", "F1", "write")
    ok("D2 used control over D4 to remove write on F1")

    header("Capabilities & revocation")
    caps = CapabilitySystem()
    k1 = caps.issue("D1", "F1", {"read"}, scheme="key")
    caps.issue("D2", "F1", {"read", "write"}, scheme="key")
    ind = caps.issue("D3", "F2", {"read"}, scheme="indirection")
    caps.revoke_by_key("F1")
    caps.revoke_indirection(ind.entry_id)
    print(caps.render())
    ok(f"cap#{k1.cap_id} valid after re-key? {caps.is_valid(k1)}")

    cmd_rbac(args)
    args.limits = False
    cmd_security(args)
    args.requests, args.random, args.containers, args.trace = None, 0, 0, None
    args.head, args.size, args.direction = 53, 200, "up"
    cmd_disk(args)
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sandbox",
                                description="Lightweight OS-level virtualization & protection engine")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--state-dir", default=os.environ.get("SANDBOX_STATE_DIR", ".sandbox_state"),
                   help="where fs/protection state is persisted")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info", help="show host isolation capabilities").set_defaults(func=cmd_info)
    sub.add_parser("demo", help="guided tour of every subsystem").set_defaults(func=cmd_demo)
    sub.add_parser("modes", help="user/supervisor dual-mode demo").set_defaults(func=cmd_modes)

    def add_run_args(sp):
        sp.add_argument("--name", default="sandbox-1")
        sp.add_argument("--hostname")
        sp.add_argument("--rootfs", help="directory to chroot into (namespace mode)")
        sp.add_argument("--memory", type=int, help="memory limit in MB")
        sp.add_argument("--cpu", type=int, help="CPU-time limit in seconds")
        sp.add_argument("--nproc", type=int, help="max processes (fork-bomb guard)")
        sp.add_argument("--simulate", action="store_true", help="force user-space simulation")
        sp.add_argument("--ha", action="store_true", help="supervise with the heartbeat monitor")
        sp.add_argument("--restart", default="on-failure", choices=[r.value for r in RestartPolicy])
        sp.add_argument("--max-restarts", type=int, default=3)
        sp.add_argument("--interval", type=float, default=0.5)

    run = sub.add_parser("run", help="run a command in an isolated container")
    add_run_args(run)
    run.add_argument("command", nargs=argparse.REMAINDER, help="command (default /bin/sh)")
    run.set_defaults(func=cmd_run)
    shell = sub.add_parser("shell", help="interactive isolated shell")
    add_run_args(shell)
    shell.set_defaults(func=cmd_run, command=["/bin/sh"])

    ha = sub.add_parser("ha-demo", help="crash a guest and watch it auto-restart")
    ha.add_argument("--restarts", type=int, default=3)
    ha.set_defaults(func=cmd_ha_demo)

    # file system
    fs = sub.add_parser("fs", help="virtual file system").add_subparsers(dest="fs_cmd", required=True)
    f = fs.add_parser("init"); f.add_argument("--blocks", type=int, default=64)
    f.add_argument("--block-size", type=int, default=64); f.add_argument("--journal-blocks", type=int, default=4)
    f = fs.add_parser("create"); f.add_argument("name"); f.add_argument("--data", default="")
    f.add_argument("--size", type=int, help="pre-allocate bytes")
    f.add_argument("--method", default="indexed", choices=[m.value for m in AllocationMethod])
    f.add_argument("--owner", default="root"); f.add_argument("--protection", default="rw-r--r--")
    f = fs.add_parser("write"); f.add_argument("name"); f.add_argument("data")
    for name in ("cat", "rm", "stat"):
        fs.add_parser(name).add_argument("name")
    f = fs.add_parser("access", help="direct access cost of a logical block")
    f.add_argument("name"); f.add_argument("block", type=int)
    for name in ("ls", "bitmap", "journal", "checkpoint", "recover"):
        fs.add_parser(name)
    f = fs.add_parser("crash", help="crash in the middle of creating a file")
    f.add_argument("name", nargs="?", default="half-written"); f.add_argument("--data")
    for sp in fs.choices.values():
        sp.set_defaults(func=cmd_fs)

    # access matrix
    mx = sub.add_parser("matrix", help="access matrix").add_subparsers(dest="m_cmd", required=True)
    mx.add_parser("init"); mx.add_parser("show")
    mx.add_parser("add-domain").add_argument("name")
    mx.add_parser("add-object").add_argument("name")
    g = mx.add_parser("grant"); g.add_argument("domain"); g.add_argument("obj"); g.add_argument("rights", nargs="+")
    g = mx.add_parser("check"); g.add_argument("domain"); g.add_argument("obj"); g.add_argument("op")
    g = mx.add_parser("copy", help="propagate a starred right")
    g.add_argument("actor"); g.add_argument("obj"); g.add_argument("right"); g.add_argument("target")
    g.add_argument("--mode", default="copy", choices=["copy", "limited", "transfer"])
    for name in ("owner-grant", "owner-revoke"):
        g = mx.add_parser(name); g.add_argument("actor"); g.add_argument("obj")
        g.add_argument("target"); g.add_argument("right")
    g = mx.add_parser("control"); g.add_argument("actor"); g.add_argument("target")
    g.add_argument("obj"); g.add_argument("right"); g.add_argument("--add", action="store_true")
    g = mx.add_parser("switch"); g.add_argument("frm", metavar="FROM"); g.add_argument("to", metavar="TO")
    for sp in mx.choices.values():
        sp.set_defaults(func=cmd_matrix)

    acl = sub.add_parser("acl", help="access control lists").add_subparsers(dest="acl_cmd", required=True)
    acl.add_parser("show").add_argument("obj", nargs="?")
    g = acl.add_parser("revoke"); g.add_argument("obj"); g.add_argument("domain"); g.add_argument("right")
    for sp in acl.choices.values():
        sp.set_defaults(func=cmd_acl)

    cap = sub.add_parser("cap", help="capability lists").add_subparsers(dest="cap_cmd", required=True)
    g = cap.add_parser("issue"); g.add_argument("domain"); g.add_argument("obj"); g.add_argument("rights", nargs="+")
    g.add_argument("--scheme", default="key", choices=["key", "indirection"]); g.add_argument("--entry", type=int)
    cap.add_parser("list")
    g = cap.add_parser("check"); g.add_argument("domain"); g.add_argument("obj"); g.add_argument("op")
    cap.add_parser("revoke-key").add_argument("obj")
    cap.add_parser("revoke-entry").add_argument("entry", type=int)
    for sp in cap.choices.values():
        sp.set_defaults(func=cmd_cap)

    sub.add_parser("rbac", help="role-based access control demo").set_defaults(func=cmd_rbac)
    sec = sub.add_parser("security", help="threat detection & DoS limits demo")
    sec.add_argument("--limits", action="store_true", help="also run live rlimit experiments")
    sec.set_defaults(func=cmd_security)

    d = sub.add_parser("disk", help="disk scheduling benchmark")
    d.add_argument("--requests", type=int, nargs="+", help="cylinder queue (default: textbook queue)")
    d.add_argument("--head", type=int, default=53)
    d.add_argument("--size", type=int, default=200, help="number of cylinders")
    d.add_argument("--direction", default="up", choices=["up", "down"])
    d.add_argument("--random", type=int, default=0, help="generate N random requests")
    d.add_argument("--containers", type=int, default=0, help="simulate N containers issuing block I/O")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--trace", metavar="ALGO", help=f"plot head path for one of {ALGORITHMS} or ALL")
    d.set_defaults(func=cmd_disk)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:  # keep our output ordered with output from guest processes
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    func: Callable = args.func
    return func(args) or 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
