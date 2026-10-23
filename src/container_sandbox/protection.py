"""Module C -- OS Protection & Access Control Engine.

Protection answers *"may a process executing in domain D perform operation
op on object O?"*.  This module implements the textbook mechanisms side by
side so their trade-offs can be demonstrated:

* **Access matrix** -- rows are domains, columns are objects, entry
  ``Access(i, j)`` is the set of operations a process in ``Domain_i`` may
  invoke on ``Object_j``.  Domains are themselves objects (columns) so that
  ``switch`` and ``control`` rights can be expressed.

* **Special rights** for dynamic protection:
    - ``owner``   -- holder may add/remove *any* right in that object's column.
    - copy ``*``  -- ``read*`` means "read, and may copy read to another domain".
                     Supports *copy*, *limited copy* and *transfer* variants.
    - ``control`` -- ``control`` in ``Access(i, D_k)`` lets ``D_i`` modify row k.
    - ``switch``  -- ``switch`` in ``Access(i, D_k)`` lets a process move from
                     ``D_i`` to ``D_k``.

* **Access Control Lists** (column-wise storage) -- revocation is
  *immediate*: delete the entry and the next check fails.

* **Capability lists** (row-wise storage) -- capabilities are unforgeable
  tickets held by domains.  Because they are scattered, revocation is done by
  **keys** (each object has a master key, re-keying invalidates all
  outstanding capabilities) or by **indirection** (capabilities point at a
  global table entry; deleting the entry kills every capability through it).

* **Role-Based Access Control** -- privileges are bundled into roles; a
  process activates only the roles it needs (*least privilege*).
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import secrets
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

OPERATIONS = ("read", "write", "execute", "print")
SPECIAL_RIGHTS = ("owner", "control", "switch")
ALL_RIGHTS = OPERATIONS + SPECIAL_RIGHTS
COPY_FLAG = "*"


class AccessDenied(PermissionError):
    """Raised when a protection check fails."""


def base_right(right: str) -> str:
    return right.rstrip(COPY_FLAG)


def is_copyable(right: str) -> bool:
    return right.endswith(COPY_FLAG)


def _validate_right(right: str) -> None:
    if base_right(right) not in ALL_RIGHTS:
        raise ValueError(f"unknown right {right!r}; valid: {', '.join(ALL_RIGHTS)} (append * for copy)")


# --------------------------------------------------------------------------- #
# Access matrix
# --------------------------------------------------------------------------- #

@dataclass
class Process:
    pid: int
    name: str
    domain: str


class AccessMatrix:
    """Sparse access matrix with dynamic-protection operations."""

    def __init__(self) -> None:
        self.domains: List[str] = []
        self.objects: List[str] = []           # includes domains as objects
        self._m: Dict[Tuple[str, str], Set[str]] = {}
        self.audit: List[str] = []

    # -- structure -----------------------------------------------------------
    def add_domain(self, name: str) -> None:
        if name not in self.domains:
            self.domains.append(name)
        if name not in self.objects:
            self.objects.append(name)

    def add_object(self, name: str) -> None:
        if name not in self.objects:
            self.objects.append(name)

    def _require(self, domain: str, obj: str) -> None:
        if domain not in self.domains:
            raise KeyError(f"unknown domain {domain!r}")
        if obj not in self.objects:
            raise KeyError(f"unknown object {obj!r}")

    def entry(self, domain: str, obj: str) -> Set[str]:
        """Access(i, j) -- a copy of the rights set."""
        self._require(domain, obj)
        return set(self._m.get((domain, obj), set()))

    def _rights(self, domain: str, obj: str) -> Set[str]:
        return self._m.setdefault((domain, obj), set())

    # -- administrative (supervisor) edits -----------------------------------
    def grant(self, domain: str, obj: str, *rights: str) -> None:
        """Kernel-level grant (used to bootstrap a policy)."""
        self._require(domain, obj)
        for r in rights:
            _validate_right(r)
            cell = self._rights(domain, obj)
            if is_copyable(r):
                cell.discard(base_right(r))
            elif r + COPY_FLAG in cell:
                continue                       # already hold the stronger form
            cell.add(r)

    def remove(self, domain: str, obj: str, right: str) -> bool:
        """Remove a right (either plain or starred form). Returns True if removed."""
        self._require(domain, obj)
        cell = self._rights(domain, obj)
        removed = False
        for form in (base_right(right), base_right(right) + COPY_FLAG):
            if form in cell:
                cell.discard(form)
                removed = True
        return removed

    # -- checks --------------------------------------------------------------
    def has(self, domain: str, obj: str, right: str) -> bool:
        if domain not in self.domains or obj not in self.objects:
            return False
        cell = self._m.get((domain, obj), set())
        return right in cell or (right + COPY_FLAG) in cell

    def check(self, domain: str, obj: str, op: str) -> bool:
        allowed = self.has(domain, obj, op)
        self.audit.append(f"{'ALLOW' if allowed else 'DENY '} {domain} {op} {obj}")
        return allowed

    def enforce(self, process: Process, obj: str, op: str) -> None:
        if not self.check(process.domain, obj, op):
            raise AccessDenied(f"pid {process.pid} in {process.domain} may not {op} {obj}")

    # -- dynamic protection --------------------------------------------------
    def copy_right(self, actor: str, obj: str, right: str, target: str, mode: str = "copy") -> None:
        """Propagate ``right`` on ``obj`` from ``actor`` to ``target``.

        Requires ``right*`` in Access(actor, obj).

        * ``copy``    -- target receives ``right*`` (may copy further)
        * ``limited`` -- target receives plain ``right``
        * ``transfer``-- target receives ``right*``; actor loses it
        """
        r = base_right(right)
        self._require(actor, obj)
        self._require(target, obj)
        if r + COPY_FLAG not in self._rights(actor, obj):
            raise AccessDenied(f"{actor} lacks {r}{COPY_FLAG} on {obj}; cannot copy")
        if mode == "copy":
            self.grant(target, obj, r + COPY_FLAG)
        elif mode == "limited":
            self.grant(target, obj, r)
        elif mode == "transfer":
            self.grant(target, obj, r + COPY_FLAG)
            self._rights(actor, obj).discard(r + COPY_FLAG)
        else:
            raise ValueError("mode must be copy, limited or transfer")
        self.audit.append(f"COPY  {actor} -> {target}: {r} on {obj} ({mode})")

    def owner_grant(self, actor: str, obj: str, target: str, right: str) -> None:
        """An owner of ``obj`` may add any right to any domain in that column."""
        if not self.has(actor, obj, "owner"):
            raise AccessDenied(f"{actor} is not owner of {obj}")
        self.grant(target, obj, right)
        self.audit.append(f"OWNER {actor} grants {right} on {obj} to {target}")

    def owner_revoke(self, actor: str, obj: str, target: str, right: str) -> bool:
        if not self.has(actor, obj, "owner"):
            raise AccessDenied(f"{actor} is not owner of {obj}")
        self.audit.append(f"OWNER {actor} revokes {right} on {obj} from {target}")
        return self.remove(target, obj, right)

    def control_modify(self, actor: str, target_domain: str, obj: str, right: str, add: bool = False) -> None:
        """``control`` in Access(actor, target_domain) lets actor edit that row."""
        if not self.has(actor, target_domain, "control"):
            raise AccessDenied(f"{actor} has no control over {target_domain}")
        if add:
            self.grant(target_domain, obj, right)
        else:
            self.remove(target_domain, obj, right)
        verb = "adds" if add else "removes"
        self.audit.append(f"CTRL  {actor} {verb} {right} on {obj} in row {target_domain}")

    def switch(self, process: Process, target_domain: str) -> Process:
        """Domain switching -- requires ``switch`` in Access(current, target)."""
        if not self.has(process.domain, target_domain, "switch"):
            self.audit.append(f"DENY  switch {process.domain} -> {target_domain}")
            raise AccessDenied(f"{process.domain} may not switch to {target_domain}")
        self.audit.append(f"SWITCH pid {process.pid}: {process.domain} -> {target_domain}")
        process.domain = target_domain
        return process

    # -- views ---------------------------------------------------------------
    def column(self, obj: str) -> Dict[str, Set[str]]:
        """The ACL view of one object (non-empty entries only)."""
        return {d: set(self._m[(d, obj)]) for d in self.domains if self._m.get((d, obj))}

    def row(self, domain: str) -> Dict[str, Set[str]]:
        """The capability-list view of one domain."""
        return {o: set(self._m[(domain, o)]) for o in self.objects if self._m.get((domain, o))}

    def render(self) -> str:
        cols = self.objects
        width = max([8] + [len(o) for o in cols]) + 2
        cell_w = max([width] + [len(",".join(sorted(v))) + 2 for v in self._m.values()])
        dom_w = max([7] + [len(d) for d in self.domains]) + 2
        header = "Domain".ljust(dom_w) + "".join(c.ljust(cell_w) for c in cols)
        lines = [header, "-" * len(header)]
        for d in self.domains:
            row = d.ljust(dom_w)
            for o in cols:
                row += (",".join(sorted(self._m.get((d, o), set()))) or ".").ljust(cell_w)
            lines.append(row)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "domains": self.domains,
            "objects": self.objects,
            "entries": [[d, o, sorted(r)] for (d, o), r in self._m.items() if r],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AccessMatrix":
        m = cls()
        m.domains = list(data["domains"])
        m.objects = list(data["objects"])
        for d, o, rights in data["entries"]:
            m._m[(d, o)] = set(rights)
        return m


# --------------------------------------------------------------------------- #
# Access control lists (column-wise)
# --------------------------------------------------------------------------- #

class ACLStore:
    """Per-object ACLs plus an optional default (applies to every domain)."""

    def __init__(self) -> None:
        self.acls: Dict[str, Dict[str, Set[str]]] = {}
        self.defaults: Dict[str, Set[str]] = {}

    @classmethod
    def from_matrix(cls, matrix: AccessMatrix) -> "ACLStore":
        store = cls()
        for obj in matrix.objects:
            col = matrix.column(obj)
            if col:
                store.acls[obj] = col
        return store

    def grant(self, obj: str, domain: str, *rights: str) -> None:
        self.acls.setdefault(obj, {}).setdefault(domain, set()).update(rights)

    def set_default(self, obj: str, *rights: str) -> None:
        self.defaults[obj] = set(rights)

    def check(self, domain: str, obj: str, op: str) -> bool:
        """Search the object's list first, then the default set."""
        entry = self.acls.get(obj, {}).get(domain)
        if entry is not None:
            return op in entry or op + COPY_FLAG in entry
        return op in self.defaults.get(obj, set())

    def revoke(self, obj: str, domain: str, right: Optional[str] = None) -> None:
        """Immediate revocation: the very next check sees the change."""
        entry = self.acls.get(obj, {}).get(domain)
        if entry is None:
            return
        if right is None:
            del self.acls[obj][domain]
        else:
            entry.discard(right)
            entry.discard(right + COPY_FLAG)

    def render(self, obj: str) -> str:
        acl = self.acls.get(obj, {})
        parts = [f"{d}:{{{','.join(sorted(r))}}}" for d, r in acl.items()]
        return f"ACL({obj}) = [" + ", ".join(parts) + "]"


# --------------------------------------------------------------------------- #
# Capability lists (row-wise) with key / indirection revocation
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Capability:
    cap_id: int
    domain: str
    obj: str
    rights: FrozenSet[str]
    scheme: str                    # "key" | "indirection"
    key: Optional[str] = None      # key scheme: snapshot of object's key at issue time
    entry_id: Optional[int] = None # indirection scheme: global table slot
    signature: str = ""            # kernel MAC -- capabilities are unforgeable


class CapabilitySystem:
    """Kernel-managed capability lists.

    Capabilities live in per-domain lists (rows of the matrix).  A user
    process can hold and present a capability but cannot fabricate one: each
    capability carries an HMAC over its fields keyed by a kernel secret.
    """

    def __init__(self, secret: Optional[bytes] = None) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self.lists: Dict[str, List[Capability]] = {}
        self.object_keys: Dict[str, str] = {}            # master key per object
        self.indirection: Dict[int, str] = {}            # entry_id -> object
        self._ids = itertools.count(1)
        self._entries = itertools.count(1)

    # -- internal ------------------------------------------------------------
    def _sign(self, cap_id, domain, obj, rights, scheme, key, entry_id) -> str:
        msg = f"{cap_id}|{domain}|{obj}|{','.join(sorted(rights))}|{scheme}|{key}|{entry_id}"
        return hmac.new(self._secret, msg.encode(), hashlib.sha256).hexdigest()

    def master_key(self, obj: str) -> str:
        return self.object_keys.setdefault(obj, secrets.token_hex(8))

    def _authentic(self, cap: Capability) -> bool:
        expected = self._sign(cap.cap_id, cap.domain, cap.obj, cap.rights, cap.scheme, cap.key, cap.entry_id)
        return hmac.compare_digest(expected, cap.signature)

    # -- issue / check -------------------------------------------------------
    def issue(self, domain: str, obj: str, rights: Iterable[str], scheme: str = "key",
              entry_id: Optional[int] = None) -> Capability:
        rights = frozenset(rights)
        for r in rights:
            _validate_right(r)
        cap_id = next(self._ids)
        key = None
        if scheme == "key":
            key = self.master_key(obj)
        elif scheme == "indirection":
            if entry_id is None:
                entry_id = next(self._entries)
                self.indirection[entry_id] = obj
            elif self.indirection.get(entry_id) != obj:
                raise ValueError(f"indirection entry {entry_id} does not point at {obj}")
        else:
            raise ValueError("scheme must be 'key' or 'indirection'")
        sig = self._sign(cap_id, domain, obj, rights, scheme, key, entry_id)
        cap = Capability(cap_id, domain, obj, rights, scheme, key, entry_id, sig)
        self.lists.setdefault(domain, []).append(cap)
        return cap

    def is_valid(self, cap: Capability) -> bool:
        if not self._authentic(cap):
            return False
        if cap.scheme == "key":
            return cap.key == self.object_keys.get(cap.obj)
        return self.indirection.get(cap.entry_id) == cap.obj

    def check(self, domain: str, obj: str, op: str) -> bool:
        """Does any *valid* capability in the domain's list grant ``op`` on ``obj``?"""
        for cap in self.lists.get(domain, []):
            if cap.obj == obj and (op in cap.rights or op + COPY_FLAG in cap.rights) and self.is_valid(cap):
                return True
        return False

    def use(self, cap: Capability, op: str) -> None:
        if not self.is_valid(cap):
            raise AccessDenied(f"capability {cap.cap_id} is revoked or forged")
        if op not in cap.rights and op + COPY_FLAG not in cap.rights:
            raise AccessDenied(f"capability {cap.cap_id} does not grant {op}")

    # -- revocation ----------------------------------------------------------
    def revoke_by_key(self, obj: str) -> str:
        """Re-key the object: every outstanding key-scheme capability dies."""
        new = secrets.token_hex(8)
        self.object_keys[obj] = new
        return new

    def revoke_indirection(self, entry_id: int) -> None:
        """Destroy one global table entry: capabilities through it die."""
        self.indirection.pop(entry_id, None)

    def valid_capabilities(self, domain: str) -> List[Capability]:
        return [c for c in self.lists.get(domain, []) if self.is_valid(c)]

    def render(self) -> str:
        lines = []
        for domain, caps in self.lists.items():
            lines.append(f"{domain}:")
            for c in caps:
                state = "valid" if self.is_valid(c) else "REVOKED"
                ref = f"key={c.key}" if c.scheme == "key" else f"entry={c.entry_id}"
                lines.append(f"  cap#{c.cap_id:<3} {c.obj:<12} {{{','.join(sorted(c.rights))}}} "
                             f"[{c.scheme} {ref}] {state}")
        return "\n".join(lines) or "(no capabilities)"

    # -- persistence ---------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "secret": self._secret.hex(),
            "object_keys": self.object_keys,
            "indirection": {str(k): v for k, v in self.indirection.items()},
            "caps": [
                {"cap_id": c.cap_id, "domain": c.domain, "obj": c.obj, "rights": sorted(c.rights),
                 "scheme": c.scheme, "key": c.key, "entry_id": c.entry_id, "signature": c.signature}
                for caps in self.lists.values() for c in caps
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CapabilitySystem":
        cs = cls(bytes.fromhex(data["secret"]))
        cs.object_keys = dict(data["object_keys"])
        cs.indirection = {int(k): v for k, v in data["indirection"].items()}
        max_id = max_entry = 0
        for c in data["caps"]:
            cap = Capability(c["cap_id"], c["domain"], c["obj"], frozenset(c["rights"]), c["scheme"],
                             c["key"], c["entry_id"], c["signature"])
            cs.lists.setdefault(cap.domain, []).append(cap)
            max_id = max(max_id, cap.cap_id)
            max_entry = max(max_entry, cap.entry_id or 0)
        cs._ids = itertools.count(max_id + 1)
        cs._entries = itertools.count(max(max_entry, *cs.indirection.keys(), 0) + 1)
        return cs


# --------------------------------------------------------------------------- #
# Role-based access control
# --------------------------------------------------------------------------- #

@dataclass
class Role:
    name: str
    privileges: Set[Tuple[str, str]] = field(default_factory=set)   # (object, operation)


class RBACEngine:
    """Roles -> privileges; processes activate only the roles they need."""

    def __init__(self) -> None:
        self.roles: Dict[str, Role] = {}
        self.assignments: Dict[int, Set[str]] = {}    # pid -> roles it MAY assume
        self.active: Dict[int, Set[str]] = {}         # pid -> roles currently active

    def define_role(self, name: str, privileges: Iterable[Tuple[str, str]]) -> Role:
        role = Role(name, set(privileges))
        self.roles[name] = role
        return role

    def assign(self, pid: int, role: str) -> None:
        if role not in self.roles:
            raise KeyError(f"unknown role {role!r}")
        self.assignments.setdefault(pid, set()).add(role)

    def activate(self, pid: int, role: str) -> None:
        if role not in self.assignments.get(pid, set()):
            raise AccessDenied(f"pid {pid} is not authorised for role {role}")
        self.active.setdefault(pid, set()).add(role)

    def deactivate(self, pid: int, role: Optional[str] = None) -> None:
        if role is None:
            self.active.pop(pid, None)
        else:
            self.active.get(pid, set()).discard(role)

    def check(self, pid: int, obj: str, op: str) -> bool:
        return any((obj, op) in self.roles[r].privileges for r in self.active.get(pid, set()))

    def enforce(self, pid: int, obj: str, op: str) -> None:
        if not self.check(pid, obj, op):
            raise AccessDenied(f"pid {pid}: no active role grants {op} on {obj}")

    def effective_privileges(self, pid: int) -> Set[Tuple[str, str]]:
        privs: Set[Tuple[str, str]] = set()
        for r in self.active.get(pid, set()):
            privs |= self.roles[r].privileges
        return privs


def demo_policy() -> AccessMatrix:
    """The classic Silberschatz example (Figs. 14.3-14.7, simplified)."""
    m = AccessMatrix()
    for d in ("D1", "D2", "D3", "D4"):
        m.add_domain(d)
    for o in ("F1", "F2", "F3", "printer"):
        m.add_object(o)
    m.grant("D1", "F1", "read", "owner")
    m.grant("D1", "F3", "read")
    m.grant("D2", "printer", "print")
    m.grant("D2", "F2", "read*", "execute")
    m.grant("D3", "F2", "read")
    m.grant("D3", "F3", "execute")
    m.grant("D4", "F1", "read", "write")
    m.grant("D4", "F3", "read", "write")
    m.grant("D1", "D2", "switch")
    m.grant("D2", "D3", "switch")
    m.grant("D2", "D4", "switch", "control")
    m.grant("D4", "D1", "switch")
    return m
