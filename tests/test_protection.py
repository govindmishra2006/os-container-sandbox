from dataclasses import replace

import pytest

from container_sandbox.protection import (ACLStore, AccessDenied, AccessMatrix, CapabilitySystem, Process,
                                          RBACEngine, demo_policy)


@pytest.fixture
def m():
    return demo_policy()


# --------------------------------------------------------------------------- access matrix

def test_rights_enforcement(m):
    assert m.check("D1", "F1", "read")
    assert not m.check("D1", "F1", "write")
    assert m.check("D4", "F3", "write")
    assert m.check("D2", "printer", "print")
    assert not m.check("D3", "printer", "print")
    assert m.check("D2", "F2", "read")            # read* implies read


def test_enforce_raises(m):
    with pytest.raises(AccessDenied):
        m.enforce(Process(1, "p", "D3"), "F1", "read")
    m.enforce(Process(1, "p", "D3"), "F3", "execute")


def test_unknown_names(m):
    assert not m.check("D9", "F1", "read")
    with pytest.raises(KeyError):
        m.entry("D1", "nope")
    with pytest.raises(ValueError):
        m.grant("D1", "F1", "teleport")


def test_audit_log(m):
    m.check("D1", "F2", "write")
    assert m.audit[-1].startswith("DENY")


def test_domain_switching(m):
    p = Process(7, "shell", "D1")
    m.switch(p, "D2")
    assert p.domain == "D2"
    m.switch(p, "D4")
    m.switch(p, "D1")
    with pytest.raises(AccessDenied):
        m.switch(p, "D3")                           # D1 has no switch on D3
    assert p.domain == "D1"


def test_copy_right_variants(m):
    m.copy_right("D2", "F2", "read", "D1", "copy")
    assert m.entry("D1", "F2") == {"read*"}
    m.copy_right("D2", "F2", "read", "D4", "limited")
    assert m.entry("D4", "F2") == {"read"}
    with pytest.raises(AccessDenied):              # limited copy cannot propagate further
        m.copy_right("D4", "F2", "read", "D3")
    m.copy_right("D2", "F2", "read", "D3", "transfer")
    assert "read*" in m.entry("D3", "F2")
    assert not m.has("D2", "F2", "read")           # transferred away


def test_copy_requires_star(m):
    with pytest.raises(AccessDenied):
        m.copy_right("D3", "F2", "read", "D1")


def test_owner_rights(m):
    m.owner_grant("D1", "F1", "D2", "write")
    assert m.check("D2", "F1", "write")
    m.owner_revoke("D1", "F1", "D4", "write")
    assert not m.check("D4", "F1", "write")
    with pytest.raises(AccessDenied):
        m.owner_grant("D4", "F1", "D3", "read")    # D4 is not the owner


def test_control_right(m):
    assert m.check("D4", "F1", "write")
    m.control_modify("D2", "D4", "F1", "write")
    assert not m.check("D4", "F1", "write")
    m.control_modify("D2", "D4", "printer", "print", add=True)
    assert m.check("D4", "printer", "print")
    with pytest.raises(AccessDenied):
        m.control_modify("D1", "D4", "F1", "read")


def test_grant_star_supersedes_plain(m):
    m.grant("D3", "F1", "read")
    m.grant("D3", "F1", "read*")
    assert m.entry("D3", "F1") == {"read*"}
    m.grant("D3", "F1", "read")
    assert m.entry("D3", "F1") == {"read*"}


def test_matrix_roundtrip(m):
    clone = AccessMatrix.from_dict(m.to_dict())
    assert clone.render() == m.render()


# --------------------------------------------------------------------------- ACLs

def test_acl_view_matches_matrix_column(m):
    acls = ACLStore.from_matrix(m)
    assert set(acls.acls["F1"]) == {"D1", "D4"}
    assert acls.check("D4", "F1", "write")
    assert not acls.check("D2", "F1", "read")


def test_acl_immediate_revocation(m):
    acls = ACLStore.from_matrix(m)
    assert acls.check("D4", "F3", "write")
    acls.revoke("F3", "D4", "write")
    assert not acls.check("D4", "F3", "write")     # effective on the very next check
    assert acls.check("D4", "F3", "read")
    acls.revoke("F3", "D4")
    assert not acls.check("D4", "F3", "read")


def test_acl_default_set():
    acls = ACLStore()
    acls.set_default("motd", "read")
    acls.grant("motd", "admin", "read", "write")
    assert acls.check("guest", "motd", "read")
    assert not acls.check("guest", "motd", "write")
    assert acls.check("admin", "motd", "write")


# --------------------------------------------------------------------------- capabilities

def test_capability_grants_access():
    cs = CapabilitySystem()
    cs.issue("D1", "F1", {"read"})
    assert cs.check("D1", "F1", "read")
    assert not cs.check("D1", "F1", "write")
    assert not cs.check("D2", "F1", "read")


def test_key_revocation_invalidates_all_outstanding():
    cs = CapabilitySystem()
    a = cs.issue("D1", "F1", {"read"}, scheme="key")
    b = cs.issue("D2", "F1", {"read", "write"}, scheme="key")
    other = cs.issue("D1", "F2", {"read"}, scheme="key")
    cs.revoke_by_key("F1")
    assert not cs.is_valid(a) and not cs.is_valid(b)
    assert cs.is_valid(other)
    with pytest.raises(AccessDenied):
        cs.use(a, "read")
    fresh = cs.issue("D1", "F1", {"read"}, scheme="key")    # re-issued under new key
    assert cs.is_valid(fresh) and cs.check("D1", "F1", "read")


def test_indirection_revocation_is_selective():
    cs = CapabilitySystem()
    c1 = cs.issue("D1", "F1", {"read"}, scheme="indirection")
    c2 = cs.issue("D2", "F1", {"read"}, scheme="indirection", entry_id=c1.entry_id)  # shares entry
    c3 = cs.issue("D3", "F1", {"read"}, scheme="indirection")                        # own entry
    cs.revoke_indirection(c1.entry_id)
    assert not cs.is_valid(c1) and not cs.is_valid(c2)
    assert cs.is_valid(c3)
    assert cs.check("D3", "F1", "read") and not cs.check("D2", "F1", "read")


def test_forged_capability_rejected():
    cs = CapabilitySystem()
    cap = cs.issue("D1", "F1", {"read"})
    forged = replace(cap, rights=frozenset({"read", "write"}))
    assert not cs.is_valid(forged)
    with pytest.raises(AccessDenied):
        cs.use(forged, "write")


def test_capability_rights_checked_on_use():
    cs = CapabilitySystem()
    cap = cs.issue("D1", "F1", {"read"})
    cs.use(cap, "read")
    with pytest.raises(AccessDenied):
        cs.use(cap, "write")


def test_capability_roundtrip_keeps_validity():
    cs = CapabilitySystem()
    keep = cs.issue("D1", "F1", {"read"})
    dead = cs.issue("D1", "F2", {"read"}, scheme="indirection")
    cs.revoke_indirection(dead.entry_id)
    clone = CapabilitySystem.from_dict(cs.to_dict())
    assert clone.is_valid(keep) and not clone.is_valid(dead)
    new = clone.issue("D2", "F3", {"read"})
    assert new.cap_id > dead.cap_id


# --------------------------------------------------------------------------- RBAC

@pytest.fixture
def rbac():
    r = RBACEngine()
    r.define_role("reader", {("logs", "read")})
    r.define_role("admin", {("config", "write"), ("logs", "read")})
    r.assign(1, "reader")
    r.assign(1, "admin")
    return r


def test_rbac_least_privilege(rbac):
    assert not rbac.check(1, "logs", "read")       # nothing active yet
    rbac.activate(1, "reader")
    assert rbac.check(1, "logs", "read")
    assert not rbac.check(1, "config", "write")    # admin assigned but not active
    rbac.activate(1, "admin")
    assert rbac.check(1, "config", "write")
    rbac.deactivate(1, "admin")
    with pytest.raises(AccessDenied):
        rbac.enforce(1, "config", "write")


def test_rbac_cannot_activate_unassigned_role(rbac):
    with pytest.raises(AccessDenied):
        rbac.activate(2, "admin")
    with pytest.raises(KeyError):
        rbac.assign(2, "ghost")


def test_rbac_effective_privileges(rbac):
    rbac.activate(1, "reader")
    assert rbac.effective_privileges(1) == {("logs", "read")}
