import pytest

from container_sandbox.cli import main


@pytest.fixture
def state(tmp_path):
    return ["--state-dir", str(tmp_path / "state")]


def test_info(capsys):
    assert main(["info"]) == 0
    assert "isolation mode" in capsys.readouterr().out


def test_disk_benchmark(capsys):
    assert main(["disk", "--trace", "SSTF"]) == 0
    out = capsys.readouterr().out
    assert "FCFS" in out and "640" in out and "236" in out and "SSTF trace" in out


def test_disk_container_mode(capsys):
    assert main(["disk", "--containers", "3"]) == 0
    assert "ctr-2" in capsys.readouterr().out


def test_fs_workflow(state, capsys):
    assert main(state + ["fs", "init", "--blocks", "32", "--block-size", "8"]) == 0
    assert main(state + ["fs", "create", "notes", "--data", "hello world", "--method", "indexed"]) == 0
    assert main(state + ["fs", "cat", "notes"]) == 0
    assert "hello world" in capsys.readouterr().out
    assert main(state + ["fs", "bitmap"]) == 0
    assert "JJJJ" in capsys.readouterr().out
    assert main(state + ["fs", "crash", "torn"]) == 0
    assert main(state + ["fs", "recover"]) == 0
    out = capsys.readouterr().out
    assert "discarded uncommitted tx [2]" in out and "notes" in out
    assert main(state + ["fs", "journal"]) == 0
    assert main(state + ["fs", "cat", "missing"]) == 1


def test_matrix_and_acl_workflow(state, capsys):
    assert main(state + ["matrix", "init"]) == 0
    assert main(state + ["matrix", "check", "D1", "F1", "read"]) == 0
    assert main(state + ["matrix", "check", "D3", "F1", "read"]) == 2
    assert main(state + ["matrix", "switch", "D1", "D2"]) == 0
    assert main(state + ["matrix", "switch", "D1", "D3"]) == 2
    assert main(state + ["matrix", "copy", "D2", "F2", "read", "D1", "--mode", "limited"]) == 0
    assert main(state + ["matrix", "check", "D1", "F2", "read"]) == 0      # persisted
    assert main(state + ["acl", "revoke", "F3", "D4", "write"]) == 0
    assert main(state + ["matrix", "check", "D4", "F3", "write"]) == 2
    assert main(state + ["acl", "show", "F3"]) == 0
    assert "ACL(F3)" in capsys.readouterr().out


def test_capability_workflow(state, capsys):
    assert main(state + ["cap", "issue", "D1", "F1", "read"]) == 0
    assert main(state + ["cap", "check", "D1", "F1", "read"]) == 0
    assert main(state + ["cap", "revoke-key", "F1"]) == 0
    assert main(state + ["cap", "list"]) == 0
    assert "REVOKED" in capsys.readouterr().out


def test_run_simulated_container(state, capsys):
    assert main(state + ["run", "--simulate", "--name", "t1", "--", "true"]) == 0
    assert "simulation" in capsys.readouterr().out


def test_demo_runs(state, capsys):
    assert main(state + ["demo"]) == 0
    out = capsys.readouterr().out
    for section in ("Dual-mode", "High-availability", "Virtual file system",
                    "Journaling", "Access matrix", "Capabilities", "Role-based", "Threat", "Disk scheduling"):
        assert section in out
