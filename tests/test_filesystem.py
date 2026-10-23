import pytest

from container_sandbox.filesystem import (AllocationMethod, BitTable, DiskFullError, FileExists, FileNotFound,
                                          FileSystemError, SimulatedCrash, VirtualFileSystem)


# --------------------------------------------------------------------------- bit table

def test_bit_table_starts_free():
    bt = BitTable(20)
    assert bt.free_count == 20 and bt.used_count == 0
    assert bt.to_bitstring() == "0" * 20


def test_bit_table_set_clear_and_packing():
    bt = BitTable(17)
    for b in (0, 7, 8, 16):
        bt.set(b)
    assert bt.to_bitstring() == "10000001100000001"
    assert len(bt._bits) == 3            # 17 bits packed in 3 bytes
    bt.clear(7)
    assert bt.is_free(7) and bt.is_allocated(8)


def test_bit_table_find_free_and_contiguous():
    bt = BitTable.from_bitstring("1101000111")
    assert bt.find_free(2) == [2, 4]
    assert bt.find_contiguous(3) == 4
    with pytest.raises(DiskFullError):
        bt.find_contiguous(4)
    assert bt.free_runs() == [(2, 1), (4, 3)]


def test_bit_table_bounds():
    bt = BitTable(4)
    with pytest.raises(IndexError):
        bt.set(4)


def test_external_fragmentation_metric():
    assert BitTable(8).external_fragmentation() == 0.0
    bt = BitTable.from_bitstring("01010000")
    assert bt.external_fragmentation() == pytest.approx(1 - 4 / 6)


# --------------------------------------------------------------------------- allocation

@pytest.fixture
def fs():
    return VirtualFileSystem(num_blocks=32, block_size=8, journal_blocks=2, index_capacity=8)


def test_journal_area_is_reserved(fs):
    assert fs.bit_table.is_allocated(0) and fs.bit_table.is_allocated(1)
    assert fs.bit_table.free_count == 30


def test_contiguous_allocation(fs):
    e = fs.create("a", "x" * 20, AllocationMethod.CONTIGUOUS)
    assert e.blocks == [2, 3, 4]
    assert e.address == 2
    assert all(fs.bit_table.is_allocated(b) for b in e.blocks)
    assert fs.read("a") == b"x" * 20
    assert fs.read_block("a", 2) == (b"xxxx", 1)


def test_linked_allocation_follows_pointers(fs):
    fs.create("hole", "h" * 8, "contiguous")       # block 2
    fs.create("keep", "k" * 8, "contiguous")       # block 3
    fs.delete("hole")                              # block 2 free again -> non-contiguous chain
    e = fs.create("chain", "0123456789abcdefXYZ", AllocationMethod.LINKED)
    assert e.blocks == [2, 4, 5]
    assert fs.link_ptr[2] == 4 and fs.link_ptr[4] == 5 and fs.link_ptr[5] == -1
    assert fs.read("chain") == b"0123456789abcdefXYZ"
    data, cost = fs.read_block("chain", 2)
    assert data == b"XYZ" and cost == 3            # had to walk the chain


def test_indexed_allocation_direct_access(fs):
    e = fs.create("idx", "A" * 8 + "B" * 8 + "C" * 8, AllocationMethod.INDEXED)
    assert e.index_block == e.address == 2
    assert e.blocks == [3, 4, 5]
    assert fs.bit_table.is_allocated(2)            # index block is in use too
    assert fs.read_block("idx", 2) == (b"C" * 8, 2)   # index + data
    assert fs.read("idx") == b"A" * 8 + b"B" * 8 + b"C" * 8


def test_indexed_avoids_external_fragmentation():
    fs = VirtualFileSystem(num_blocks=12, block_size=4, journal_blocks=2, index_capacity=8)
    for i in range(5):
        fs.create(f"f{i}", "xxxx" * 2, "contiguous")      # blocks 2..11 in pairs
    fs.delete("f1")
    fs.delete("f3")                                         # holes of 2 at [4,5] and [8,9]
    with pytest.raises(DiskFullError):
        fs.create("big", "y" * 12, "contiguous")           # needs 3 contiguous blocks
    e = fs.create("big", "y" * 12, "indexed")             # 1 index + 3 data across holes
    assert sorted([e.index_block] + e.blocks) == [4, 5, 8, 9]
    assert fs.read("big") == b"y" * 12


def test_index_capacity_limit():
    fs = VirtualFileSystem(num_blocks=32, block_size=4, journal_blocks=1, index_capacity=2)
    with pytest.raises(FileSystemError):
        fs.create("toolarge", "z" * 12, "indexed")


def test_directory_attributes(fs):
    e = fs.create("doc", "hello", "indexed", owner_id="alice", protection="rw-r-----", ftype="text")
    assert e.name == "doc" and e.type == "text" and e.owner_id == "alice"
    assert e.protection == "rw-r-----"
    assert e.current_length == 5
    assert e.maximum_length == 8 * 8
    assert e.date_last_accessed > 0 and e.date_last_updated > 0
    before = e.date_last_updated
    fs.chmod("doc", "r--------")
    assert fs.stat("doc").protection == "r--------"
    assert fs.stat("doc").date_last_updated >= before


def test_write_grows_and_shrinks(fs):
    fs.create("g", "a" * 4, "indexed")
    e = fs.write("g", "b" * 30)
    assert len(e.blocks) == 4 and fs.read("g") == b"b" * 30
    freed = e.blocks[1:]
    e = fs.write("g", "c")
    assert len(e.blocks) == 1
    assert all(fs.bit_table.is_free(b) for b in freed)


def test_contiguous_cannot_exceed_maximum_length(fs):
    fs.create("c", "x" * 8, "contiguous")
    with pytest.raises(FileSystemError):
        fs.write("c", "x" * 9)


def test_delete_frees_blocks(fs):
    e = fs.create("tmp", "t" * 16, "indexed")
    used = [e.index_block] + e.blocks
    fs.delete("tmp")
    assert all(fs.bit_table.is_free(b) for b in used)
    with pytest.raises(FileNotFound):
        fs.stat("tmp")


def test_duplicate_and_missing(fs):
    fs.create("x", "1")
    with pytest.raises(FileExists):
        fs.create("x", "2")
    with pytest.raises(FileNotFound):
        fs.read("nope")


def test_disk_full(fs):
    with pytest.raises(DiskFullError):
        fs.create("huge", "x" * 8 * 31, "linked")


# --------------------------------------------------------------------------- journaling

def test_every_change_is_journaled(fs):
    fs.create("a", "1")
    fs.write("a", "22")
    fs.delete("a")
    ops = [(r.kind, r.op) for r in fs.journal.records if r.kind == "BEGIN"]
    assert ops == [("BEGIN", "create"), ("BEGIN", "update"), ("BEGIN", "delete")]
    assert fs.journal.pending_txids() == []


def test_recovery_replays_committed_transactions(fs):
    fs.create("a", "alpha", "contiguous")
    fs.create("b", "bravo" * 3, "linked")
    fs.create("c", "charlie" * 2, "indexed")
    fs.delete("a")
    snapshot = (fs.bit_table.to_bitstring(), {n: e.blocks for n, e in fs.directory.items()})
    fs.crash()
    assert fs.directory == {} and fs.bit_table.used_count == 0
    report = fs.recover()
    assert report["replayed"] == [1, 2, 3, 4] and report["discarded"] == []
    assert (fs.bit_table.to_bitstring(), {n: e.blocks for n, e in fs.directory.items()}) == snapshot
    assert fs.read("b") == b"bravo" * 3
    assert fs.read("c") == b"charlie" * 2


def test_recovery_discards_uncommitted_transaction(fs):
    fs.create("safe", "s" * 10)
    fs.crash_after_log = True
    with pytest.raises(SimulatedCrash):
        fs.create("torn", "t" * 10)
    assert fs.journal.pending_txids() == [2]
    fs.crash()
    report = fs.recover()
    assert report["discarded"] == [2]
    assert set(fs.directory) == {"safe"}
    # the blocks the torn transaction wanted are still free -> no leak
    assert fs.bit_table.used_count == 2 + 1 + 2      # journal + index + data
    assert fs.journal.pending_txids() == []


def test_recovery_after_checkpoint_only_replays_tail(fs):
    fs.create("old", "o")
    fs.checkpoint()
    fs.create("new", "n")
    fs.crash()
    report = fs.recover()
    assert len(report["replayed"]) == 1
    assert set(fs.directory) == {"old", "new"}


def test_recovery_is_idempotent(fs):
    fs.create("a", "aaaa")
    fs.crash()
    fs.recover()
    first = fs.bit_table.to_bitstring()
    fs.crash()
    fs.recover()
    assert fs.bit_table.to_bitstring() == first


def test_persistence_roundtrip(fs):
    fs.create("p", "persist me", "linked")
    clone = VirtualFileSystem.from_dict(fs.to_dict())
    assert clone.read("p") == b"persist me"
    assert clone.bit_table.to_bitstring() == fs.bit_table.to_bitstring()
    clone.crash()
    clone.recover()
    assert clone.read("p") == b"persist me"
