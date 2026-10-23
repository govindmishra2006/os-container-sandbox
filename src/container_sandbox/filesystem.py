"""Module B -- Virtual File System & Free-Space Manager.

Every container gets a private virtual disk made of fixed-size blocks.  This
module models the pieces of a real file system that sit between "a file" and
"a pile of disk blocks":

* **Free-space management with a bit table (bitmap).**  One bit per block:
  ``0`` = free, ``1`` = in use.  Finding *n* free blocks is a scan for zero
  bits; finding *n contiguous* free blocks is a scan for a run of zero bits.

* **Three allocation methods.**
    - *Contiguous* -- a file occupies blocks ``start .. start+n-1``.  Fast
      sequential and direct access, but suffers external fragmentation and
      the file cannot easily grow.
    - *Linked* -- each block stores a pointer to the next one.  No external
      fragmentation, but direct access to block *k* must follow *k* pointers.
    - *Indexed* -- one *index block* per file holds the addresses of all its
      data blocks.  Supports sequential **and** direct access with no external
      fragmentation (cost: one extra block per file).

* **Directory entries** carrying the classic attributes: name, type, address,
  current length, maximum length, date last accessed, date last updated,
  owner ID and protection information.

* **Journaling.**  Every metadata change is first written to a reserved
  recovery-log area (write-ahead log) as a transaction ``BEGIN ... COMMIT``.
  After a crash the directory and bit table are rebuilt from the last
  checkpoint by *redoing* committed transactions; uncommitted ones are
  discarded.  This is how ext3/ext4, NTFS and XFS recover in seconds instead
  of running a full ``fsck``.
"""

from __future__ import annotations

import copy
import enum
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple


class FileSystemError(Exception):
    """Base error for the virtual file system."""


class DiskFullError(FileSystemError):
    pass


class FileNotFound(FileSystemError):
    pass


class FileExists(FileSystemError):
    pass


class SimulatedCrash(FileSystemError):
    """Raised to emulate power loss in the middle of a metadata update."""


class AllocationMethod(str, enum.Enum):
    CONTIGUOUS = "contiguous"
    LINKED = "linked"
    INDEXED = "indexed"


# --------------------------------------------------------------------------- #
# Free-space management
# --------------------------------------------------------------------------- #

class BitTable:
    """Bit vector with one bit per disk block (0 = free, 1 = allocated)."""

    def __init__(self, num_blocks: int):
        if num_blocks <= 0:
            raise ValueError("num_blocks must be positive")
        self.num_blocks = num_blocks
        self._bits = bytearray((num_blocks + 7) // 8)

    # -- bit primitives ----------------------------------------------------
    def _check(self, block: int) -> None:
        if not 0 <= block < self.num_blocks:
            raise IndexError(f"block {block} out of range 0..{self.num_blocks - 1}")

    def is_allocated(self, block: int) -> bool:
        self._check(block)
        return bool(self._bits[block // 8] & (1 << (block % 8)))

    def is_free(self, block: int) -> bool:
        return not self.is_allocated(block)

    def set(self, block: int) -> None:
        self._check(block)
        self._bits[block // 8] |= 1 << (block % 8)

    def clear(self, block: int) -> None:
        self._check(block)
        self._bits[block // 8] &= ~(1 << (block % 8)) & 0xFF

    # -- queries -----------------------------------------------------------
    @property
    def free_count(self) -> int:
        return sum(1 for b in range(self.num_blocks) if self.is_free(b))

    @property
    def used_count(self) -> int:
        return self.num_blocks - self.free_count

    def find_free(self, count: int = 1) -> List[int]:
        """First ``count`` free blocks (any position)."""
        found = []
        for b in range(self.num_blocks):
            if self.is_free(b):
                found.append(b)
                if len(found) == count:
                    return found
        raise DiskFullError(f"need {count} free blocks, only {len(found)} available")

    def find_contiguous(self, count: int) -> int:
        """First-fit search for a run of ``count`` free blocks; returns start."""
        run_start, run_len = 0, 0
        for b in range(self.num_blocks):
            if self.is_free(b):
                if run_len == 0:
                    run_start = b
                run_len += 1
                if run_len == count:
                    return run_start
            else:
                run_len = 0
        raise DiskFullError(
            f"no contiguous run of {count} free blocks "
            f"({self.free_count} free in total -> external fragmentation)")

    def free_runs(self) -> List[Tuple[int, int]]:
        """List of (start, length) holes -- used to measure fragmentation."""
        runs, start = [], None
        for b in range(self.num_blocks + 1):
            free = b < self.num_blocks and self.is_free(b)
            if free and start is None:
                start = b
            elif not free and start is not None:
                runs.append((start, b - start))
                start = None
        return runs

    def external_fragmentation(self) -> float:
        """1 - largest_hole / total_free  (0 = no fragmentation)."""
        runs = self.free_runs()
        total = sum(n for _, n in runs)
        return 0.0 if total == 0 else 1 - max(n for _, n in runs) / total

    def to_bitstring(self) -> str:
        return "".join("1" if self.is_allocated(b) else "0" for b in range(self.num_blocks))

    @classmethod
    def from_bitstring(cls, bits: str) -> "BitTable":
        table = cls(len(bits))
        for i, ch in enumerate(bits):
            if ch == "1":
                table.set(i)
        return table

    def render(self, per_row: int = 32, labels: Optional[Dict[int, str]] = None) -> str:
        """Pretty grid of the bitmap.  ``labels`` maps block -> 1-char tag."""
        labels = labels or {}
        rows = []
        for start in range(0, self.num_blocks, per_row):
            cells = []
            for b in range(start, min(start + per_row, self.num_blocks)):
                cells.append(labels.get(b, "1" if self.is_allocated(b) else "0"))
            rows.append(f"{start:>5}: {''.join(cells)}")
        return "\n".join(rows)


# --------------------------------------------------------------------------- #
# Directory entries
# --------------------------------------------------------------------------- #

@dataclass
class DirectoryEntry:
    """File Control Block / directory record."""

    name: str
    type: str                     # e.g. "regular", "binary", "text", "dir"
    address: int                  # start block / first block / index block
    current_length: int           # bytes
    maximum_length: int           # bytes
    date_last_accessed: float
    date_last_updated: float
    owner_id: str
    protection: str               # rwx triplets, e.g. "rw-r-----"
    method: AllocationMethod
    blocks: List[int] = field(default_factory=list)       # data blocks in order
    index_block: Optional[int] = None                     # indexed allocation only

    def to_dict(self) -> dict:
        d = asdict(self)
        d["method"] = self.method.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DirectoryEntry":
        d = dict(d)
        d["method"] = AllocationMethod(d["method"])
        return cls(**d)


# --------------------------------------------------------------------------- #
# Journal (write-ahead metadata log)
# --------------------------------------------------------------------------- #

@dataclass
class JournalRecord:
    txid: int
    kind: str                  # BEGIN | COMMIT | CHECKPOINT
    op: str = ""               # create | update | delete
    name: str = ""
    entry: Optional[dict] = None
    timestamp: float = field(default_factory=time.time)


class Journal:
    """Metadata journal stored in a reserved region of the virtual disk.

    Protocol for every metadata update (redo logging):

        1. append  BEGIN(txid, op, new metadata)   -- intent is durable
        2. apply the change to the in-memory directory / bit table
        3. append  COMMIT(txid)                    -- change is now official

    ``checkpoint()`` snapshots the full metadata state and truncates the log.
    ``replay()`` returns the committed operations after the last checkpoint.
    """

    def __init__(self, reserved_blocks: List[int]):
        self.reserved_blocks = list(reserved_blocks)
        self.records: List[JournalRecord] = []
        self.checkpoint_state: Optional[dict] = None
        self._next_txid = 1

    def begin(self, op: str, name: str, entry: Optional[dict]) -> int:
        txid = self._next_txid
        self._next_txid += 1
        self.records.append(JournalRecord(txid, "BEGIN", op, name, copy.deepcopy(entry)))
        return txid

    def commit(self, txid: int) -> None:
        self.records.append(JournalRecord(txid, "COMMIT"))

    def checkpoint(self, state: dict) -> None:
        self.checkpoint_state = copy.deepcopy(state)
        self.records = [JournalRecord(0, "CHECKPOINT")]

    def committed_txids(self) -> set:
        return {r.txid for r in self.records if r.kind == "COMMIT"}

    def pending_txids(self) -> List[int]:
        done = self.committed_txids()
        return [r.txid for r in self.records if r.kind == "BEGIN" and r.txid not in done]

    def replay(self) -> List[JournalRecord]:
        done = self.committed_txids()
        return [r for r in self.records if r.kind == "BEGIN" and r.txid in done]

    def to_dict(self) -> dict:
        return {
            "reserved_blocks": self.reserved_blocks,
            "records": [asdict(r) for r in self.records],
            "checkpoint_state": self.checkpoint_state,
            "next_txid": self._next_txid,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Journal":
        j = cls(d["reserved_blocks"])
        j.records = [JournalRecord(**r) for r in d["records"]]
        j.checkpoint_state = d["checkpoint_state"]
        j._next_txid = d["next_txid"]
        return j

    def render(self) -> str:
        if not self.records:
            return "(journal empty)"
        pending = set(self.pending_txids())
        lines = [f"{'TX':>4}  {'KIND':<10} {'OP':<7} {'FILE':<16} STATUS"]
        for r in self.records:
            status = ""
            if r.kind == "BEGIN":
                status = "UNCOMMITTED (will be discarded)" if r.txid in pending else "committed"
            lines.append(f"{r.txid:>4}  {r.kind:<10} {r.op:<7} {r.name:<16} {status}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# The virtual file system
# --------------------------------------------------------------------------- #

NULL_PTR = -1


class VirtualFileSystem:
    """Block-structured file system on a simulated disk.

    The *disk* (``self.disk`` data blocks + ``self.link_ptr`` + journal area)
    survives a crash; the in-memory directory and bit table do not and are
    rebuilt by :meth:`recover`.
    """

    def __init__(self, num_blocks: int = 64, block_size: int = 64, journal_blocks: int = 4,
                 index_capacity: Optional[int] = None):
        if journal_blocks >= num_blocks:
            raise ValueError("journal area must be smaller than the disk")
        self.num_blocks = num_blocks
        self.block_size = block_size
        # an index block of size B holding 4-byte pointers
        self.index_capacity = index_capacity or max(1, block_size // 4)
        self.disk: List[bytes] = [b""] * num_blocks
        self.link_ptr: List[int] = [NULL_PTR] * num_blocks     # linked allocation pointers
        self.index_table: Dict[int, List[int]] = {}             # index block -> data blocks
        self.bit_table = BitTable(num_blocks)
        self.directory: Dict[str, DirectoryEntry] = {}

        reserved = list(range(journal_blocks))                  # recovery-log area
        for b in reserved:
            self.bit_table.set(b)
        self.journal = Journal(reserved)
        self.journal.checkpoint(self._metadata_state())
        self.crash_after_log: bool = False                       # fault injection hook

    # -- helpers -------------------------------------------------------------
    def _blocks_needed(self, nbytes: int) -> int:
        return max(1, -(-nbytes // self.block_size))

    def _metadata_state(self) -> dict:
        return {
            "bitmap": self.bit_table.to_bitstring(),
            "directory": {n: e.to_dict() for n, e in self.directory.items()},
            "index_table": {str(k): v for k, v in self.index_table.items()},
        }

    def _logged(self, op: str, name: str, entry: Optional[DirectoryEntry]) -> int:
        txid = self.journal.begin(op, name, entry.to_dict() if entry else None)
        if self.crash_after_log:
            # Intent is in the log but the change never reached the metadata and
            # no COMMIT was written: exactly the window a journal must handle.
            raise SimulatedCrash(f"power lost during tx {txid} ({op} {name})")
        return txid

    def _apply(self, op: str, name: str, entry_dict: Optional[dict]) -> None:
        """Idempotent redo of one metadata operation (used live and in recovery)."""
        if op == "delete":
            old = self.directory.pop(name, None)
            if old:
                for b in self._owned_blocks(old):
                    self.bit_table.clear(b)
                if old.index_block is not None:
                    self.index_table.pop(old.index_block, None)
            return
        entry = DirectoryEntry.from_dict(entry_dict)
        old = self.directory.get(name)
        if old:
            for b in self._owned_blocks(old):
                self.bit_table.clear(b)
        for b in self._owned_blocks(entry):
            self.bit_table.set(b)
        if entry.index_block is not None:
            self.index_table[entry.index_block] = list(entry.blocks)
        self.directory[name] = entry

    @staticmethod
    def _owned_blocks(entry: DirectoryEntry) -> List[int]:
        blocks = list(entry.blocks)
        if entry.index_block is not None:
            blocks.append(entry.index_block)
        return blocks

    def _commit(self, op: str, name: str, entry: Optional[DirectoryEntry]) -> None:
        txid = self._logged(op, name, entry)
        self._apply(op, name, entry.to_dict() if entry else None)
        self.journal.commit(txid)

    # -- allocation ----------------------------------------------------------
    def _allocate(self, method: AllocationMethod, nblocks: int) -> Tuple[int, List[int], Optional[int]]:
        """Return (address, data_blocks, index_block) without touching the bitmap."""
        if method == AllocationMethod.CONTIGUOUS:
            start = self.bit_table.find_contiguous(nblocks)
            return start, list(range(start, start + nblocks)), None
        if method == AllocationMethod.LINKED:
            blocks = self.bit_table.find_free(nblocks)
            return blocks[0], blocks, None
        if method == AllocationMethod.INDEXED:
            if nblocks > self.index_capacity:
                raise FileSystemError(
                    f"file needs {nblocks} blocks but a one-level index block holds "
                    f"{self.index_capacity} pointers")
            blocks = self.bit_table.find_free(nblocks + 1)
            index_block, data = blocks[0], blocks[1:]
            return index_block, data, index_block
        raise FileSystemError(f"unknown allocation method {method}")

    def _write_blocks(self, entry: DirectoryEntry, data: bytes) -> None:
        bs = self.block_size
        for i, b in enumerate(entry.blocks):
            self.disk[b] = data[i * bs:(i + 1) * bs]
        if entry.method == AllocationMethod.LINKED:
            for cur, nxt in zip(entry.blocks, entry.blocks[1:] + [NULL_PTR]):
                self.link_ptr[cur] = nxt
        if entry.index_block is not None:
            # the index block physically stores the pointer table
            self.disk[entry.index_block] = json.dumps(entry.blocks).encode()

    # -- public API ----------------------------------------------------------
    def create(self, name: str, data: bytes | str = b"", method: AllocationMethod | str = AllocationMethod.INDEXED,
               owner_id: str = "root", protection: str = "rw-r--r--", ftype: str = "regular",
               size: Optional[int] = None) -> DirectoryEntry:
        """Create a file.  ``size`` pre-allocates space (bytes) beyond ``data``."""
        if name in self.directory:
            raise FileExists(name)
        if isinstance(data, str):
            data = data.encode()
        method = AllocationMethod(method)
        nbytes = max(len(data), size or 0)
        nblocks = self._blocks_needed(nbytes)
        address, blocks, index_block = self._allocate(method, nblocks)
        if method == AllocationMethod.INDEXED:
            max_len = self.index_capacity * self.block_size
        elif method == AllocationMethod.CONTIGUOUS:
            max_len = nblocks * self.block_size          # cannot grow in place
        else:
            max_len = (self.num_blocks - len(self.journal.reserved_blocks)) * self.block_size
        now = time.time()
        entry = DirectoryEntry(name=name, type=ftype, address=address, current_length=len(data),
                               maximum_length=max_len, date_last_accessed=now, date_last_updated=now,
                               owner_id=owner_id, protection=protection, method=method,
                               blocks=blocks, index_block=index_block)
        self._write_blocks(entry, data)
        self._commit("create", name, entry)
        return entry

    def write(self, name: str, data: bytes | str) -> DirectoryEntry:
        """Replace a file's contents, growing/shrinking its allocation."""
        if isinstance(data, str):
            data = data.encode()
        old = self.stat(name)
        if len(data) > old.maximum_length:
            raise FileSystemError(f"{name}: {len(data)} bytes exceeds maximum length {old.maximum_length}")
        needed = self._blocks_needed(len(data))
        entry = copy.deepcopy(old)
        have = len(entry.blocks)
        if needed > have:
            extra = [b for b in self.bit_table.find_free(needed - have)]
            entry.blocks.extend(extra)
        elif needed < have:
            entry.blocks = entry.blocks[:needed]
        entry.current_length = len(data)
        entry.date_last_updated = entry.date_last_accessed = time.time()
        self._write_blocks(entry, data)
        self._commit("update", name, entry)
        return entry

    def read(self, name: str) -> bytes:
        entry = self.stat(name)
        entry.date_last_accessed = time.time()
        if entry.method == AllocationMethod.LINKED:
            out, cur = [], entry.address
            while cur != NULL_PTR and len(out) < len(entry.blocks):
                out.append(self.disk[cur])
                cur = self.link_ptr[cur]
            raw = b"".join(out)
        else:
            raw = b"".join(self.disk[b] for b in entry.blocks)
        return raw[:entry.current_length]

    def read_block(self, name: str, logical: int) -> Tuple[bytes, int]:
        """Direct access to logical block ``logical``.

        Returns ``(data, disk_accesses)`` so the cost of each allocation method
        is visible: contiguous = 1, indexed = 2 (index + data), linked = k+1.
        """
        entry = self.stat(name)
        if not 0 <= logical < len(entry.blocks):
            raise FileSystemError(f"{name}: logical block {logical} out of range")
        if entry.method == AllocationMethod.CONTIGUOUS:
            return self.disk[entry.address + logical], 1
        if entry.method == AllocationMethod.INDEXED:
            pointers = json.loads(self.disk[entry.index_block].decode())
            return self.disk[pointers[logical]], 2
        cur, accesses = entry.address, 1
        for _ in range(logical):
            cur = self.link_ptr[cur]
            accesses += 1
        return self.disk[cur], accesses

    def delete(self, name: str) -> None:
        self.stat(name)
        self._commit("delete", name, None)

    def stat(self, name: str) -> DirectoryEntry:
        try:
            return self.directory[name]
        except KeyError:
            raise FileNotFound(name) from None

    def chmod(self, name: str, protection: str) -> DirectoryEntry:
        entry = copy.deepcopy(self.stat(name))
        entry.protection = protection
        entry.date_last_updated = time.time()
        self._commit("update", name, entry)
        return entry

    def listdir(self) -> List[DirectoryEntry]:
        return sorted(self.directory.values(), key=lambda e: e.name)

    def checkpoint(self) -> None:
        self.journal.checkpoint(self._metadata_state())

    def block_labels(self) -> Dict[int, str]:
        """Map block -> tag for rendering: J journal, I index block, file initial."""
        labels = {b: "J" for b in self.journal.reserved_blocks}
        for e in self.directory.values():
            for b in e.blocks:
                labels[b] = e.name[0].upper() if e.name else "?"
            if e.index_block is not None:
                labels[e.index_block] = "I"
        return labels

    # -- crash & recovery ----------------------------------------------------
    def crash(self) -> None:
        """Lose all volatile metadata (directory, bitmap, index cache)."""
        self.directory = {}
        self.index_table = {}
        self.bit_table = BitTable(self.num_blocks)
        self.crash_after_log = False

    def recover(self) -> dict:
        """Rebuild metadata: load checkpoint, redo committed, discard the rest."""
        state = self.journal.checkpoint_state or {"bitmap": "0" * self.num_blocks,
                                                  "directory": {}, "index_table": {}}
        self.bit_table = BitTable.from_bitstring(state["bitmap"])
        for b in self.journal.reserved_blocks:
            self.bit_table.set(b)
        self.directory = {n: DirectoryEntry.from_dict(e) for n, e in state["directory"].items()}
        self.index_table = {int(k): v for k, v in state["index_table"].items()}
        discarded = self.journal.pending_txids()
        replayed = self.journal.replay()
        for rec in replayed:
            self._apply(rec.op, rec.name, rec.entry)
        # drop the incomplete transactions from the log, then checkpoint
        self.checkpoint()
        return {"replayed": [r.txid for r in replayed], "discarded": discarded}

    # -- persistence (for the CLI) ------------------------------------------
    def to_dict(self) -> dict:
        return {
            "num_blocks": self.num_blocks,
            "block_size": self.block_size,
            "index_capacity": self.index_capacity,
            "disk": [b.decode("latin-1") for b in self.disk],
            "link_ptr": self.link_ptr,
            "metadata": self._metadata_state(),
            "journal": self.journal.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "VirtualFileSystem":
        fs = cls.__new__(cls)
        fs.num_blocks = d["num_blocks"]
        fs.block_size = d["block_size"]
        fs.index_capacity = d["index_capacity"]
        fs.disk = [s.encode("latin-1") for s in d["disk"]]
        fs.link_ptr = d["link_ptr"]
        meta = d["metadata"]
        fs.bit_table = BitTable.from_bitstring(meta["bitmap"])
        fs.directory = {n: DirectoryEntry.from_dict(e) for n, e in meta["directory"].items()}
        fs.index_table = {int(k): v for k, v in meta["index_table"].items()}
        fs.journal = Journal.from_dict(d["journal"])
        fs.crash_after_log = False
        return fs

    def usage_summary(self) -> str:
        bt = self.bit_table
        return (f"blocks={self.num_blocks} block_size={self.block_size}B "
                f"used={bt.used_count} free={bt.free_count} "
                f"journal={len(self.journal.reserved_blocks)} "
                f"ext_frag={bt.external_fragmentation():.0%}")
