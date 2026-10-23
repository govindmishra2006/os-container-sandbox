"""Module E -- Container Disk I/O Scheduler.

Containers share one physical (here: virtual) disk.  Every container issues
block requests; the block number is translated into a cylinder using the disk
geometry and the scheduler decides the order in which the read/write head
services the pending cylinders.

Seek time dominates disk access time, so all algorithms try to minimise the
*total head movement* (sum of |cylinder_i - cylinder_{i-1}| along the path).

Implemented algorithms (Silberschatz, *Operating System Concepts*, ch. 11):

* FCFS   -- First-Come First-Served: fair, no starvation, usually wild swings.
* SSTF   -- Shortest Seek Time First: greedy nearest request; may starve.
* SCAN   -- the elevator: sweep to one end of the disk, reverse, sweep back.
* C-SCAN -- circular SCAN: sweep to the end, jump to the other end, sweep again
            in the same direction (more uniform wait time).
* LOOK   -- SCAN that only travels as far as the last request in a direction.
* C-LOOK -- C-SCAN that only travels as far as the last request, then jumps to
            the lowest/highest pending request.

Conventions
-----------
* ``direction`` is ``"up"`` (towards higher cylinders) or ``"down"``.
* SCAN/C-SCAN only travel to the physical end of the disk when requests remain
  on the other side of the head (a sweep with nothing left to do stops early).
* The C-SCAN / C-LOOK return jump is *included* in total head movement and is
  also reported separately as ``return_distance`` so both textbook
  conventions can be read off the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Sequence

UP = "up"
DOWN = "down"

ALGORITHMS = ("FCFS", "SSTF", "SCAN", "C-SCAN", "LOOK", "C-LOOK")


@dataclass
class ScheduleResult:
    """Outcome of scheduling a request queue with one algorithm."""

    algorithm: str
    start: int
    path: List[int]                      # every head position visited, in order (excl. start)
    serviced: List[int]                  # request cylinders, in service order
    total_head_movement: int
    return_distance: int = 0             # C-SCAN / C-LOOK wrap-around jump

    @property
    def average_seek(self) -> float:
        return self.total_head_movement / len(self.serviced) if self.serviced else 0.0


def _validate(requests: Sequence[int], head: int, disk_size: int, direction: str) -> None:
    if disk_size <= 0:
        raise ValueError("disk_size must be positive")
    if not 0 <= head < disk_size:
        raise ValueError(f"head {head} outside disk [0, {disk_size - 1}]")
    for r in requests:
        if not 0 <= r < disk_size:
            raise ValueError(f"request {r} outside disk [0, {disk_size - 1}]")
    if direction not in (UP, DOWN):
        raise ValueError("direction must be 'up' or 'down'")


def _movement(start: int, path: Iterable[int]) -> int:
    total, pos = 0, start
    for p in path:
        total += abs(p - pos)
        pos = p
    return total


def fcfs(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    path = list(requests)
    return ScheduleResult("FCFS", head, path, list(path), _movement(head, path))


def sstf(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    pending = list(requests)
    pos, path = head, []
    while pending:
        # Nearest request wins; ties broken towards the lower cylinder (deterministic).
        nxt = min(pending, key=lambda c: (abs(c - pos), c))
        pending.remove(nxt)
        path.append(nxt)
        pos = nxt
    return ScheduleResult("SSTF", head, path, list(path), _movement(head, path))


def _split(requests: Sequence[int], head: int):
    lower = sorted(r for r in requests if r < head)
    upper = sorted(r for r in requests if r >= head)
    return lower, upper


def scan(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    lower, upper = _split(requests, head)
    if direction == UP:
        first, second, edge = upper, list(reversed(lower)), disk_size - 1
    else:
        first, second, edge = list(reversed(lower)), upper, 0
    path = list(first)
    if second:                       # must reverse -> sweep all the way to the edge first
        if not path or path[-1] != edge:
            path.append(edge)
        path.extend(second)
    serviced = list(first) + list(second)
    return ScheduleResult("SCAN", head, path, serviced, _movement(head, path))


def c_scan(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    lower, upper = _split(requests, head)
    if direction == UP:
        first, second, far_edge, near_edge = upper, lower, disk_size - 1, 0
    else:
        first, second, far_edge, near_edge = list(reversed(lower)), list(reversed(upper)), 0, disk_size - 1
    path = list(first)
    ret = 0
    if second:
        if not path or path[-1] != far_edge:
            path.append(far_edge)
        path.append(near_edge)
        ret = abs(far_edge - near_edge)
        path.extend(second)
    serviced = list(first) + list(second)
    return ScheduleResult("C-SCAN", head, path, serviced, _movement(head, path), ret)


def look(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    lower, upper = _split(requests, head)
    if direction == UP:
        path = upper + list(reversed(lower))
    else:
        path = list(reversed(lower)) + upper
    return ScheduleResult("LOOK", head, path, list(path), _movement(head, path))


def c_look(requests: Sequence[int], head: int, disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    _validate(requests, head, disk_size, direction)
    lower, upper = _split(requests, head)
    if direction == UP:
        first, second = upper, lower
    else:
        first, second = list(reversed(lower)), list(reversed(upper))
    path = first + second
    ret = abs(first[-1] - second[0]) if first and second else 0
    return ScheduleResult("C-LOOK", head, path, list(path), _movement(head, path), ret)


SCHEDULERS: Dict[str, Callable[..., ScheduleResult]] = {
    "FCFS": fcfs,
    "SSTF": sstf,
    "SCAN": scan,
    "C-SCAN": c_scan,
    "LOOK": look,
    "C-LOOK": c_look,
}


def schedule(algorithm: str, requests: Sequence[int], head: int,
             disk_size: int = 200, direction: str = UP) -> ScheduleResult:
    try:
        fn = SCHEDULERS[algorithm.upper()]
    except KeyError:
        raise ValueError(f"unknown algorithm {algorithm!r}; choose from {', '.join(ALGORITHMS)}") from None
    return fn(requests, head, disk_size, direction)


def compare_all(requests: Sequence[int], head: int, disk_size: int = 200,
                direction: str = UP) -> List[ScheduleResult]:
    """Run every algorithm on the same queue (in canonical order)."""
    return [SCHEDULERS[name](requests, head, disk_size, direction) for name in ALGORITHMS]


# --------------------------------------------------------------------------- #
# Container-facing request queue
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class IORequest:
    container: str
    block: int
    op: str = "read"


@dataclass
class DiskGeometry:
    cylinders: int = 200
    blocks_per_cylinder: int = 16

    def cylinder_of(self, block: int) -> int:
        cyl = block // self.blocks_per_cylinder
        if not 0 <= cyl < self.cylinders:
            raise ValueError(f"block {block} beyond disk geometry")
        return cyl


@dataclass
class ContainerIOQueue:
    """Shared queue where containers enqueue virtual disk block requests."""

    geometry: DiskGeometry = field(default_factory=DiskGeometry)
    head: int = 0
    pending: List[IORequest] = field(default_factory=list)

    def submit(self, container: str, block: int, op: str = "read") -> IORequest:
        self.geometry.cylinder_of(block)            # validate early
        req = IORequest(container, block, op)
        self.pending.append(req)
        return req

    def cylinders(self) -> List[int]:
        return [self.geometry.cylinder_of(r.block) for r in self.pending]

    def dispatch(self, algorithm: str = "SSTF", direction: str = UP) -> ScheduleResult:
        """Service every pending request, move the head, and clear the queue."""
        result = schedule(algorithm, self.cylinders(), self.head, self.geometry.cylinders, direction)
        if result.path:
            self.head = result.path[-1]
        self.pending.clear()
        return result


# --------------------------------------------------------------------------- #
# Rendering helpers (used by the CLI benchmark)
# --------------------------------------------------------------------------- #

def render_benchmark(results: Sequence[ScheduleResult], width: int = 40) -> str:
    """ASCII bar chart of total head movement, best algorithm marked."""
    if not results:
        return "(no results)"
    worst = max(r.total_head_movement for r in results) or 1
    best = min(r.total_head_movement for r in results)
    lines = [f"{'Algorithm':<8} {'Movement':>8}  {'Avg seek':>8}  Chart"]
    for r in results:
        bar = "#" * max(1, round(width * r.total_head_movement / worst)) if r.total_head_movement else ""
        mark = "  <- best" if r.total_head_movement == best else ""
        lines.append(f"{r.algorithm:<8} {r.total_head_movement:>8}  {r.average_seek:>8.1f}  {bar}{mark}")
    return "\n".join(lines)


def render_trace(result: ScheduleResult, disk_size: int, width: int = 60) -> str:
    """Plot the head's path: one row per move, '*' marks the head position."""
    scale = (width - 1) / max(1, disk_size - 1)
    rows = [f"{result.algorithm} trace (0 .. {disk_size - 1})"]
    for pos in [result.start] + result.path:
        col = round(pos * scale)
        rows.append(f"{pos:>5} |" + " " * col + "*")
    return "\n".join(rows)
