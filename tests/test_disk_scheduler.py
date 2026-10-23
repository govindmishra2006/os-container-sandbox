import pytest

from container_sandbox.disk_scheduler import (ContainerIOQueue, DiskGeometry, c_look, c_scan, compare_all,
                                              fcfs, look, render_benchmark, render_trace, scan, schedule, sstf)

# Silberschatz, Operating System Concepts -- head at 53, cylinders 0..199
QUEUE = [98, 183, 37, 122, 14, 124, 65, 67]
HEAD = 53


def test_fcfs_textbook():
    r = fcfs(QUEUE, HEAD)
    assert r.path == QUEUE
    assert r.total_head_movement == 640


def test_sstf_textbook():
    r = sstf(QUEUE, HEAD)
    assert r.serviced == [65, 67, 37, 14, 98, 122, 124, 183]
    assert r.total_head_movement == 236


def test_scan_towards_zero_textbook():
    r = scan(QUEUE, HEAD, 200, "down")
    assert r.path == [37, 14, 0, 65, 67, 98, 122, 124, 183]
    assert r.total_head_movement == 236


def test_scan_up():
    r = scan(QUEUE, HEAD, 200, "up")
    assert r.path[-3:] == [199, 37, 14]
    assert r.total_head_movement == (199 - 53) + (199 - 14)


def test_c_scan_up_includes_return():
    r = c_scan(QUEUE, HEAD, 200, "up")
    assert r.path == [65, 67, 98, 122, 124, 183, 199, 0, 14, 37]
    assert r.return_distance == 199
    assert r.total_head_movement == 146 + 199 + 37
    assert r.total_head_movement - r.return_distance == 183


def test_c_scan_down():
    r = c_scan(QUEUE, HEAD, 200, "down")
    assert r.serviced == [37, 14, 183, 124, 122, 98, 67, 65]
    assert r.total_head_movement == 53 + 199 + (199 - 65)


def test_look_up_and_down():
    assert look(QUEUE, HEAD, 200, "up").total_head_movement == (183 - 53) + (183 - 14)
    assert look(QUEUE, HEAD, 200, "down").total_head_movement == (53 - 14) + (183 - 14)


def test_c_look_up():
    r = c_look(QUEUE, HEAD, 200, "up")
    assert r.path == [65, 67, 98, 122, 124, 183, 14, 37]
    assert r.return_distance == 169
    assert r.total_head_movement == 130 + 169 + 23


def test_c_look_down():
    r = c_look(QUEUE, HEAD, 200, "down")
    assert r.path == [37, 14, 183, 124, 122, 98, 67, 65]


def test_scan_without_reversal_does_not_visit_edge():
    r = scan([60, 70, 80], 50, 200, "up")
    assert r.path == [60, 70, 80]
    assert r.total_head_movement == 30


def test_request_at_head_position():
    for name in ("FCFS", "SSTF", "SCAN", "C-SCAN", "LOOK", "C-LOOK"):
        r = schedule(name, [53], 53, 200)
        assert r.total_head_movement == 0
        assert r.serviced == [53]


def test_empty_queue():
    for r in compare_all([], 10, 100):
        assert r.total_head_movement == 0
        assert r.serviced == []


def test_every_algorithm_services_every_request():
    for r in compare_all(QUEUE, HEAD, 200):
        assert sorted(r.serviced) == sorted(QUEUE)


def test_sstf_never_worse_than_fcfs_on_textbook_queue():
    results = {r.algorithm: r.total_head_movement for r in compare_all(QUEUE, HEAD)}
    assert results["SSTF"] < results["FCFS"]
    assert results["LOOK"] <= results["SCAN"]
    assert results["C-LOOK"] <= results["C-SCAN"]


@pytest.mark.parametrize("bad", [dict(requests=[250], head=10), dict(requests=[1], head=-1)])
def test_validation(bad):
    with pytest.raises(ValueError):
        fcfs(bad["requests"], bad["head"], 200)


def test_unknown_algorithm():
    with pytest.raises(ValueError):
        schedule("RANDOM", [1], 0)


def test_container_queue_dispatch_moves_head():
    q = ContainerIOQueue(DiskGeometry(cylinders=100, blocks_per_cylinder=10), head=50)
    q.submit("a", 800)   # cyl 80
    q.submit("b", 105)   # cyl 10
    q.submit("a", 555)   # cyl 55
    assert q.cylinders() == [80, 10, 55]
    r = q.dispatch("SSTF")
    assert r.serviced == [55, 80, 10]
    assert q.head == 10 and q.pending == []


def test_container_queue_rejects_out_of_range_block():
    q = ContainerIOQueue(DiskGeometry(cylinders=10, blocks_per_cylinder=4))
    with pytest.raises(ValueError):
        q.submit("a", 40)


def test_rendering_marks_best():
    text = render_benchmark(compare_all(QUEUE, HEAD))
    assert "SSTF" in text and "<- best" in text
    assert "*" in render_trace(sstf(QUEUE, HEAD), 200)
