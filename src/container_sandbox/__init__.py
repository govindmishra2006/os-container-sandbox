"""os-container-sandbox: a lightweight OS-level virtualization & protection engine.

Subsystems
----------
virtualization  -- namespaces / chroot runtime, dual-mode CPU model, HA monitor
filesystem      -- bit-table free-space manager, allocation methods, journaling
protection      -- access matrix, ACLs, capabilities, RBAC
security        -- resource limits (DoS defence) and threat detection
disk_scheduler  -- FCFS / SSTF / SCAN / C-SCAN / LOOK / C-LOOK I/O scheduling
"""

__version__ = "1.0.0"

__all__ = ["virtualization", "filesystem", "protection", "security", "disk_scheduler", "__version__"]
