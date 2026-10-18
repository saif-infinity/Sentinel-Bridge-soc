"""Collector processus — psutil, cross-platform."""
import datetime
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def collect_processes(max_count: int = 500) -> list[dict]:
    if not HAS_PSUTIL:
        return []
    out = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_info"]):
        try:
            info = proc.info
            # cpu_percent needs interval 0 for non-blocking
            cpu = info.get("cpu_percent") or 0
            mem = info.get("memory_info")
            mem_kb = int(mem.rss / 1024) if mem else 0
            out.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "user": info.get("username"),
                "cmdline": " ".join(info.get("cmdline") or [])[:300],
                "cpu_pct": float(cpu),
                "mem_kb": mem_kb,
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if len(out) >= max_count:
            break
    # Top CPU first for useful batch
    out.sort(key=lambda x: x.get("cpu_pct", 0), reverse=True)
    return out[:max_count]
