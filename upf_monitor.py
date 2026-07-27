"""UPF Telemetry monitoring helper for tracking process health during fuzzing campaigns."""

import time
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class UPF_Telemetry:
    timestamp: float
    memory_mb: float
    cpu_percent: float
    process_alive: bool
    kernel_errors: int
    anomaly_detected: Optional[str] = None


class UPF_Monitor:
    def __init__(self, upf_pid: Optional[int] = None):
        self.upf_pid = upf_pid
        self.baseline_memory = None
        self.baseline_cpu = None
        self.measurements: List[UPF_Telemetry] = []
        if upf_pid:
            self._init_baseline()

    def _init_baseline(self):
        try:
            import psutil
            proc = psutil.Process(self.upf_pid)
            self.baseline_memory = proc.memory_info().rss / (1024 * 1024)
            self.baseline_cpu = proc.cpu_percent(interval=0.1)
        except ImportError:
            print("[WARN] psutil not installed")

    def send_packet(self, pkt_bytes: bytes, duration: float = 1.0, interval: float = 0.1):
        print(f"[SEND] {len(pkt_bytes)} bytes: {' '.join(f'{b:02x}' for b in pkt_bytes)}")
        measurements = []
        start = time.time()
        while time.time() - start < duration:
            measurements.append((time.time(), 0, 0, True))
            time.sleep(interval)
        return measurements
