#!/usr/bin/env python3
"""Quick correctness and load tests for osquery_exporter.

Linux only. During load tests this script monitors CPU and RSS for the
osqueryd process tree and the osquery_exporter process by reading /proc.
"""

import argparse
import os
import statistics
import subprocess
import sys
import threading
import time
import urllib.request


def fetch_metrics(base_url: str) -> str:
    with urllib.request.urlopen(base_url, timeout=30) as resp:
        return resp.read().decode("utf-8")


def find_pids_by_comm(name: str) -> list[int]:
    """Return PIDs whose /proc/PID/comm matches `name` exactly.

    Avoids pgrep because process comms are truncated to 15 bytes on many
    kernels, failing for names like "osquery_exporter".
    """
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                comm = f.read().strip()
            if comm == name:
                pids.append(int(entry))
        except Exception:
            continue
    return pids


def find_pids_by_cmdline_fragment(fragment: str) -> list[int]:
    """Return PIDs whose /proc/PID/cmdline contains the fragment."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace")
            if fragment in cmdline:
                pids.append(int(entry))
        except Exception:
            continue
    return pids


def read_stat(pid: int) -> tuple[int, int] | None:
    """Return (utime_ticks, stime_ticks) for pid, or None on failure."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            return int(parts[13]), int(parts[14])
    except Exception:
        return None


def read_rss_kb(pid: int) -> int | None:
    """Return VmRSS in kiB for pid, or None on failure."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        return None
    except Exception:
        return None


def p95(values: list[float]) -> float:
    if not values:
        return 0.0
    return sorted(values)[int(len(values) * 0.95)]


def summarize(label: str, samples: list[tuple[float, float, float]]) -> None:
    """Print mean/p95/max CPU% and RSS MiB for a set of samples."""
    if not samples:
        print(f"{label}: no samples collected")
        return
    cpus = [s[1] for s in samples]
    rss = [s[2] for s in samples]
    print(f"{label}: CPU% mean/p95/max = {statistics.mean(cpus):.1f} / {p95(cpus):.1f} / {max(cpus):.1f}")
    print(f"{label}: RSS MiB mean/p95/max = {statistics.mean(rss):.1f} / {p95(rss):.1f} / {max(rss):.1f}")


class ProcessSampler:
    """Sample aggregate CPU and RSS for a process or process tree."""

    def __init__(self, name: str, hz: float, find_pids_fn):
        self.name = name
        self.hz = hz
        self.find_pids = find_pids_fn
        # (elapsed, cpu_percent, rss_mb)
        self.samples: list[tuple[float, float, float]] = []
        self._stop = threading.Event()

    def start(self, duration: int, interval: float = 0.1) -> None:
        self._thread = threading.Thread(target=self._sample, args=(duration, interval))
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _sample(self, duration: int, interval: float) -> None:
        start = time.time()
        prev_total_cpu = 0.0
        prev_time = start
        first = True

        while time.time() - start < duration and not self._stop.is_set():
            pids = self.find_pids()
            total_cpu = 0.0
            total_rss_kb = 0
            found = False
            for pid in pids:
                stat = read_stat(pid)
                rss = read_rss_kb(pid)
                if stat is None or rss is None:
                    continue
                found = True
                total_cpu += (stat[0] + stat[1]) / self.hz
                total_rss_kb += rss

            now = time.time()
            elapsed = now - start
            if found and not first:
                cpu_delta = total_cpu - prev_total_cpu
                time_delta = now - prev_time
                cpu_percent = (cpu_delta / time_delta) * 100.0 if time_delta > 0 else 0.0
                self.samples.append((elapsed, cpu_percent, total_rss_kb / 1024.0))

            first = False
            prev_total_cpu = total_cpu
            prev_time = now

            time.sleep(interval)


def sample_baseline(samplers: list[ProcessSampler], duration: int) -> None:
    """Record baseline CPU/RSS with no synthetic load."""
    print(f"\n=== Baseline: monitoring for {duration}s with no load ===")
    for sampler in samplers:
        sampler.start(duration)
    time.sleep(duration)
    for sampler in samplers:
        sampler.stop()

    print("\n==== Process metrics ====")
    for sampler in samplers:
        summarize(sampler.name + " [baseline]", sampler.samples)
        sampler.samples.clear()


def sample_load(
    base_url: str,
    duration: int,
    concurrency: int,
    samplers: list[ProcessSampler],
) -> tuple[list[float], int]:
    """Run load test while monitoring CPU/RSS. Return latencies and error count."""
    print(f"\n=== Load test: {concurrency} clients for {duration}s ===")

    for sampler in samplers:
        sampler.start(duration)

    stop = threading.Event()
    latencies: list[float] = []
    errors: list[str] = []
    threads = [
        threading.Thread(target=_request_loop, args=(base_url, stop, latencies, errors))
        for _ in range(concurrency)
    ]

    start = time.time()
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    for sampler in samplers:
        sampler.stop()

    print(f"requests: {len(latencies)}")
    print(f"errors: {len(errors)}")
    print(f"req/sec: {len(latencies) / elapsed:.1f}")
    if latencies:
        print(f"latency p50: {statistics.median(latencies):.1f}ms")
        print(f"latency p95: {sorted(latencies)[int(len(latencies) * 0.95)]:.1f}ms")
        print(f"latency min/max: {min(latencies):.1f}ms / {max(latencies):.1f}ms")
    if errors:
        print(f"first error: {errors[0]}")

    print("\n==== Process metrics ====")
    for sampler in samplers:
        summarize(sampler.name + " [under load]", sampler.samples)

    return latencies, len(errors)


def _request_loop(base_url: str, stop: threading.Event, latencies: list[float], errors: list[str]) -> None:
    while not stop.is_set():
        t0 = time.time()
        try:
            fetch_metrics(base_url)
            latencies.append((time.time() - t0) * 1000)
        except Exception as e:
            errors.append(str(e))
        # yield so /proc sampler threads get scheduled
        time.sleep(0.001)


def test_correctness(base_url: str, expected_names: list[str]) -> bool:
    print("=== Correctness tests ===")
    payload = fetch_metrics(base_url)
    ok = True

    if not payload:
        print("FAIL: empty response")
        return False
    print("PASS: non-empty response")

    for name in expected_names:
        if name not in payload:
            print(f"FAIL: expected metric {name} not found")
            ok = False
        else:
            print(f"PASS: found {name}")

    for line in payload.splitlines():
        if line.startswith("osquery_exporter_query_success{"):
            _, val = line.rsplit(" ", 1)
            if float(val) != 1:
                print(f"FAIL: query not successful: {line}")
                ok = False
    if ok:
        print("PASS: all osquery_exporter_query_success == 1")

    prom_errs = 0.0
    for line in payload.splitlines():
        if line.startswith("promhttp_metric_handler_errors_total{cause=\"gathering\"}"):
            _, val = line.rsplit(" ", 1)
            prom_errs = float(val)
    if prom_errs != 0:
        print(f"FAIL: promhttp gathering errors: {prom_errs}")
        ok = False
    else:
        print("PASS: no promhttp gathering errors")

    return ok


def build_samplers(hz: float, enable_monitoring: bool) -> list[ProcessSampler]:
    if not enable_monitoring:
        return []
    return [
        ProcessSampler("osqueryd", hz, lambda: find_pids_by_comm("osqueryd")),
        ProcessSampler("osquery_exporter", hz, lambda: find_pids_by_cmdline_fragment("osquery_exporter")),
    ]


def main() -> int:
    if not os.path.isdir("/proc"):
        print("ERROR: /proc is not available. This script is Linux only.", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(description="Test osquery_exporter")
    parser.add_argument("--url", default="http://localhost:9232/metrics")
    parser.add_argument("--expected-metric", action="append", default=[],
                        help="metric name expected in output (repeatable)")
    parser.add_argument("--load-duration", type=int, default=10,
                        help="Duration of the load test in seconds")
    parser.add_argument("--load-concurrency", type=int, default=1,
                        help="Number of concurrent scrapers during load test (default exporter limit is 2)")
    parser.add_argument("--baseline-duration", type=int, default=10,
                        help="Duration of the idle baseline monitoring period before load test")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="Skip the idle baseline and run load test immediately")
    parser.add_argument("--load-only", action="store_true")
    parser.add_argument("--correctness-only", action="store_true")
    parser.add_argument("--no-process-monitor", action="store_true",
                        help="Disable CPU/RSS sampling")
    args = parser.parse_args()

    defaults = [
        "osquery_exporter_query_success",
        "osquery_exporter_query_duration_seconds_count",
        "osquery_exporter_resultsets",
    ]
    expected = args.expected_metric or defaults

    hz = os.sysconf("SC_CLK_TCK")
    samplers = build_samplers(hz, not args.no_process_monitor)

    ok = True
    if not args.load_only and not test_correctness(args.url, expected):
        ok = False

    if not args.correctness_only:
        if not args.skip_baseline:
            sample_baseline(samplers, args.baseline_duration)
        _, errors = sample_load(args.url, args.load_duration, args.load_concurrency, samplers)
        if errors > 0:
            ok = False

    print()
    if ok:
        print("ALL PASS")
        return 0
    print("SOME TESTS FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
