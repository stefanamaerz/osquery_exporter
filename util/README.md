# util

Helper scripts for osquery_exporter.

## test_exporter.py

Correctness and load-tests the exporter on Linux. Monitors CPU/RSS of the osqueryd tree and the exporter.

```bash
python3 util/test_exporter.py --url http://localhost:9232/metrics
```

Modes:

```bash
# Only validate that /metrics returns the expected metrics
python3 util/test_exporter.py --correctness-only

# Only run load test
python3 util/test_exporter.py --load-only --load-concurrency 5 --load-duration 30

# Baseline for 10s, then load-test for 30s at 5 clients
python3 util/test_exporter.py --load-concurrency 5 --load-duration 30

# Disable /proc CPU/RSS monitoring
python3 util/test_exporter.py --no-process-monitor
```
