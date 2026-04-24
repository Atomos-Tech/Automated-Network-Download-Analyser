# Automated Network Download Analyser

A three-person distributed tool for measuring real-world network performance. One machine runs the test server, one runs the network analyser to collect data, and one runs the report generator to produce reports and stress tests.

---

## Project Structure

```
.
├── src/
│   ├── test_server.py        # TCP/UDP test server
│   ├── network_analyzer.py   # Download analyser (data collection)
│   └── report_generator.py   # Report generation + stress tester
├── tests/
│   └── performance_test.py   # Legacy performance test script
├── docs/                     # Architecture and handbook docs
├── results/                  # JSON output from the analyser
├── reports/                  # Generated reports (TXT, CSV, MD, PNG)
└── requirements.txt
```

---

## Requirements

- Python 3.8+
- Optional: `cryptography` — auto-generates SSL certificates for TCP+SSL mode
- Optional: `matplotlib` — enables PNG chart output in reports

```bash
pip install -r requirements.txt
```

---

## Three-Person Workflow

### Person 1 — Run the Server

The server generates a test file in memory and serves it to clients over TCP or UDP.

**UDP mode** (default for stress testing):
```bash
python src/test_server.py --protocol udp --size 10
```

**TCP mode** (plain HTTP):
```bash
python src/test_server.py --protocol tcp --size 10 --no-ssl
```

**TCP mode with SSL/TLS**:
```bash
python src/test_server.py --protocol tcp --size 10
```

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol` | `tcp` | `tcp` or `udp` |
| `--host` | `0.0.0.0` | Interface to bind |
| `--port` | `8443` | Port number |
| `--size` | `10` | Test file size in MB (1–1000) |
| `--duration` | unlimited | Auto-stop after N seconds |
| `--max-connections` | `50` | Max concurrent TCP connections |
| `--no-ssl` | off | Disable SSL/TLS in TCP mode |

---

### Person 2 — Run the Network Analyser

The analyser connects to the server repeatedly over a set duration and records download metrics. Results are printed to the terminal — no files are saved.

**TCP** (use `http://` for no-SSL, `https://` for SSL):
```bash
python src/network_analyzer.py --protocol tcp http://192.168.0.215:8443/test
```

**UDP**:
```bash
python src/network_analyzer.py --protocol udp --udp-port 8443 http://192.168.0.215:8443/test
```

**Quick test mode** (5 downloads, 10-second intervals):
```bash
python src/network_analyzer.py --protocol tcp --test http://192.168.0.215:8443/test
```

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol` | `tcp` | `tcp` or `udp` |
| `--size` | — | Request a specific file size from the server in MB |
| `--duration` | `3600` | Total test duration in seconds |
| `--interval` | `60` | Seconds between downloads |
| `--timeout` | `30` | Per-connection socket timeout |
| `--udp-port` | `8443` | UDP port (UDP mode only) |
| `--test` | off | Quick 5-download test mode |

Metrics collected per download:
- Download speed (Mbps)
- Connection time (ms)
- SSL handshake time (ms, TCP+SSL only)
- File size and MD5 checksum
- UDP packet loss and retransmission counts

---

### Person 3 — Generate Reports or Run Stress Tests

The report generator has two subcommands: `report` and `stress`.

#### `report` — Generate reports from a JSON file

Takes a JSON results file produced by a previous analyser run and generates all output formats.

```bash
python src/report_generator.py report results/results_20260410_142936.json
```

```bash
# Multiple files, custom output directory
python src/report_generator.py report results/*.json --output-dir reports

# Specific formats only
python src/report_generator.py report results/*.json --formats text csv
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | `reports` | Directory for TXT/CSV/MD/PNG output |
| `--json-dir` | input file's directory | Directory to re-save the JSON |
| `--formats` | `all` | `text`, `csv`, `markdown`, or `all` |

**Output files produced:**

| File | Description |
|------|-------------|
| `report_<session>.txt` | Full text report with speed stats, hourly breakdown, congestion analysis |
| `data_<session>.csv` | Per-download row export (18 columns) |
| `report_<session>.md` | Markdown report with summary and hourly table |
| `visualizations_<session>.png` | 3-panel chart: speed over time, hourly bar chart, speed distribution |
| `hourly_ranking_<session>.png` | Horizontal bar chart ranking hours by average speed |

---

#### `stress` — Run a concurrent load test

Runs multiple scenarios of increasing concurrency against the server. Each scenario spawns N worker threads that repeatedly download the test file simultaneously for the configured duration. Results are saved as JSON and all report formats are generated automatically.

**UDP stress test**:
```bash
python src/report_generator.py stress --host 192.168.0.215 --port 8443 --protocol udp
```

**TCP stress test**:
```bash
python src/report_generator.py stress --host 192.168.0.215 --port 8443 --protocol tcp
```

**Custom scenarios**:
```bash
python src/report_generator.py stress --host 192.168.0.215 --port 8443 --protocol udp \
    --concurrency 1 5 10 20 50 --duration 60
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | required | Server hostname or IP |
| `--port` | `8443` | Server port |
| `--protocol` | `tcp` | `tcp` or `udp` |
| `--concurrency` | `1 5 10 20` | Space-separated list of client counts to test |
| `--duration` | `30` | Seconds per scenario |
| `--timeout` | `30` | Per-connection socket timeout |
| `--ssl` | off | Use HTTPS/TLS (TCP only) |
| `--path` | `/` | URL path (TCP only) |
| `--output-dir` | `reports` | Directory for report output |
| `--json-dir` | `results` | Directory for JSON output |

**Stress test output files:**

| File | Description |
|------|-------------|
| `stress_<session>.json` | Full results for all scenarios |
| `stress_report_<session>.txt` | Scenario comparison table + scaling efficiency + error breakdown |
| `stress_data_<session>.csv` | Per-download row export across all scenarios |
| `stress_report_<session>.md` | Markdown summary with scaling table |
| `stress_<session>.png` | 4-panel chart: aggregate throughput, per-client speed, success rate, connection time — all vs concurrency |

**Stress test design:**
- Uses `threading.Barrier` so all workers in a scenario start downloading simultaneously
- Workers loop continuously for the full scenario duration (not just one download each)
- Aggregate throughput is calculated as `total bytes transferred / wall-clock time`, which is more accurate than summing per-thread peaks
- The server's UDP handler runs each file transfer in its own thread, so concurrent clients don't block each other

---

## Protocol Notes

### TCP Mode

The server speaks plain HTTP/1.1 (`Connection: close`). Use `http://` in the URL when SSL is disabled (`--no-ssl`) and `https://` when SSL is enabled. The analyser disables certificate verification, so self-signed certs work fine.

### UDP Mode

The server uses a custom binary protocol:

```
Header (20 bytes, big-endian):
  magic       (4 bytes) = 0x55445046
  sequence    (4 bytes) = packet index
  total       (4 bytes) = total packet count
  chunk_size  (4 bytes) = payload length
  file_size   (4 bytes) = total file size

Payload: up to 1400 bytes
```

Client sends `GETF` (4 bytes) to request a file. Missing packets are requested with the text command `GET_MISSING:seq1,seq2,...`. File size can be changed live with `SET_SIZE:<mb>`.

---

## SSL Certificates

When running TCP with SSL, the server auto-generates a self-signed certificate on first run (requires the `cryptography` package). The files `server.crt` and `server.key` are written to the working directory. Do not commit these to version control.

To generate manually:
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
```

---

## Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `cryptography` | Optional | Auto-generate SSL certificates |
| `matplotlib` | Optional | PNG chart output in reports |

All other dependencies (`socket`, `ssl`, `threading`, `struct`, `json`, `hashlib`, `statistics`, `argparse`) are Python built-ins.
