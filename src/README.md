# Automated Network Download Analyser - Source Guide

This folder contains the runnable Python programs for the Automated Network Download
Analyser. The project measures download performance over time using low-level socket
programming, HTTPS/TLS downloads, UDP control commands, optional UDP file transfer,
JSON result logging, report generation, and concurrent-client performance testing.

Run commands from the repository root:

```bash
cd "C:\Users\Merull Shah\Desktop\Code Stuff\Automated-Network-Download-Analyser"
```

On Linux/macOS, use the equivalent path to the project directory.

## Source Files

| File | Purpose |
| --- | --- |
| `network_analyzer.py` | Main client. Downloads a file repeatedly, records timing/throughput metrics, supports TCP/HTTPS and UDP file transfer. |
| `test_server.py` | Local HTTPS test server with a UDP listener for control commands and UDP file transfer. |
| `report_generator.py` | Converts JSON result files into text, CSV, Markdown, and PNG visual reports. |

## Requirements

Use Python 3.8 or newer.

Install optional dependencies:

```bash
pip install -r requirements.txt
```

The project mostly uses Python standard-library modules such as `socket`, `ssl`,
`threading`, `json`, `hashlib`, `argparse`, and `statistics`.

Optional packages:

| Package | Used For |
| --- | --- |
| `cryptography` | Auto-generating local self-signed TLS certificates if `server.crt` and `server.key` are missing. |
| `matplotlib` | Generating PNG charts from result files. |

## Network Ports

| Port | Protocol | Used By | Purpose |
| --- | --- | --- | --- |
| `8443` | TCP | `test_server.py` | HTTPS file downloads and HTTP control endpoint. |
| `9443` | UDP | `test_server.py` | UDP control commands and UDP file transfer. |

Both ports can be changed with command-line options.

## Quick Start

Terminal 1: start the local test server.

```bash
python src/test_server.py --size 10
```

Terminal 2: run a short HTTPS/TCP test download.

```bash
python src/network_analyzer.py https://localhost:8443/testfile --duration 60 --interval 30
```

Terminal 2: run a short UDP file-transfer test.

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp --duration 60 --interval 30
```

Results are saved under `results/` as JSON files.

## Running The Test Server

Basic server:

```bash
python src/test_server.py
```

Start with a 20 MB generated test file:

```bash
python src/test_server.py --size 20
```

Bind to localhost only:

```bash
python src/test_server.py --host 127.0.0.1
```

Use custom TCP and UDP ports:

```bash
python src/test_server.py --port 8444 --udp-port 9555
```

Disable UDP support:

```bash
python src/test_server.py --no-udp
```

### Server Options

| Option | Default | Description |
| --- | --- | --- |
| `-H`, `--host` | `0.0.0.0` | Address to bind. Use `127.0.0.1` for local-only testing. |
| `-p`, `--port` | `8443` | TCP HTTPS port. |
| `-s`, `--size` | `10` | Generated test file size in MB. |
| `-c`, `--max-connections` | `50` | Maximum queued TCP connections. |
| `--udp-port` | `9443` | UDP control and file-transfer port. |
| `--no-udp` | disabled | Turns off the UDP listener. |

## Running The Analyzer

The analyzer is the client that performs repeated downloads and records metrics.

Basic HTTPS/TCP download analysis:

```bash
python src/network_analyzer.py https://localhost:8443/testfile
```

Short test mode:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --test
```

Custom interval and duration:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --interval 1800 --duration 43200
```

This runs for 12 hours and starts a download every 30 minutes.

Request the server to change the generated file size before running:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --size 25
```

Run file transfer over UDP instead of HTTPS/TCP:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp
```

Run UDP transfer on a custom UDP port:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp --udp-port 9555
```

Disable UDP control commands while keeping TCP/HTTPS downloads:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --no-udp
```

Save results somewhere else:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --results-dir custom_results
```

### Analyzer Options

| Option | Default | Description |
| --- | --- | --- |
| `url` | required | HTTP or HTTPS URL to download. |
| `-i`, `--interval` | `3600` | Seconds between downloads. |
| `-d`, `--duration` | `86400` | Total run duration in seconds. |
| `-t`, `--timeout` | `300` | Socket timeout in seconds. |
| `-r`, `--results-dir` | `results` | Directory for JSON result files. |
| `--test` | disabled | Uses 5 downloads at 1-minute intervals. |
| `--udp-port` | `9443` | UDP control and file-transfer port. |
| `--no-udp` | disabled | Disables UDP control commands. |
| `--udp` | disabled | Downloads file bytes over UDP instead of TCP/HTTPS. |
| `-s`, `--size` | unset | Requests server file size in MB through UDP control. |

## TCP/HTTPS Download Mode

TCP/HTTPS is the default download mode.

In this mode, the analyzer:

- Creates a raw IPv4 TCP socket.
- Connects to the target host and TCP port.
- Wraps the socket with TLS when using an `https://` URL.
- Sends a manual HTTP `GET` request.
- Reads the full response body.
- Calculates file size, download time, speed in Mbps, and MD5 checksum.
- Saves the result into a JSON file.

Example:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --duration 300 --interval 60
```

## UDP Control Channel

The UDP control channel is enabled by default on port `9443`.

Supported UDP text commands:

| Command | Response | Description |
| --- | --- | --- |
| `PING` | `PONG` | Checks whether the UDP listener is reachable. |
| `GET_SIZE` | `SIZE:<MB>` | Returns current generated test file size. |
| `SET_SIZE:<MB>` | `OK:<MB>` or error | Changes generated file size. Valid range is 1-100 MB. |

The analyzer uses this channel automatically when `--size` is supplied:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --size 50
```

You can disable UDP control commands:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --no-udp
```

## UDP File Transfer Mode

UDP file transfer is enabled with `--udp`.

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp
```

In UDP mode, the analyzer still accepts an HTTP/HTTPS URL so it can reuse the
same hostname and configuration, but file bytes are requested from the UDP port.

UDP transfer flow:

1. Client sends `GETF` to the server UDP port.
2. Server sends the generated file in numbered UDP packets.
3. Client stores packets by sequence number.
4. Client requests missing packets with `GET_MISSING:<seq>,<seq>,...`.
5. Client reassembles the file when all packets arrive.
6. Client records checksum, size, throughput, retry count, and packet counts.

UDP data packet format:

| Field | Size | Description |
| --- | --- | --- |
| Magic | 4 bytes | `0x55445046`, representing `UDPF`. |
| Sequence number | 4 bytes | Zero-based packet index. |
| Total packets | 4 bytes | Expected number of packets. |
| Payload size | 4 bytes | Bytes in this packet payload. |
| Total file size | 4 bytes | Full file size in bytes. |
| Payload | up to 1400 bytes | File data chunk. |

UDP transfer result fields include:

- `udp_transfer`
- `packets_expected`
- `packets_received`
- `packets_retransmitted`
- `udp_retries`
- `file_size_bytes`
- `download_time_seconds`
- `download_speed_bps`
- `download_speed_mbps`
- `md5_checksum`

Important UDP limitations:

- UDP file data is not encrypted.
- UDP control commands are not authenticated.
- The retry logic requests missing packets, but it does not implement TCP-style
  congestion control.
- Firewalls must allow UDP traffic on the selected UDP port.

## HTTPS Control Endpoint

The server also supports an HTTPS control endpoint for file size changes:

```bash
curl -k -X POST https://localhost:8443/control/size/20
```

This changes the generated file size to 20 MB. The valid range is 1-100 MB.

You can query the current size:

```bash
curl -k https://localhost:8443/size
```

## Output Files

Analyzer result files are written to `results/` by default:

```text
results/results_<session_id>.json
```

Each result file contains:

- Session ID and timestamp.
- Analyzer configuration.
- Aggregate statistics.
- Per-download records.
- Success/failure status.
- Timing metrics.
- Throughput metrics.
- Checksum values.
- Error details when a download fails.
- UDP packet metrics when `--udp` is used.

## Generating Reports

After an analyzer run, generate reports from the JSON result file:

```bash
python src/report_generator.py results/results_YYYYMMDD_HHMMSS.json
```

Choose output formats:

```bash
python src/report_generator.py results/results_YYYYMMDD_HHMMSS.json --formats text csv markdown
```

Choose an output directory:

```bash
python src/report_generator.py results/results_YYYYMMDD_HHMMSS.json --output-dir reports
```

Report outputs can include:

- Text report: `reports/report_<session_id>.txt`
- CSV export: `reports/data_<session_id>.csv`
- Markdown report: `reports/report_<session_id>.md`
- Visualization chart: `reports/visualizations_<session_id>.png`
- Hourly ranking chart: `reports/hourly_ranking_<session_id>.png`

Visualization PNG files require `matplotlib`.

## Performance Testing

The performance tester is in the `tests/` folder and creates multiple concurrent
TCP/HTTPS clients.

Start the server first:

```bash
python src/test_server.py --size 10
```

Run performance tests:

```bash
python tests/performance_test.py https://localhost:8443/testfile
```

The test scenarios include:

- 1 concurrent client.
- 5 concurrent clients.
- 10 concurrent clients.
- 20 concurrent clients.

The output includes success count, average speed, average download time, minimum
speed, and maximum speed for each scenario.

## Recommended Workflows

### Local Baseline Test

```bash
python src/test_server.py --size 10
python src/network_analyzer.py https://localhost:8443/testfile --duration 300 --interval 60
```

### UDP Transfer Test

```bash
python src/test_server.py --size 10
python src/network_analyzer.py https://localhost:8443/testfile --udp --duration 300 --interval 60
```

### Compare TCP And UDP

Run TCP/HTTPS:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --duration 300 --interval 60
```

Run UDP:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp --duration 300 --interval 60
```

Compare the generated JSON files in `results/`.

### Long Monitoring Run

```bash
python src/test_server.py --size 25
python src/network_analyzer.py https://localhost:8443/testfile --interval 3600 --duration 86400
```

This runs for 24 hours and downloads once per hour.

## Troubleshooting

### Connection refused

- Confirm `test_server.py` is running.
- Confirm the analyzer URL uses the same TCP port as the server.
- Default URL for local testing is `https://localhost:8443/testfile`.

### TLS certificate warning or browser warning

The local server uses a self-signed certificate. The analyzer disables certificate
verification for local testing. For production, use a real CA-signed certificate.

### UDP commands timeout

- Confirm the server was not started with `--no-udp`.
- Confirm both server and analyzer use the same `--udp-port`.
- Confirm firewall rules allow UDP traffic on that port.

### UDP transfer is incomplete

- Try a smaller file size with `--size 1`.
- Run on localhost to confirm the baseline.
- Check for firewall, VPN, or network rules that rate-limit or drop UDP packets.

### Port already in use

Use different ports:

```bash
python src/test_server.py --port 8444 --udp-port 9555
python src/network_analyzer.py https://localhost:8444/testfile --udp-port 9555
```

### Report visualizations are missing

Install `matplotlib`:

```bash
pip install matplotlib
```

Then rerun `report_generator.py`.

## Security Notes

- TCP/HTTPS file transfer uses TLS.
- UDP file transfer is not encrypted.
- UDP control commands are not authenticated.
- Do not expose the UDP control port publicly without firewall restrictions.
- Generated SSL certificate files such as `server.crt` and `server.key` should
  not be committed for production use.

## Example Full Session

Start the server:

```bash
python src/test_server.py --size 5
```

Run a TCP/HTTPS analysis:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --duration 120 --interval 30
```

Run a UDP analysis:

```bash
python src/network_analyzer.py https://localhost:8443/testfile --udp --duration 120 --interval 30
```

Generate reports from a saved result file:

```bash
python src/report_generator.py results/results_YYYYMMDD_HHMMSS.json --formats all
```

Run concurrent-client performance testing:

```bash
python tests/performance_test.py https://localhost:8443/testfile
```
