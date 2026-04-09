# QUICK START - 5 Minutes to Running Demo

Get your project running in 5 minutes. Follow these exact steps.

---

## ⚡ Ultra-Fast Start

```bash
# Terminal 1: Start server
python3 src/test_server.py

# Terminal 2: Run analyzer
python3 src/network_analyzer.py https://localhost:8443/testfile --test

# Wait 5 minutes for completion

# Terminal 3: Generate reports
python3 src/report_generator.py results/results_*.json
```

**Done!** You have:
- 5 download results
- Performance analysis
- Generated reports

---

## 📝 Detailed Steps

### Step 1: Start HTTPS Test Server (30 seconds)

```bash
cd project15_final
python3 src/test_server.py
```

**Expected Output:**
```
Generating 10MB test file...
✓ Test file ready (10,485,760 bytes)
================================================================================
HTTPS TEST FILE SERVER
================================================================================
Host: 0.0.0.0
Port: 8443
File Size: 10 MB
URL: https://localhost:8443/testfile
================================================================================

Server ready. Waiting for connections... (Ctrl+C to stop)
```

**Leave this running!** Open a new terminal for Step 2.

---

### Step 2: Run Network Analyzer (5 minutes)

```bash
# In a NEW terminal
cd project15_final
python3 src/network_analyzer.py https://localhost:8443/testfile --test
```

**What happens:**
- 5 downloads at 1-minute intervals
- Each download will show:
  - TCP connection established
  - SSL/TLS handshake (TLSv1.3)
  - Download progress
  - Performance metrics
- Total time: 5 minutes

**Expected Output:**
```
Network Download Analyzer initialized
Target: localhost:8443
SSL/TLS: Enabled
Session ID: 20250214_143052
================================================================================
RUNNING IN TEST MODE
5 downloads at 1-minute intervals (5 minutes total)
================================================================================

================================================================================
DOWNLOAD #1
Elapsed: 0.00 hours
================================================================================

[14:30:52] Starting download #1
  Target: localhost:8443
  SSL/TLS: True
  ✓ TCP socket created
  Connecting to localhost:8443...
  ✓ TCP connection established (2.34ms)
  Initiating SSL/TLS handshake...
  ✓ SSL/TLS handshake complete (15.67ms)
  ✓ Protocol: TLSv1.3
  ...
  SUCCESS
  Status Code: 200
  File Size: 10.00 MB
  Download Time: 1.23 seconds
  Average Speed: 65.04 Mbps
  MD5 Checksum: ...
```

**Wait for all 5 downloads to complete.**

---

### Step 3: Generate Reports (30 seconds)

```bash
# After analyzer completes
python3 src/report_generator.py results/results_*.json
```

**Expected Output:**
```
Loading results from: results/results_20250214_143052.json
✓ Text report saved: reports/report_20250214_143052.txt
✓ CSV export saved: reports/data_20250214_143052.csv
✓ Markdown report saved: reports/report_20250214_143052.md

✓ Report generation complete!
```

**Check reports directory:**
```bash
ls -l reports/
# You should see:
# - report_*.txt (detailed analysis)
# - data_*.csv (Excel-compatible)
# - report_*.md (GitHub-compatible)
```

---

### Step 4: View Results (1 minute)

```bash
# View text report
cat reports/report_*.txt

# Or open in editor
nano reports/report_*.txt
```

**You'll see:**
- Overall statistics
- Download speed analysis
- Time analysis
- Hourly performance
- Detailed download log

---

## 🧪 Test Performance Testing

```bash
# Run concurrent client test
python3 tests/performance_test.py https://localhost:8443/testfile
```

**This demonstrates:**
- Multiple concurrent clients (1, 5, 10, 20)
- Thread-safe operations
- Performance under load

**Time:** 2-3 minutes

---

## 🔧 Troubleshooting Quick Fixes

### "Connection refused"
```bash
# Make sure server is running
# Check: Is Terminal 1 still showing the server?
# If not, restart: python3 src/test_server.py
```

### "No module named 'cryptography'"
```bash
# Install it (optional, only for auto cert generation)
pip install cryptography

# Or ignore - you can generate certs manually:
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
```

### "Port 8443 already in use"
```bash
# Kill existing process
lsof -i :8443
kill <PID>

# Or use different port
python3 src/test_server.py --port 9443
python3 src/network_analyzer.py https://localhost:9443/testfile --test
```

---

## 📊 What You Should See

### In Server Terminal:
```
[14:30:52] #1 127.0.0.1 - 10.0MB in 1.23s (65.04 Mbps)
[14:31:52] #2 127.0.0.1 - 10.0MB in 1.25s (64.00 Mbps)
[14:32:52] #3 127.0.0.1 - 10.0MB in 1.22s (65.57 Mbps)
[14:33:52] #4 127.0.0.1 - 10.0MB in 1.24s (64.52 Mbps)
[14:34:52] #5 127.0.0.1 - 10.0MB in 1.23s (65.04 Mbps)
```

### In Analyzer Terminal:
```
FINAL STATISTICS:
  Total Downloads: 5
  Successful: 5
  Failed: 0
  Success Rate: 100.0%

DOWNLOAD SPEED STATISTICS (Mbps):
  Average: 64.83
  Median: 65.04
  Minimum: 64.00
  Maximum: 65.57
  Range: 1.57

Results saved: results/results_20250214_143052.json
```

---

## ✅ Success Checklist

After following these steps, you should have:

- [ ] Server running on port 8443
- [ ] 5 successful downloads completed
- [ ] Results JSON file in `results/`
- [ ] 3 report files in `reports/`
- [ ] All showing SSL/TLS connections
- [ ] Performance metrics displayed

**If all checked: You're ready for demo!**

---

## 🎯 For Full 24-Hour Analysis

Instead of `--test` flag:

```bash
# Full analysis (24 hours, hourly downloads)
python3 src/network_analyzer.py https://example.com/file.zip

# Or use public test file
python3 src/network_analyzer.py https://speed.cloudflare.com/10mb.bin
```

**Then come back in 24 hours to generate reports!**

---

## 🎬 For Demo Day

1. **Start server** (show it running)
2. **Run analyzer** with `--test` (5 minutes)
3. **While waiting**, explain:
   - Socket programming (show code)
   - SSL/TLS implementation (show code)
   - Concurrent support (show threading)
4. **When complete**, generate reports
5. **Show results** in report files

**Total demo time: ~10 minutes**

---

**You're ready! Everything works!** 🚀
