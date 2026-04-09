# 📘 COMPLETE HANDBOOK - PART 2
## Project Architecture & Line-by-Line Code Explanation

---

# PART 3: PROJECT ARCHITECTURE

---

## <a name="overall-system-design"></a>🏗️ **11. OVERALL SYSTEM DESIGN**

### **The Big Picture:**

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR COMPUTER (Ubuntu)                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐                    ┌──────────────┐       │
│  │  Terminal 1  │                    │  Terminal 2  │       │
│  │              │                    │              │       │
│  │   SERVER     │◄────SSL/TLS───────┤   CLIENT A   │       │
│  │              │                    │              │       │
│  │ test_server  │                    │   network_   │       │
│  │    .py       │                    │  analyzer.py │       │
│  │              │                    │              │       │
│  │  Port: 8443  │                    │              │       │
│  └──────────────┘                    └──────────────┘       │
│         ▲                                    │               │
│         │                                    │               │
│         │                                    ▼               │
│         │                            ┌──────────────┐       │
│         │                            │ results/     │       │
│         │                            │ results.json │       │
│         │                            └──────────────┘       │
│         │                                    │               │
│         │                                    │               │
│         └────SSL/TLS───────┐                │               │
│                             │                │               │
│                      ┌──────────────┐        │               │
│                      │  Terminal 3  │        │               │
│                      │              │◄───────┘               │
│                      │   CLIENT B   │                        │
│                      │              │                        │
│                      │ performance_ │                        │
│                      │   test.py    │                        │
│                      │      +       │                        │
│                      │ report_      │                        │
│                      │ generator.py │                        │
│                      │              │                        │
│                      │              │                        │
│                      └──────────────┘                        │
│                             │                                │
│                             ▼                                │
│                      ┌──────────────┐                        │
│                      │ reports/     │                        │
│                      │ report.txt   │                        │
│                      │ data.csv     │                        │
│                      │ report.md    │                        │
│                      └──────────────┘                        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### **Communication Flow:**

**Step 1: Server Starts (Terminal 1)**
```
test_server.py:
1. Creates TCP socket
2. Binds to port 8443
3. Wraps with SSL/TLS
4. Listens for connections
5. Waits...
```

**Step 2: Client A Connects (Terminal 2)**
```
network_analyzer.py:
1. Creates TCP socket
2. Connects to localhost:8443
3. Wraps with SSL/TLS (handshake happens here)
4. Sends HTTP GET request
5. Receives file data
6. Measures speed and time
7. Saves to results JSON
8. Repeats every hour (or in test mode, every minute)
```

**Step 3: Server Responds**
```
test_server.py:
1. Accepts Client A's connection
2. Creates new thread for Client A
3. Receives HTTP request
4. Sends HTTP response + file data
5. Logs the connection
6. Closes connection
7. Goes back to waiting for more clients
```

**Step 4: Client B Tests (Terminal 3)**
```
performance_test.py:
1. Creates 1, 5, 10, 20 sockets
2. All connect simultaneously (concurrently)
3. All download file at same time
4. Measures how server handles load
5. Shows results

report_generator.py:
1. Reads results JSON from Client A
2. Calculates statistics
3. Generates 3 report formats
4. Saves to reports/ directory
```

---

## <a name="component-breakdown"></a>🧩 **12. COMPONENT BREAKDOWN**

### **Component 1: Server (test_server.py)**

**Purpose:** Serve files to clients over HTTPS

**Key Classes:**
- `HTTPSTestServer` - Main server class

**Key Methods:**
- `__init__()` - Initialize server
- `create_ssl_context()` - Setup SSL/TLS
- `_generate_test_file()` - Create test file data
- `handle_client()` - Handle one client connection
- `start()` - Main server loop

**Data Flow:**
```
1. Server starts
2. Generates 10MB test file (once, at startup)
3. Listens on port 8443
4. When client connects:
   a. Accept connection (in main thread)
   b. Create new thread for client
   c. In new thread:
      - Receive HTTP request
      - Send HTTP response
      - Send file data
      - Close connection
   d. Main thread continues accepting more clients
```

---

### **Component 2: Client A (network_analyzer.py)**

**Purpose:** Download files automatically, measure performance

**Key Classes:**
- `NetworkDownloadAnalyzer` - Main analyzer class

**Key Methods:**
- `__init__()` - Initialize analyzer
- `_parse_url()` - Parse URL into hostname, port, path
- `_create_tcp_socket()` - Create raw TCP socket
- `_wrap_ssl_socket()` - Add SSL/TLS encryption
- `_build_http_request()` - Build HTTP GET request
- `_parse_http_response()` - Parse server's response
- `download_file()` - Perform one download
- `run_analysis()` - Main loop (downloads every hour)
- `_save_results()` - Save to JSON
- `_generate_final_report()` - Print summary

**Data Flow:**
```
1. Parse URL (https://localhost:8443/testfile)
   → hostname=localhost, port=8443, use_ssl=True

2. Every hour (or minute in test mode):
   a. Create TCP socket
   b. Connect to server
   c. Wrap with SSL/TLS
   d. Send HTTP GET request
   e. Receive response (header + file)
   f. Parse response
   g. Calculate metrics:
      - Download speed (bytes/second → Mbps)
      - Download time
      - Connection time
      - SSL handshake time
   h. Save results to list
   i. Write JSON file
   j. Sleep until next hour

3. After all downloads:
   - Calculate statistics
   - Print final report
   - Save final JSON
```

---

### **Component 3: Client B Part 1 (performance_test.py)**

**Purpose:** Test server with concurrent clients

**Key Classes:**
- `PerformanceTester` - Main tester class

**Key Methods:**
- `__init__()` - Initialize tester
- `_single_download()` - One download from one client
- `test_concurrent_clients()` - Run N clients simultaneously
- `run_performance_tests()` - Run all test scenarios

**Data Flow:**
```
1. Test scenario 1: 1 client
   - Create 1 thread
   - Download file
   - Measure speed
   
2. Test scenario 2: 5 clients
   - Create 5 threads
   - All start at same time
   - All download simultaneously
   - Measure average speed

3. Test scenario 3: 10 clients
   - Same as above, but 10 threads

4. Test scenario 4: 20 clients
   - Same as above, but 20 threads

5. Compare results:
   - Speed with 1 client (baseline)
   - Speed with 20 clients (under load)
   - Show server handles concurrency
```

---

### **Component 4: Client B Part 2 (report_generator.py)**

**Purpose:** Generate human-readable reports from JSON results

**Key Functions:**
- `load_results()` - Read JSON file
- `generate_text_report()` - Create detailed text report
- `generate_csv_export()` - Create CSV for Excel
- `generate_markdown_report()` - Create markdown for GitHub

**Data Flow:**
```
1. Load results JSON
2. Parse data:
   - Extract successful downloads
   - Extract failed downloads
   - Group by hour

3. Calculate statistics:
   - Average speed
   - Median, min, max
   - Standard deviation
   - Hourly averages

4. Generate reports:
   - Text: Human-readable with tables
   - CSV: Excel-compatible
   - Markdown: GitHub-compatible

5. Save all 3 files to reports/ directory
```

---

## <a name="data-flow"></a>📊 **13. DATA FLOW**

### **Detailed Data Flow:**

**Phase 1: Server Startup**
```
1. test_server.py starts
2. Generates test file (10MB of data)
   → Stored in memory as bytes
3. Creates SSL context
   → Loads/generates server.crt and server.key
4. Creates TCP socket
5. Binds to 0.0.0.0:8443
6. Wraps socket with SSL
7. Calls listen(50)
8. Enters accept() loop
   → Blocks, waiting for clients
```

**Phase 2: Client Connection & Download**
```
1. network_analyzer.py starts
2. Parses URL:
   https://localhost:8443/testfile
   ↓
   hostname: localhost
   port: 8443
   ssl: True
   path: /testfile

3. Creates TCP socket
4. Calls connect((localhost, 8443))
   ↓
   TCP 3-way handshake:
   Client → Server: SYN
   Server → Client: SYN-ACK
   Client → Server: ACK
   ↓
   TCP connection established

5. Wraps socket with SSL
   ↓
   SSL/TLS handshake:
   Client → Server: ClientHello
   Server → Client: ServerHello + Certificate
   Client → Server: Key exchange
   Both: Switch to encrypted communication
   ↓
   SSL connection established (TLS 1.3)

6. Client sends HTTP request:
   GET /testfile HTTP/1.1\r\n
   Host: localhost:8443\r\n
   User-Agent: NetworkAnalyzer/1.0\r\n
   Connection: close\r\n
   \r\n

7. Server receives request
8. Server sends HTTP response:
   HTTP/1.1 200 OK\r\n
   Content-Type: application/octet-stream\r\n
   Content-Length: 10485760\r\n
   \r\n
   [10MB of file data]

9. Client receives data:
   - Receives in chunks (8192 bytes at a time)
   - Appends chunks to list
   - Continues until connection closes

10. Client processes:
    - Separates headers from body
    - Extracts file data
    - Calculates:
      * File size: len(body)
      * Download time: end_time - start_time
      * Speed: (file_size / download_time) * 8 / (1024*1024)
      * MD5: hashlib.md5(body).hexdigest()

11. Client stores result:
    {
      'timestamp': '2025-03-19T11:36:50',
      'success': True,
      'file_size_bytes': 10485760,
      'download_time_seconds': 0.85,
      'download_speed_mbps': 94.12,
      'md5_checksum': 'a1b2c3...'
    }

12. Client closes connection
13. Client sleeps until next hour
```

**Phase 3: Report Generation**
```
1. report_generator.py starts
2. Loads JSON file
3. Parses results array:
   [
     {download1 data},
     {download2 data},
     {download3 data},
     ...
   ]

4. Filters successful downloads:
   successful = [r for r in results if r['success']]

5. Calculates statistics:
   speeds = [r['download_speed_mbps'] for r in successful]
   average = sum(speeds) / len(speeds)
   median = sorted(speeds)[len(speeds)//2]
   min_speed = min(speeds)
   max_speed = max(speeds)
   std_dev = statistics.stdev(speeds)

6. Groups by hour:
   hourly = {}
   for result in successful:
       hour = datetime.parse(result['timestamp']).hour
       hourly[hour] = hourly.get(hour, []) + [result]

7. Generates reports:
   - Text: Formatted tables and statistics
   - CSV: Comma-separated values
   - Markdown: Tables in markdown format

8. Saves files:
   reports/report_20250319_123456.txt
   reports/data_20250319_123456.csv
   reports/report_20250319_123456.md
```

---

# PART 4: LINE-BY-LINE CODE EXPLANATION

---

## <a name="server-code"></a>🖥️ **14. SERVER CODE - test_server.py**

### **Full File Overview:**

```
Lines 1-50: Imports and class definition
Lines 51-100: Initialization and file generation
Lines 101-150: SSL certificate handling
Lines 151-200: Client connection handling
Lines 201-250: Main server loop
Lines 251-300: Statistics and cleanup
Lines 301-350: Main entry point
```

Let me explain EVERY significant line:

---

### **Lines 1-20: Imports and Documentation**

```python
#!/usr/bin/env python3
```
**What:** Shebang line
**Why:** Tells OS to use python3 to run this file
**When:** When you run `./test_server.py` directly

```python
"""
HTTPS Test File Server
Provides local testing server for the network analyzer
...
"""
```
**What:** Docstring (documentation)
**Why:** Explains what this file does
**When:** Shows up in `help(test_server)`

```python
import socket
```
**What:** Import socket module
**Why:** Need this for network communication (TCP sockets)
**When:** Used throughout to create sockets

```python
import ssl
```
**What:** Import SSL module
**Why:** Need this for HTTPS (encryption)
**When:** Used to wrap socket with TLS

```python
import threading
```
**What:** Import threading module
**Why:** Need to handle multiple clients simultaneously
**When:** Used to create thread for each client

```python
import os
```
**What:** Import os module
**Why:** Check if certificate files exist
**When:** Used in `create_ssl_context()`

```python
import time
```
**What:** Import time module
**Why:** Track connection timing
**When:** Used to measure download duration

```python
from datetime import datetime
```
**What:** Import datetime class
**Why:** Show timestamps in logs
**When:** Used in print statements

---

### **Lines 21-50: Class Definition**

```python
class HTTPSTestServer:
    """HTTPS server for local testing with SSL/TLS support."""
```
**What:** Define class for our server
**Why:** Object-oriented programming - keeps all server logic together
**How:** Class = blueprint for creating server objects

```python
def __init__(self, host='0.0.0.0', port=8443, file_size_mb=10, max_connections=50):
```
**What:** Constructor (initialization method)
**Why:** Sets up server when you create it
**When:** Called when you do `server = HTTPSTestServer()`

**Parameters explained:**
- `self` - Reference to this object (automatic in Python)
- `host='0.0.0.0'` - Listen on all network interfaces (default)
- `port=8443` - Port number for HTTPS (default)
- `file_size_mb=10` - Size of test file (default 10MB)
- `max_connections=50` - Max simultaneous connections (default)

```python
        self.host = host
        self.port = port
```
**What:** Store parameters as instance variables
**Why:** Need to remember these values for later use
**Where:** Accessible as `self.host` anywhere in the class

```python
        self.file_size_mb = file_size_mb
        self.max_connections = max_connections
        self.running = False
```
**What:** Store more instance variables
**Why:** 
- `file_size_mb` - Remember file size for generation
- `max_connections` - Remember for listen() call
- `running` - Track if server is running (for clean shutdown)

```python
        # Performance metrics
        self.total_connections = 0
        self.successful_transfers = 0
        self.failed_transfers = 0
        self.total_bytes_sent = 0
        self.lock = threading.Lock()
```
**What:** Initialize statistics variables
**Why:**
- Track performance (how many connections, how much data)
- `lock` ensures thread-safe access (multiple threads updating these)

**Why Lock?**
```python
# WITHOUT lock (WRONG):
Thread 1: reads total_connections (0)
Thread 2: reads total_connections (0)
Thread 1: writes total_connections (1)
Thread 2: writes total_connections (1)  ← Should be 2!

# WITH lock (CORRECT):
Thread 1: locks, reads (0), writes (1), unlocks
Thread 2: waits for lock, reads (1), writes (2), unlocks  ← Correct!
```

```python
        print(f"Generating {file_size_mb}MB test file...")
        self.test_file_data = self._generate_test_file(file_size_mb)
        print(f"✓ Test file ready ({len(self.test_file_data)} bytes)")
```
**What:** Generate test file during initialization
**Why:** 
- Generate once, reuse for all clients (efficient!)
- Avoids generating on each request (slow!)
**Result:** `self.test_file_data` contains 10MB of bytes

---

### **Lines 51-80: File Generation**

```python
def _generate_test_file(self, size_mb: int) -> bytes:
    """Generate test file data - pre-generated for performance"""
```
**What:** Method to create test file
**Why:** Need data to send to clients
**Return:** bytes object (binary data)

```python
        pattern = b"SERVER1_HIGH_PERFORMANCE_DATA_" * 100
```
**What:** Create a repeating pattern
**Why:** 
- `b"..."` = bytes literal (not string)
- Multiply by 100 = longer pattern
- Pattern makes file recognizable in hex dumps

**Why bytes, not string?**
```python
# String
text = "Hello"  # Unicode characters
# Network needs bytes
data = text.encode('utf-8')  # Convert to bytes

# Bytes (direct)
data = b"Hello"  # Already bytes, ready to send
```

```python
        size_bytes = size_mb * 1024 * 1024
```
**What:** Convert megabytes to bytes
**Why:** Need exact byte count
**Math:** 10 MB × 1024 KB/MB × 1024 bytes/KB = 10,485,760 bytes

```python
        repetitions = (size_bytes // len(pattern)) + 1
```
**What:** Calculate how many times to repeat pattern
**Why:** Make sure we generate enough data
**Math:** 
- `//` = integer division (no remainder)
- `+1` = ensure we have extra (trim later)

```python
        data = (pattern * repetitions)[:size_bytes]
```
**What:** Create file data and trim to exact size
**How:**
- `pattern * repetitions` = repeat pattern many times
- `[:size_bytes]` = slice to exact size needed

**Example:**
```python
pattern = b"ABC"  # 3 bytes
size_bytes = 10
repetitions = (10 // 3) + 1 = 4
data = (b"ABC" * 4)[:10]
     = b"ABCABCABCABC"[:10]
     = b"ABCABCABCA"  # Exactly 10 bytes
```

```python
        return data
```
**What:** Return the generated bytes
**Result:** Stored in `self.test_file_data`

---

### **Lines 81-150: SSL Certificate Handling**

```python
def create_ssl_context(self) -> ssl.SSLContext:
    """Create optimized SSL context"""
```
**What:** Create SSL/TLS configuration
**Why:** Need to set up encryption
**Return:** SSL context object

```python
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
```
**What:** Create server SSL context
**Why:** 
- `PROTOCOL_TLS_SERVER` = Use TLS, we're the server
- Automatically uses TLS 1.2 or 1.3 (secure!)

```python
        cert_file = 'server.crt'
        key_file = 'server.key'
```
**What:** Define certificate filenames
**Why:** These files prove our server's identity

**What's in these files?**
- `server.crt` - Public certificate (shows to clients)
- `server.key` - Private key (keep secret!)

```python
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("Certificates not found. Generating...")
            self._generate_certificates(cert_file, key_file)
```
**What:** Check if certificates exist, generate if not
**Why:** Need certificates for HTTPS
**When:** First time running, or after deleting old certificates

```python
        context.load_cert_chain(cert_file, key_file)
```
**What:** Load certificate and private key into SSL context
**Why:** SSL needs both to prove identity and encrypt
**Result:** Context ready to use for HTTPS

```python
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')
```
**What:** Configure which encryption algorithms to use
**Why:** Security - only use strong encryption
**Breakdown:**
- `HIGH` = High-strength ciphers
- `!aNULL` = Exclude no authentication
- `!eNULL` = Exclude no encryption
- `!EXPORT` = Exclude weak export ciphers
- `!DES` = Exclude DES (broken)
- `!MD5` = Exclude MD5 (weak hash)
- `!PSK` = Exclude pre-shared key
- `!RC4` = Exclude RC4 (broken)

```python
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
```
**What:** Disable old TLS versions
**Why:** TLS 1.0 and 1.1 are insecure
**Result:** Only TLS 1.2 and 1.3 allowed

**Bitwise OR explained:**
```python
# |= means "add this option"
options = 0b0000     # Start
options |= 0b0001    # Add option 1 → 0b0001
options |= 0b0010    # Add option 2 → 0b0011
# Both options now set
```

```python
        return context
```
**What:** Return configured SSL context
**Result:** Ready to wrap socket with SSL

---

### **Lines 151-220: Client Connection Handling**

```python
def handle_client(self, client_socket, address):
    """Handle client connection with optimized performance"""
```
**What:** Method to handle ONE client
**Why:** Called in separate thread for each client
**Parameters:**
- `client_socket` - Socket for this specific client
- `address` - Tuple of (ip_address, port) for this client

```python
        start_time = time.time()
```
**What:** Record when handling started
**Why:** Calculate total time to serve client
**Returns:** Seconds since epoch (like 1710851142.123456)

```python
        with self.lock:
            self.total_connections += 1
            conn_num = self.total_connections
```
**What:** Safely increment connection counter
**Why:** Multiple threads updating same variable needs lock
**How:**
- `with self.lock:` - Acquire lock
- Increment counter
- Assign connection number
- Auto-release lock when exiting `with` block

```python
        try:
```
**What:** Start try block
**Why:** Catch any errors during client handling

```python
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
```
**What:** Receive HTTP request from client
**How:**
- `recv(4096)` - Receive up to 4KB of data
- `.decode('utf-8', errors='ignore')` - Convert bytes to string
  - `errors='ignore'` - Skip invalid UTF-8 bytes

**Why 4096?**
- HTTP headers usually small (< 4KB)
- We only care about the request line
- Don't need the full request

```python
            if not request:
                return
```
**What:** If no request received, exit
**Why:** Connection might have closed immediately
**Return:** Exit this method (thread ends)

```python
            lines = request.split('\r\n')
            if len(lines) < 1:
                return
```
**What:** Split request into lines and validate
**Why:** HTTP uses \r\n as line separator
**Check:** Need at least 1 line (the request line)

```python
            request_line = lines[0]
```
**What:** Extract first line (request line)
**Example:** `"GET /testfile HTTP/1.1"`
**Why:** Contains the method and path (we don't actually use it)

```python
            response_header = f"HTTP/1.1 200 OK\r\n"
```
**What:** Start building HTTP response
**Parts:**
- `HTTP/1.1` - Protocol version
- `200` - Status code (success)
- `OK` - Status message
- `\r\n` - Line ending

```python
            response_header += f"Content-Type: application/octet-stream\r\n"
```
**What:** Add Content-Type header
**Why:** Tells client this is binary data (not text/HTML/etc)
**octet-stream:** Generic binary data

```python
            response_header += f"Content-Length: {len(self.test_file_data)}\r\n"
```
**What:** Tell client how many bytes to expect
**Why:** Client knows when download is complete
**Example:** `Content-Length: 10485760`

```python
            response_header += f"Server: Server1-HighPerf/1.0\r\n"
```
**What:** Identify our server
**Why:** Standard practice, helps debugging
**Optional:** Not required but good practice

```python
            response_header += f"X-Server-ID: SERVER1\r\n"
```
**What:** Custom header
**Why:** Identifies which server responded (if testing multiple)
**X-** prefix = custom header (not standard HTTP)

```python
            response_header += f"Connection: close\r\n"
```
**What:** Tell client we'll close connection after response
**Why:** HTTP/1.1 keeps connections alive by default, we don't want that
**Result:** Client knows to close socket after receiving

```python
            response_header += f"\r\n"
```
**What:** Blank line (CRITICAL!)
**Why:** Separates headers from body
**Without this:** Client won't know where headers end

```python
            client_socket.sendall(response_header.encode('utf-8'))
```
**What:** Send HTTP headers
**How:**
- `.encode('utf-8')` - Convert string to bytes
- `.sendall()` - Send all bytes (loops until done)

```python
            client_socket.sendall(self.test_file_data)
```
**What:** Send the actual file data
**Why:** This is what client wants to download
**Size:** 10MB

**Why two sendall() calls?**
- Could combine, but separate for clarity
- Headers = text (encoded)
- File = already bytes

```python
            duration = time.time() - start_time
```
**What:** Calculate how long transfer took
**Units:** Seconds (float, like 0.85)

```python
            speed_mbps = (len(self.test_file_data) * 8) / (duration * 1024 * 1024)
```
**What:** Calculate transfer speed in Mbps
**Math:**
```
bytes × 8 = bits
bits / seconds = bits per second (bps)
bps / (1024 × 1024) = megabits per second (Mbps)

Example:
10485760 bytes × 8 = 83886080 bits
83886080 / 0.85 seconds = 98689505.88 bps
98689505.88 / 1048576 = 94.12 Mbps
```

```python
            with self.lock:
                self.successful_transfers += 1
                self.total_bytes_sent += len(self.test_file_data)
```
**What:** Update statistics (thread-safe)
**Why:** Track server performance

```python
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - {len(self.test_file_data)/(1024*1024):.1f}MB "
                  f"in {duration:.2f}s ({speed_mbps:.2f} Mbps)")
```
**What:** Log successful transfer
**Output Example:**
```
[11:36:50] #1 127.0.0.1 - 10.0MB in 0.85s (94.12 Mbps)
```

**Format specifiers:**
- `{datetime.now().strftime('%H:%M:%S')}` - Current time
- `{conn_num}` - Connection number
- `{address[0]}` - Client IP address
- `{value:.1f}` - Float with 1 decimal place
- `{value:.2f}` - Float with 2 decimal places

```python
        except Exception as e:
            with self.lock:
                self.failed_transfers += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - ERROR: {e}")
```
**What:** Handle any errors
**Why:** Thread shouldn't crash, just log error

```python
        finally:
            try:
                client_socket.close()
            except:
                pass
```
**What:** Always close client socket
**Why:**
- Free resources
- `finally` runs even if exception occurs
- Inner `try/except` - closing might fail, ignore it

---

*[Continuing in next file due to length...]*

**This handbook continues with detailed explanation of:**
- Main server loop
- Client analyzer code (every line)
- Report generator code
- Performance tester code
- Demo Q&A preparation
- Common mistakes
- Scoring rubric alignment

Would you like me to continue with the remaining sections?
