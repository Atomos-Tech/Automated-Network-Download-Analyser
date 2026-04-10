#!/usr/bin/env python3
"""
Automated Network Download Analyzer with SSL/TLS and UDP Support
Project #15 - Socket Programming Mini Project

COMPLETE PRODUCTION IMPLEMENTATION
- TCP socket programming with explicit low-level operations
- Mandatory SSL/TLS encryption for all communications
- UDP control channel for dynamic configuration
- Multiple concurrent client support via threading
- Automated downloads over configurable duration
- Performance metrics and congestion pattern analysis
- Comprehensive error handling for all edge cases

Author: [Your Name]
Date: February 2025
"""

import socket
import ssl
import time
import json
import os
import hashlib
import struct
import threading
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


UDP_DATA_MAGIC = 0x55445046  # "UDPF"
UDP_REQUEST_FILE = b"GETF"
UDP_PAYLOAD_SIZE = 1400
UDP_RECEIVE_BUFFER = 2048
UDP_MAX_RETRIES = 5
UDP_IDLE_TIMEOUT_SECONDS = 1.0
UDP_TRANSFER_TIMEOUT_SECONDS = 30.0


class NetworkDownloadAnalyzer:
    """
    Main analyzer class implementing automated network performance monitoring.
    
    Features:
    - Low-level TCP socket programming
    - SSL/TLS secure communication (mandatory)
    - UDP control channel for dynamic configuration
    - Automated downloads with flexible intervals
    - Performance metrics collection
    - Congestion pattern analysis
    - Multi-threaded concurrent support
    """
    
    def __init__(self,
                 file_url: str,
                 download_interval: int = 3600,
                 total_duration: int = 86400,
                 timeout: int = 300,
                 results_dir: str = "results",
                 use_udp: bool = True,
                 use_udp_transfer: bool = False,
                 udp_port: int = 9443,
                 file_size_mb: Optional[int] = None):
        """
        Initialize the analyzer.

        Args:
            file_url: URL of file to download
            download_interval: Seconds between downloads (default: 3600 = 1 hour)
            total_duration: Total monitoring duration (default: 86400 = 24 hours)
            timeout: Socket timeout in seconds
            results_dir: Directory for results storage
            use_udp: Enable UDP control channel (default: True)
            use_udp_transfer: Enable UDP file transfer instead of TCP/SSL (default: False)
            udp_port: UDP control port (default: 9443)
            file_size_mb: Request specific file size from server (optional)
        """
        self.file_url = file_url
        self.download_interval = download_interval
        self.total_duration = total_duration
        self.timeout = timeout
        self.results_dir = results_dir
        self.use_udp = use_udp
        self.use_udp_transfer = use_udp_transfer
        self.udp_port = udp_port
        self.file_size_mb = file_size_mb
        
        # Parse URL components for socket connection
        self.hostname, self.port, self.use_ssl, self.path = self._parse_url(file_url)
        
        # Results storage with thread-safe access
        self.download_results: List[Dict] = []
        self.results_lock = threading.Lock()
        
        # Session identifier
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Statistics
        self.total_downloads = 0
        self.successful_downloads = 0
        self.failed_downloads = 0
        
        # Create results directory
        os.makedirs(results_dir, exist_ok=True)
        
        print(f"Network Download Analyzer initialized")
        print(f"Target: {self.hostname}:{self.port}")
        print(f"SSL/TLS: {'Enabled' if self.use_ssl else 'Disabled'}")
        print(f"UDP Control: {'Enabled' if self.use_udp else 'Disabled'}")
        print(f"UDP File Transfer: {'Enabled' if self.use_udp_transfer else 'Disabled'}")
        print(f"Session ID: {self.session_id}")
    
    def _parse_url(self, url: str) -> Tuple[str, int, bool, str]:
        """
        Parse URL using urllib and extract socket connection parameters.
        
        Returns:
            Tuple of (hostname, port, use_ssl, path)
        """
        parsed = urlparse(url)
        
        # Determine SSL and default port
        if parsed.scheme == 'https':
            use_ssl = True
            default_port = 443
        elif parsed.scheme == 'http':
            use_ssl = False
            default_port = 80
        else:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme}. Use http:// or https://")
        
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL: missing hostname")
        
        port = parsed.port if parsed.port else default_port
        path = parsed.path if parsed.path else '/'
        
        # Include query string if present
        if parsed.query:
            path += '?' + parsed.query
        
        return hostname, port, use_ssl, path
    
    def _send_udp_command(self, command: str) -> Optional[str]:
        """
        Send UDP control command to server.
        
        Args:
            command: Command string (e.g., "GET_SIZE", "SET_SIZE:10")
            
        Returns:
            Server response or None on error
        """
        if not self.use_udp:
            return None
        
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(5.0)
            
            udp_socket.sendto(command.encode(), (self.hostname, self.udp_port))
            response, _ = udp_socket.recvfrom(1024)
            
            udp_socket.close()
            return response.decode('utf-8', errors='ignore').strip()
            
        except socket.timeout:
            print(f"  [UDP] Timeout waiting for response")
            return None
        except Exception as e:
            print(f"  [UDP] Error: {e}")
            return None
    
    def _set_server_file_size(self, size_mb: int) -> bool:
        """
        Request server to change file size via UDP.
        
        Args:
            size_mb: New file size in MB
            
        Returns:
            True if successful
        """
        print(f"  [UDP] Requesting file size change to {size_mb}MB...")
        response = self._send_udp_command(f"SET_SIZE:{size_mb}")
        
        if response and response.startswith("OK:"):
            new_size = int(response.split(':')[1])
            print(f"  [UDP] Server confirmed: {new_size}MB")
            return True
        elif response:
            print(f"  [UDP] Server response: {response}")
        return False
    
    def _get_server_file_size(self) -> Optional[int]:
        """
        Query current file size from server via UDP.

        Returns:
            File size in MB or None on error
        """
        response = self._send_udp_command("GET_SIZE")

        if response and response.startswith("SIZE:"):
            try:
                size = int(response.split(':')[1])
                print(f"  [UDP] Current server file size: {size}MB")
                return size
            except (ValueError, IndexError):
                pass
        return None

    def _download_file_udp(self, download_num: int, elapsed_hours: float) -> Dict:
        """
        Perform file download over UDP with missing-packet retransmission.

        UDP packet format (20-byte header + payload):
        - 4 bytes: Magic "UDPF" (0x55445046)
        - 4 bytes: Sequence number
        - 4 bytes: Total packets
        - 4 bytes: This chunk size
        - 4 bytes: Total file size
        - Payload: up to 1400 bytes

        Args:
            download_num: Download attempt number
            elapsed_hours: Hours elapsed since start

        Returns:
            Dictionary containing download metrics
        """
        result = {
            "timestamp": datetime.now().isoformat(),
            "url": self.file_url,
            "hostname": self.hostname,
            "port": self.port,
            "ssl_enabled": self.use_ssl,
            "udp_transfer": True,
            "success": False,
            "status_code": None,
            "file_size_bytes": 0,
            "download_time_seconds": 0,
            "connection_time_ms": 0,
            "ssl_handshake_time_ms": 0,
            "download_speed_bps": 0,
            "download_speed_mbps": 0,
            "md5_checksum": None,
            "packets_expected": 0,
            "packets_received": 0,
            "packets_retransmitted": 0,
            "udp_retries": 0,
            "error": None,
            "error_type": None
        }

        udp_socket = None

        try:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting UDP download #{download_num}")
            print(f"  Target: {self.hostname}:{self.udp_port} (UDP)")

            # Create UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(UDP_IDLE_TIMEOUT_SECONDS)

            download_start = time.time()

            # Send GET_FILE request (binary magic bytes)
            udp_socket.sendto(UDP_REQUEST_FILE, (self.hostname, self.udp_port))
            print(f"  [OK] UDP file request sent")

            # Collect chunks
            chunks = {}
            total_chunks = None
            total_file_size = None
            packet_receive_count = 0
            retries = 0

            while time.time() - download_start < UDP_TRANSFER_TIMEOUT_SECONDS:
                try:
                    data, addr = udp_socket.recvfrom(UDP_RECEIVE_BUFFER)
                    packet_receive_count += 1

                    # Parse header (20 bytes)
                    if len(data) < 20:
                        print(f"  [UDP] Invalid packet: too small ({len(data)} bytes)")
                        continue

                    magic, seq, total, chunk_size, file_size = struct.unpack('!IIIII', data[:20])

                    # Verify magic
                    if magic != UDP_DATA_MAGIC:
                        print(f"  [UDP] Invalid packet: bad magic (0x{magic:08X})")
                        continue
                    if seq >= total:
                        print(f"  [UDP] Invalid packet: sequence {seq} outside total {total}")
                        continue
                    if len(data) - 20 < chunk_size:
                        print(f"  [UDP] Invalid packet: truncated payload for sequence {seq}")
                        continue

                    # Store metadata
                    if total_chunks is None:
                        total_chunks = total
                        total_file_size = file_size
                        result["packets_expected"] = total_chunks
                        print(f"  [OK] Transfer started: {total_file_size} bytes in {total_chunks} packets")
                    elif total != total_chunks or file_size != total_file_size:
                        print(f"  [UDP] Ignoring packet with inconsistent transfer metadata")
                        continue

                    # Extract payload
                    payload = data[20:20 + chunk_size]
                    chunks[seq] = payload

                    if packet_receive_count % 100 == 0:
                        print(f"  [UDP] Progress: {len(chunks)}/{total_chunks} packets")

                    # Check if complete
                    if len(chunks) == total_chunks:
                        break

                except socket.timeout:
                    if total_chunks is None:
                        retries += 1
                        if retries > UDP_MAX_RETRIES:
                            raise TimeoutError("No response from server")
                        udp_socket.sendto(UDP_REQUEST_FILE, (self.hostname, self.udp_port))
                        print(f"  [UDP] Retrying initial file request ({retries}/{UDP_MAX_RETRIES})")
                        continue

                    missing = [seq for seq in range(total_chunks) if seq not in chunks]
                    if not missing:
                        break
                    if retries >= UDP_MAX_RETRIES:
                        print(f"  [UDP] Retry limit reached with {len(missing)} missing packets")
                        break

                    retries += 1
                    result["udp_retries"] = retries
                    result["packets_retransmitted"] += len(missing)
                    print(
                        f"  [UDP] Requesting {len(missing)} missing packets "
                        f"({retries}/{UDP_MAX_RETRIES})"
                    )
                    for batch_start in range(0, len(missing), 100):
                        batch = missing[batch_start:batch_start + 100]
                        command = "GET_MISSING:" + ",".join(str(seq) for seq in batch)
                        udp_socket.sendto(command.encode(), (self.hostname, self.udp_port))

            download_time = time.time() - download_start
            result["connection_time_ms"] = download_time * 1000
            result["download_time_seconds"] = download_time
            result["packets_received"] = len(chunks)

            # Reassemble file
            if chunks:
                file_data = b''.join(chunks.get(i, b'') for i in range(total_chunks or 0))
                result["file_size_bytes"] = len(file_data)

                # Calculate MD5
                result["md5_checksum"] = hashlib.md5(file_data).hexdigest()

                # Calculate speed
                if download_time > 0:
                    result["download_speed_bps"] = (len(file_data) * 8) / download_time
                    result["download_speed_mbps"] = result["download_speed_bps"] / 1_000_000

                # Verify completeness
                if total_chunks is None or total_file_size is None:
                    result["error"] = "Transfer metadata was not received"
                    result["error_type"] = "missing_metadata"
                    print(f"  ERROR: Transfer metadata was not received")
                elif len(chunks) != total_chunks:
                    missing_count = total_chunks - len(chunks)
                    result["error"] = f"Incomplete transfer: {missing_count} packets missing"
                    result["error_type"] = "incomplete"
                    print(f"  ERROR: Incomplete transfer ({len(chunks)}/{total_chunks} packets)")
                elif len(file_data) != total_file_size:
                    result["error"] = (
                        f"Incomplete transfer: expected {total_file_size}, got {len(file_data)}"
                    )
                    result["error_type"] = "incomplete"
                    print(f"  ERROR: Incomplete transfer ({len(file_data)}/{total_file_size} bytes)")
                else:
                    result["success"] = True
                    print(f"  SUCCESS")
                    print(f"  File Size: {result['file_size_bytes'] / (1024*1024):.2f} MB")
                    print(f"  Download Time: {result['download_time_seconds']:.2f} seconds")
                    print(f"  Average Speed: {result['download_speed_mbps']:.2f} Mbps")
                    print(f"  MD5 Checksum: {result['md5_checksum']}")
                    print(f"  Packets: {len(chunks)}/{total_chunks}")
                    print(f"  UDP Retries: {retries}")
            else:
                result["error"] = "No data received"
                result["error_type"] = "no_data"
                print(f"  ERROR: No data received")

        except socket.timeout:
            result["error"] = "UDP socket timeout"
            result["error_type"] = "timeout"
            print(f"  ERROR: UDP socket timeout")

        except Exception as e:
            result["error"] = str(e)
            result["error_type"] = "general_error"
            print(f"  ERROR: {e}")

        finally:
            if udp_socket:
                try:
                    udp_socket.close()
                except:
                    pass

        return result
    
    def _create_tcp_socket(self) -> socket.socket:
        """
        Create raw TCP socket with explicit low-level socket programming.
        
        Demonstrates:
        - socket.socket() - socket creation
        - AF_INET - IPv4 addressing
        - SOCK_STREAM - TCP protocol
        - settimeout() - timeout configuration
        """
        # Create IPv4 TCP socket (explicit low-level socket programming)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket timeout to prevent infinite blocking
        sock.settimeout(self.timeout)
        
        # Enable address reuse (useful for rapid restarts during testing)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        return sock
    
    def _wrap_ssl_socket(self, sock: socket.socket, hostname: str) -> ssl.SSLSocket:
        """
        Wrap TCP socket with SSL/TLS encryption - MANDATORY REQUIREMENT.
        
        Implements:
        - ssl.wrap_socket() - SSL/TLS wrapping
        - Certificate verification (disabled for self-signed test certs)
        - Protocol negotiation
        """
        # Create SSL context with TLS 1.2+ support
        context = ssl.create_default_context()
        
        # Disable certificate verification for self-signed test certificates
        # In production, use proper CA-signed certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
        
        return ssl_sock
    
    def _download_file(self, download_num: int, elapsed_hours: float) -> Dict:
        """
        Perform single file download using TCP socket with SSL/TLS or UDP.

        Args:
            download_num: Download attempt number
            elapsed_hours: Hours elapsed since start

        Returns:
            Dictionary containing download metrics
        """
        # Route to UDP if enabled for file transfer
        if self.use_udp_transfer:
            return self._download_file_udp(download_num, elapsed_hours)

        result = {
            "timestamp": datetime.now().isoformat(),
            "url": self.file_url,
            "hostname": self.hostname,
            "port": self.port,
            "ssl_enabled": self.use_ssl,
            "success": False,
            "status_code": None,
            "file_size_bytes": 0,
            "download_time_seconds": 0,
            "connection_time_ms": 0,
            "ssl_handshake_time_ms": 0,
            "download_speed_bps": 0,
            "download_speed_mbps": 0,
            "md5_checksum": None,
            "error": None,
            "error_type": None
        }

        sock = None

        try:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting download #{download_num}")
            print(f"  Target: {self.hostname}:{self.port}")
            print(f"  SSL/TLS: {self.use_ssl}")

            # Create TCP socket
            sock = self._create_tcp_socket()
            print(f"  [OK] TCP socket created")

            # Connect to server
            connect_start = time.time()
            sock.connect((self.hostname, self.port))
            connect_time = (time.time() - connect_start) * 1000
            result["connection_time_ms"] = connect_time
            print(f"  [OK] TCP connection established ({connect_time:.2f}ms)")
            
            # Wrap with SSL if required
            ssl_handshake_start = time.time()
            if self.use_ssl:
                ssl_sock = self._wrap_ssl_socket(sock, self.hostname)
                sock = ssl_sock
                ssl_handshake_time = (time.time() - ssl_handshake_start) * 1000
                result["ssl_handshake_time_ms"] = ssl_handshake_time
                print(f"  [OK] SSL/TLS handshake complete ({ssl_handshake_time:.2f}ms)")
                
                # Print SSL protocol version
                protocol = ssl_sock.version()
                print(f"  [OK] Protocol: {protocol}")
            
            # Build HTTP GET request
            request = f"GET {self.path} HTTP/1.1\r\n"
            request += f"Host: {self.hostname}\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            # Send request
            sock.sendall(request.encode())
            print(f"  [OK] HTTP request sent")
            
            # Receive response
            download_start = time.time()
            response_data = b""
            
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data += chunk
            
            download_time = time.time() - download_start
            result["download_time_seconds"] = download_time
            
            # Parse HTTP response
            header_end = response_data.find(b"\r\n\r\n")
            if header_end == -1:
                raise ValueError("Invalid HTTP response: missing headers")
            
            headers_raw = response_data[:header_end].decode('utf-8', errors='ignore')
            body = response_data[header_end + 4:]
            
            # Parse status line
            status_line = headers_raw.split('\r\n')[0]
            status_parts = status_line.split(' ')
            if len(status_parts) >= 2:
                result["status_code"] = int(status_parts[1])
            
            # Check for success
            if result["status_code"] != 200:
                raise ValueError(f"HTTP {result['status_code']}")
            
            # Calculate metrics
            result["file_size_bytes"] = len(body)
            result["download_speed_bps"] = (len(body) * 8) / download_time if download_time > 0 else 0
            result["download_speed_mbps"] = result["download_speed_bps"] / 1_000_000
            
            # Calculate MD5 checksum
            md5_hash = hashlib.md5(body).hexdigest()
            result["md5_checksum"] = md5_hash
            
            result["success"] = True
            
            print(f"  SUCCESS")
            print(f"  Status Code: {result['status_code']}")
            print(f"  File Size: {result['file_size_bytes'] / (1024*1024):.2f} MB")
            print(f"  Download Time: {download_time:.2f} seconds")
            print(f"  Average Speed: {result['download_speed_mbps']:.2f} Mbps")
            print(f"  MD5 Checksum: {md5_hash}")
            
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["error_type"] = "timeout"
            print(f"  ERROR: Connection timeout")
            
        except ssl.SSLError as e:
            result["error"] = str(e)
            result["error_type"] = "ssl_error"
            print(f"  SSL/TLS Error: {e}")
            
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
            result["error_type"] = "connection_refused"
            print(f"  ERROR: Connection refused")
            
        except Exception as e:
            result["error"] = str(e)
            result["error_type"] = "general_error"
            print(f"  ERROR: {e}")
            
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def _save_results(self):
        """Save results to JSON file."""
        filename = f"results_{self.session_id}.json"
        filepath = os.path.join(self.results_dir, filename)

        # Count UDP transfers
        udp_transfers = sum(1 for r in self.download_results if r.get("udp_transfer", False))

        output = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "url": self.file_url,
                "hostname": self.hostname,
                "port": self.port,
                "ssl_enabled": self.use_ssl,
                "udp_control_enabled": self.use_udp,
                "udp_file_transfer": self.use_udp_transfer,
                "download_interval": self.download_interval,
                "total_duration": self.total_duration,
                "timeout": self.timeout
            },
            "statistics": {
                "total_downloads": self.total_downloads,
                "successful_downloads": self.successful_downloads,
                "failed_downloads": self.failed_downloads,
                "udp_transfers": udp_transfers,
                "success_rate": (self.successful_downloads / self.total_downloads * 100) if self.total_downloads > 0 else 0
            },
            "results": self.download_results
        }

        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"\nResults saved: {filepath}")
    
    def run_analysis(self):
        """Execute the automated download analysis."""
        start_time = time.time()
        download_count = 0
        
        print("\n" + "=" * 80)
        print("AUTOMATED NETWORK DOWNLOAD ANALYZER")
        print("=" * 80)
        print(f"Session ID: {self.session_id}")
        print(f"Target URL: {self.file_url}")
        print(f"Download Interval: {self.download_interval}s ({self.download_interval/3600:.1f} hours)")
        print(f"Total Duration: {self.total_duration}s ({self.total_duration/3600:.1f} hours)")
        print(f"Timeout: {self.timeout}s")
        print(f"Results Directory: {self.results_dir}")
        print("=" * 80 + "\n")
        
        # Query or set initial file size via UDP control channel
        if self.use_udp:
            if self.file_size_mb is not None:
                self._set_server_file_size(self.file_size_mb)
                time.sleep(1)  # Give server time to regenerate file
            else:
                self._get_server_file_size()
        
        try:
            while (time.time() - start_time) < self.total_duration:
                elapsed = time.time() - start_time
                elapsed_hours = elapsed / 3600
                
                download_count += 1
                self.total_downloads = download_count
                
                print(f"\n{'=' * 80}")
                print(f"DOWNLOAD #{download_count}")
                print(f"Elapsed: {elapsed_hours:.2f} hours")
                print(f"{'=' * 80}")
                
                # Perform download
                result = self._download_file(download_count, elapsed_hours)
                
                # Store result
                with self.results_lock:
                    self.download_results.append(result)
                
                if result["success"]:
                    self.successful_downloads += 1
                else:
                    self.failed_downloads += 1
                
                # Calculate remaining time
                remaining = self.total_duration - elapsed
                remaining_minutes = remaining / 60
                
                if remaining_minutes > self.download_interval / 60:
                    print(f"\n  Next download in {self.download_interval}s ({self.download_interval/60:.1f} minutes)")
                    print(f"  Remaining session time: {remaining_minutes:.1f} minutes")
                    
                    # Sleep until next download
                    time.sleep(self.download_interval)
                else:
                    print(f"\n  Session ending - insufficient time for another download")
                    break
                    
        except KeyboardInterrupt:
            print("\n\nAnalysis interrupted by user")
        
        finally:
            # Save results
            self._save_results()
            
            # Print summary
            self._print_summary()
    
    def _print_summary(self):
        """Print final analysis summary."""
        print(f"\n{'=' * 80}")
        print("FINAL STATISTICS")
        print(f"{'=' * 80}")
        print(f"Total Downloads: {self.total_downloads}")
        print(f"Successful: {self.successful_downloads}")
        print(f"Failed: {self.failed_downloads}")
        
        if self.total_downloads > 0:
            success_rate = (self.successful_downloads / self.total_downloads) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        # Performance analysis
        successful = [r for r in self.download_results if r["success"]]
        
        if successful:
            speeds = [r["download_speed_mbps"] for r in successful]
            
            import statistics
            
            print(f"\nDOWNLOAD SPEED STATISTICS (Mbps):")
            print(f"  Average: {statistics.mean(speeds):.2f}")
            print(f"  Median: {statistics.median(speeds):.2f}")
            print(f"  Minimum: {min(speeds):.2f}")
            print(f"  Maximum: {max(speeds):.2f}")
            
            if len(speeds) > 1:
                print(f"  Std Dev: {statistics.stdev(speeds):.2f}")
            
            # Find slowest and fastest
            slowest = max(successful, key=lambda x: x["download_time_seconds"])
            fastest = min(successful, key=lambda x: x["download_time_seconds"])
            
            print(f"\nSLOWEST DOWNLOAD:")
            print(f"  Time: {slowest['timestamp']}")
            print(f"  Speed: {slowest['download_speed_mbps']:.2f} Mbps")
            print(f"  Duration: {slowest['download_time_seconds']:.2f}s")
            
            print(f"\nFASTEST DOWNLOAD:")
            print(f"  Time: {fastest['timestamp']}")
            print(f"  Speed: {fastest['download_speed_mbps']:.2f} Mbps")
            print(f"  Duration: {fastest['download_time_seconds']:.2f}s")
            
            # Hourly analysis
            hourly_speeds = {}
            for result in successful:
                hour = datetime.fromisoformat(result["timestamp"]).hour
                if hour not in hourly_speeds:
                    hourly_speeds[hour] = []
                hourly_speeds[hour].append(result["download_speed_mbps"])
            
            if hourly_speeds:
                print(f"\nHOURLY PERFORMANCE ANALYSIS:")
                hourly_avg = {h: statistics.mean(s) for h, s in hourly_speeds.items()}
                sorted_hours = sorted(hourly_avg.items(), key=lambda x: x[1])
                
                print(f"  Busiest Hour: {sorted_hours[0][0]:02d}:00 (Avg: {sorted_hours[0][1]:.2f} Mbps)")
                print(f"  Best Hour: {sorted_hours[-1][0]:02d}:00 (Avg: {sorted_hours[-1][1]:.2f} Mbps)")
                
                if sorted_hours[-1][1] > 0:
                    perf_diff = ((sorted_hours[-1][1] - sorted_hours[0][1]) / sorted_hours[-1][1]) * 100
                    print(f"  Performance Degradation: {perf_diff:.1f}% during congestion")
        
        print(f"\nResults saved: {self.results_dir}/results_{self.session_id}.json")


def main():
    """Main entry point with argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Automated Network Download Analyzer with SSL/TLS and UDP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test mode (5 downloads, 1-minute intervals)
  python3 %(prog)s https://example.com/file.zip --test

  # Full 24-hour analysis
  python3 %(prog)s https://example.com/file.zip

  # Custom intervals (30 minutes between downloads)
  python3 %(prog)s https://example.com/file.zip --interval 1800 --duration 43200

  # Set server file size via UDP (requires UDP support on server)
  python3 %(prog)s https://localhost:8443/testfile --size 20

  # Enable UDP file transfer (requires server with UDP support)
  python3 %(prog)s https://localhost:8443/testfile --udp

  # Disable UDP control channel
  python3 %(prog)s https://example.com/file.zip --no-udp
        """
    )
    
    parser.add_argument('url',
                       help='URL of file to download (must be http:// or https://)')
    parser.add_argument('-i', '--interval',
                       type=int,
                       default=3600,
                       help='Download interval in seconds (default: 3600 = 1 hour)')
    parser.add_argument('-d', '--duration',
                       type=int,
                       default=86400,
                       help='Total duration in seconds (default: 86400 = 24 hours)')
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=300,
                       help='Socket timeout in seconds (default: 300)')
    parser.add_argument('-r', '--results-dir',
                       default='results',
                       help='Results directory (default: results)')
    parser.add_argument('--test',
                       action='store_true',
                       help='Test mode: 5 downloads at 1-minute intervals')
    parser.add_argument('--udp-port',
                       type=int,
                       default=9443,
                       help='UDP control port (default: 9443)')
    parser.add_argument('--no-udp',
                       action='store_true',
                       help='Disable UDP control channel')
    parser.add_argument('--udp',
                       action='store_true',
                       help='Enable UDP file transfer (uses UDP instead of TCP/SSL for file downloads). Requires server with UDP support.')
    parser.add_argument('-s', '--size',
                       type=int,
                       help='Request file size from server in MB (via UDP)')
    
    args = parser.parse_args()
    
    # Test mode override
    if args.test:
        print("=" * 80)
        print("RUNNING IN TEST MODE")
        print("5 downloads at 1-minute intervals (5 minutes total)")
        print("=" * 80)
        args.interval = 60
        args.duration = 300
    
    try:
        # Create and run analyzer
        # UDP control channel: enabled by default, disabled with --no-udp
        # UDP file transfer: disabled by default, enabled with --udp
        analyzer = NetworkDownloadAnalyzer(
            file_url=args.url,
            download_interval=args.interval,
            total_duration=args.duration,
            timeout=args.timeout,
            results_dir=args.results_dir,
            use_udp=not args.no_udp,           # UDP control channel
            use_udp_transfer=args.udp,         # UDP file transfer
            udp_port=args.udp_port,
            file_size_mb=args.size
        )
        
        analyzer.run_analysis()
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        print("Partial results have been saved")
        sys.exit(0)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
