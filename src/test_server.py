#!/usr/bin/env python3
"""
HTTPS/UDP Test File Server
Provides local testing server for the network analyzer

Features:
- SSL/TLS encrypted connections (TCP)
- UDP packet support
- Concurrent client handling via threading
- Dynamic file size configuration via control endpoint
- Connection statistics tracking
- Auto-generated SSL certificates
"""

import socket
import ssl
import threading
import os
import time
import json
import struct
from datetime import datetime
from typing import Optional


UDP_DATA_MAGIC = 0x55445046  # "UDPF"
UDP_REQUEST_FILE = b"GETF"
UDP_PAYLOAD_SIZE = 1400
UDP_RECEIVE_BUFFER = 4096


class HTTPSTestServer:
    """HTTPS/UDP server for local testing with SSL/TLS and UDP support."""
    
    def __init__(self, host='0.0.0.0', port=8443, file_size_mb=10, 
                 max_connections=50, udp_port=9443, enable_udp=True):
        self.host = host
        self.port = port
        self._file_size_mb = file_size_mb
        self.max_connections = max_connections
        self.running = False
        self.enable_udp = enable_udp
        self.udp_port = udp_port
        
        # Lock for thread-safe file size changes
        self._file_size_lock = threading.Lock()
        
        # Statistics
        self.total_connections = 0
        self.successful_transfers = 0
        self.failed_transfers = 0
        self.total_bytes_sent = 0
        self.stats_lock = threading.Lock()
        
        # Pre-generate test file data for performance
        print(f"Generating {file_size_mb}MB test file...")
        self.test_file_data = self._generate_test_file(file_size_mb)
        print(f"[OK] Test file ready ({len(self.test_file_data):,} bytes)")
        
        # UDP statistics
        self.udp_requests = 0
        self.udp_errors = 0
        self.udp_transfer_sessions = {}
        self.udp_transfer_lock = threading.Lock()
    
    @property
    def file_size_mb(self) -> int:
        """Thread-safe getter for file size."""
        with self._file_size_lock:
            return self._file_size_mb
    
    @file_size_mb.setter
    def file_size_mb(self, value: int):
        """Thread-safe setter for file size."""
        with self._file_size_lock:
            self._file_size_mb = value
            print(f"\n[INFO] File size changed to {value}MB")
            # Regenerate test file data
            self.test_file_data = self._generate_test_file(value)
            print(f"[INFO] Test file regenerated ({len(self.test_file_data):,} bytes)")
    
    def _generate_test_file(self, size_mb: int) -> bytes:
        """Generate test file data of specified size."""
        pattern = b"NETWORK_ANALYZER_TEST_DATA_" * 100
        size_bytes = size_mb * 1024 * 1024
        repetitions = (size_bytes // len(pattern)) + 1
        data = (pattern * repetitions)[:size_bytes]
        return data

    def _get_file_snapshot(self) -> bytes:
        """Return a consistent snapshot of the current test file data."""
        with self._file_size_lock:
            return self.test_file_data
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with certificates."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        cert_file = 'server.crt'
        key_file = 'server.key'
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("SSL certificates not found. Generating...")
            self._generate_certificates(cert_file, key_file)
        
        context.load_cert_chain(cert_file, key_file)
        return context
    
    def _generate_certificates(self, cert_file: str, key_file: str):
        """Generate self-signed SSL certificate."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime as dt
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Network Analyzer Test Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                dt.datetime.utcnow()
            ).not_valid_after(
                dt.datetime.utcnow() + dt.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.DNSName(u"127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write private key
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"[OK] Generated: {cert_file}, {key_file}")
            
        except ImportError:
            print("ERROR: cryptography library not installed")
            print("Install with: pip install cryptography")
            print("\nOr generate manually:")
            print(f"  openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj \'/CN=localhost\'")
            raise
    
    def _handle_client(self, client_socket, address, ssl_context: ssl.SSLContext):
        """Handle individual TCP client connection."""
        with self.stats_lock:
            self.total_connections += 1
            conn_num = self.total_connections

        ssl_conn = None
        
        try:
            # Wrap with SSL
            ssl_conn = ssl_context.wrap_socket(client_socket, server_side=True)
            
            # Read HTTP request
            request = ssl_conn.recv(4096).decode('utf-8', errors='ignore')
            
            # Parse request
            lines = request.split('\r\n')
            if not lines:
                ssl_conn.close()
                return
            
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 2:
                ssl_conn.close()
                return
            
            method = parts[0]
            path = parts[1]
            
            # Handle control endpoints for dynamic configuration
            if path.startswith('/control/'):
                self._handle_control_request(ssl_conn, path, method)
            elif path == '/size':
                # Return current file size
                response = self._build_http_response(
                    json.dumps({"size_mb": self.file_size_mb}).encode(),
                    content_type="application/json"
                )
                ssl_conn.sendall(response)
            else:
                # Standard file download
                self._send_file(ssl_conn, address, conn_num)
            
        except ssl.SSLError as e:
            with self.stats_lock:
                self.failed_transfers += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - SSL Error: {e}")
        except Exception as e:
            with self.stats_lock:
                self.failed_transfers += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - ERROR: {e}")
        finally:
            try:
                if ssl_conn:
                    ssl_conn.close()
                else:
                    client_socket.close()
            except:
                pass
    
    def _handle_control_request(self, ssl_conn, path: str, method: str):
        """Handle control endpoint requests for dynamic configuration."""
        if method != 'POST':
            response = self._build_http_response(
                b'{"error": "Method not allowed"}',
                status=405,
                content_type="application/json"
            )
            ssl_conn.sendall(response)
            return
        
        # Parse control command
        # e.g., /control/size/5 or /control/size/20
        parts = path.strip('/').split('/')
        if len(parts) >= 3 and parts[1] == 'size':
            try:
                new_size = int(parts[2])
                if 1 <= new_size <= 100:  # Limit between 1-100 MB
                    self.file_size_mb = new_size
                    response = self._build_http_response(
                        json.dumps({"success": True, "size_mb": new_size}).encode(),
                        content_type="application/json"
                    )
                else:
                    response = self._build_http_response(
                        json.dumps({"error": "Size must be between 1 and 100 MB"}).encode(),
                        status=400,
                        content_type="application/json"
                    )
            except ValueError:
                response = self._build_http_response(
                    json.dumps({"error": "Invalid size value"}).encode(),
                    status=400,
                    content_type="application/json"
                )
        else:
            response = self._build_http_response(
                b'{"error": "Unknown control command"}',
                status=404,
                content_type="application/json"
            )
        
        ssl_conn.sendall(response)
    
    def _build_http_response(self, body: bytes, status: int = 200, 
                            content_type: str = "application/octet-stream") -> bytes:
        """Build HTTP response headers and body."""
        status_messages = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error"
        }
        
        headers = [
            f"HTTP/1.1 {status} {status_messages.get(status, 'Unknown')}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "",
            ""
        ]
        
        return "\r\n".join(headers).encode() + body
    
    def _send_file(self, ssl_conn, address, conn_num: int):
        """Send test file to client over SSL connection."""
        start_time = time.time()
        file_data = self._get_file_snapshot()
        file_size_mb = len(file_data) / (1024 * 1024)
        
        # Build HTTP response
        headers = [
            "HTTP/1.1 200 OK",
            f"Content-Type: application/octet-stream",
            f"Content-Length: {len(file_data)}",
            f"Content-Disposition: attachment; filename=testfile_{int(file_size_mb)}MB.bin",
            "Connection: close",
            "",
            ""
        ]
        
        response_headers = "\r\n".join(headers).encode()
        ssl_conn.sendall(response_headers)
        ssl_conn.sendall(file_data)
        
        duration = time.time() - start_time
        speed_mbps = (len(file_data) * 8) / (duration * 1_000_000)
        
        with self.stats_lock:
            self.successful_transfers += 1
            self.total_bytes_sent += len(file_data)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"#{conn_num} {address[0]} - "
              f"{len(file_data)/(1024*1024):.1f}MB "
              f"in {duration:.2f}s ({speed_mbps:.2f} Mbps)")
    
    def _build_udp_packet(self, file_data: bytes, seq: int, total_chunks: int) -> bytes:
        """Build one UDP file-transfer packet."""
        total_size = len(file_data)
        start = seq * UDP_PAYLOAD_SIZE
        end = min(start + UDP_PAYLOAD_SIZE, total_size)
        chunk = file_data[start:end]
        header = struct.pack('!IIIII', UDP_DATA_MAGIC, seq, total_chunks, len(chunk), total_size)
        return header + chunk

    def _send_udp_chunks(self,
                         address: tuple,
                         udp_socket: socket.socket,
                         file_data: bytes,
                         sequences: list,
                         total_chunks: int) -> int:
        """Send selected UDP file chunks and return the number of packets sent."""
        packets_sent = 0
        for seq in sequences:
            if 0 <= seq < total_chunks:
                udp_socket.sendto(self._build_udp_packet(file_data, seq, total_chunks), address)
                packets_sent += 1
        return packets_sent

    def _send_file_udp(self, address: tuple, udp_socket: socket.socket) -> None:
        """
        Send file over UDP in chunks.

        Packet format (20-byte header + payload):
        - 4 bytes: Magic "UDPF" (0x55445046)
        - 4 bytes: Sequence number
        - 4 bytes: Total packets
        - 4 bytes: This chunk size
        - 4 bytes: Total file size
        - Payload: up to 1400 bytes
        """
        file_data = self._get_file_snapshot()
        total_size = len(file_data)
        total_chunks = (total_size + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE

        with self.udp_transfer_lock:
            self.udp_transfer_sessions[address] = (file_data, total_chunks, time.time())

        print(f"[UDP] Sending {total_size} bytes in {total_chunks} chunks to {address}")

        packets_sent = self._send_udp_chunks(
            address,
            udp_socket,
            file_data,
            range(total_chunks),
            total_chunks
        )

        with self.stats_lock:
            self.successful_transfers += 1
            self.total_bytes_sent += total_size

        print(f"[UDP] File transfer queued to {address} ({packets_sent} packets)")

    def _resend_udp_chunks(self,
                           address: tuple,
                           udp_socket: socket.socket,
                           sequence_text: str) -> None:
        """Resend selected UDP chunks requested by the client."""
        with self.udp_transfer_lock:
            session = self.udp_transfer_sessions.get(address)

        if session:
            file_data, total_chunks, _ = session
        else:
            file_data = self._get_file_snapshot()
            total_chunks = (len(file_data) + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE

        sequences = []

        for raw_seq in sequence_text.split(','):
            raw_seq = raw_seq.strip()
            if not raw_seq:
                continue
            try:
                sequences.append(int(raw_seq))
            except ValueError:
                continue

        packets_sent = self._send_udp_chunks(
            address,
            udp_socket,
            file_data,
            sequences,
            total_chunks
        )
        print(f"[UDP] Resent {packets_sent}/{len(sequences)} requested chunks to {address}")

    def _cleanup_udp_transfer_sessions(self) -> None:
        """Discard old UDP transfer snapshots used for retransmission."""
        cutoff = time.time() - 120
        with self.udp_transfer_lock:
            stale_addresses = [
                address
                for address, (_, _, created_at) in self.udp_transfer_sessions.items()
                if created_at < cutoff
            ]
            for address in stale_addresses:
                del self.udp_transfer_sessions[address]

    def _handle_udp_request(self, data: bytes, address: tuple, udp_socket: socket.socket):
        """Handle UDP requests for file size info and control."""
        self.udp_requests += 1
        self._cleanup_udp_transfer_sessions()

        try:
            # Check for binary file transfer request.
            if len(data) >= 4 and data[:4] == UDP_REQUEST_FILE:
                # GET_FILE request - send file over UDP
                self._send_file_udp(address, udp_socket)
                return

            # Parse text UDP command
            message = data.decode('utf-8', errors='ignore').strip()

            if message == "GET_SIZE":
                response = f"SIZE:{self.file_size_mb}".encode()
            elif message == "PING":
                response = b"PONG"
            elif message.startswith("SET_SIZE:"):
                try:
                    new_size = int(message.split(':')[1])
                    if 1 <= new_size <= 100:
                        self.file_size_mb = new_size
                        response = f"OK:{new_size}".encode()
                    else:
                        response = b"ERROR:Size must be 1-100 MB"
                except (ValueError, IndexError):
                    response = b"ERROR:Invalid format"
            elif message.startswith("GET_MISSING:"):
                self._resend_udp_chunks(address, udp_socket, message.split(':', 1)[1])
                return
            else:
                response = b"ERROR:Unknown command"

            udp_socket.sendto(response, address)

        except Exception as e:
            self.udp_errors += 1
            error_msg = f"ERROR:{str(e)}".encode()
            udp_socket.sendto(error_msg, address)
    
    def _udp_listener(self):
        """UDP listener thread for control commands."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((self.host, self.udp_port))
        udp_socket.settimeout(1.0)
        
        print(f"[OK] UDP control listener on port {self.udp_port}")
        
        while self.running:
            try:
                data, address = udp_socket.recvfrom(UDP_RECEIVE_BUFFER)
                self._handle_udp_request(data, address, udp_socket)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"UDP error: {e}")
        
        udp_socket.close()
    
    def start(self):
        """Start the HTTPS/UDP server."""
        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind and listen
            server_socket.bind((self.host, self.port))
            server_socket.listen(self.max_connections)
            
            ssl_context = self._create_ssl_context()
            
            self.running = True
            
            # Start UDP listener thread
            udp_thread = None
            if self.enable_udp:
                udp_thread = threading.Thread(target=self._udp_listener, daemon=True)
                udp_thread.start()
            
            print("=" * 80)
            print("HTTPS/UDP TEST FILE SERVER")
            print("=" * 80)
            print(f"Host: {self.host}")
            print(f"TCP Port: {self.port} (HTTPS)")
            if self.enable_udp:
                print(f"UDP Port: {self.udp_port} (Control)")
            print(f"File Size: {self.file_size_mb} MB (dynamic)")
            print(f"Max Connections: {self.max_connections}")
            print(f"URL: https://localhost:{self.port}/testfile")
            print(f"Control: POST https://localhost:{self.port}/control/size/<MB>")
            if self.enable_udp:
                print(f"UDP Control: echo \"SET_SIZE:10\" | nc -u localhost {self.udp_port}")
            print("=" * 80)
            print("\nServer ready. Waiting for connections... (Ctrl+C to stop)\n")
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    
                    # Handle in thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address, ssl_context),
                        daemon=True
                    )
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
            
        except Exception as e:
            print(f"Server error: {e}")
            raise
        finally:
            self.running = False
            try:
                server_socket.close()
            except:
                pass
            
            self._print_statistics()
    
    def _print_statistics(self):
        """Print final statistics."""
        print(f"\n{'=' * 80}")
        print("SERVER STATISTICS")
        print(f"{'=' * 80}")
        print(f"Total TCP Connections: {self.total_connections}")
        print(f"Successful: {self.successful_transfers}")
        print(f"Failed: {self.failed_transfers}")
        print(f"Total Data Sent: {self.total_bytes_sent / (1024**3):.2f} GB")
        if self.enable_udp:
            print(f"UDP Requests: {self.udp_requests}")
            print(f"UDP Errors: {self.udp_errors}")
        if self.total_connections > 0:
            print(f"Success Rate: {(self.successful_transfers/self.total_connections*100):.1f}%")
        print(f"{'=' * 80}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTPS/UDP Test File Server')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                       help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8443,
                       help='TCP Port to listen (default: 8443)')
    parser.add_argument('-s', '--size', type=int, default=10,
                       help='File size in MB (default: 10)')
    parser.add_argument('-c', '--max-connections', type=int, default=50,
                       help='Max connections (default: 50)')
    parser.add_argument('--udp-port', type=int, default=9443,
                       help='UDP control port (default: 9443)')
    parser.add_argument('--no-udp', action='store_true',
                       help='Disable UDP control listener')
    
    args = parser.parse_args()
    
    server = HTTPSTestServer(
        host=args.host,
        port=args.port,
        file_size_mb=args.size,
        max_connections=args.max_connections,
        udp_port=args.udp_port,
        enable_udp=not args.no_udp
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == '__main__':
    main()
