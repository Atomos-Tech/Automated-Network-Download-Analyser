#!/usr/bin/env python3
"""
HTTPS Test File Server
Provides local testing server for the network analyzer

Features:
- SSL/TLS encrypted connections (mandatory)
- Concurrent client handling via threading
- Configurable file sizes
- Connection statistics tracking
- Auto-generated SSL certificates
"""

import socket
import ssl
import threading
import os
import time
from datetime import datetime


class HTTPSTestServer:
    """HTTPS server for local testing with SSL/TLS support."""
    
    def __init__(self, host='0.0.0.0', port=8443, file_size_mb=10, max_connections=50):
        self.host = host
        self.port = port
        self.file_size_mb = file_size_mb
        self.max_connections = max_connections
        self.running = False
        
        # Statistics
        self.total_connections = 0
        self.successful_transfers = 0
        self.failed_transfers = 0
        self.total_bytes_sent = 0
        self.stats_lock = threading.Lock()
        
        # Pre-generate test file data for performance
        print(f"Generating {file_size_mb}MB test file...")
        self.test_file_data = self._generate_test_file(file_size_mb)
        print(f"✓ Test file ready ({len(self.test_file_data):,} bytes)")
    
    def _generate_test_file(self, size_mb: int) -> bytes:
        """Generate test file data."""
        pattern = b"NETWORK_ANALYZER_TEST_DATA_" * 100
        size_bytes = size_mb * 1024 * 1024
        repetitions = (size_bytes // len(pattern)) + 1
        data = (pattern * repetitions)[:size_bytes]
        return data
    
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
            
            print(f"✓ Generated: {cert_file}, {key_file}")
            
        except ImportError:
            print("ERROR: cryptography library not installed")
            print("Install with: pip install cryptography")
            print("\nOr generate manually:")
            print(f"  openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj '/CN=localhost'")
            raise
    
    def _handle_client(self, client_socket, address):
        """Handle individual client connection."""
        start_time = time.time()
        
        with self.stats_lock:
            self.total_connections += 1
            conn_num = self.total_connections
        
        try:
            # Receive HTTP request
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            # Parse request line
            lines = request.split('\r\n')
            if len(lines) < 1:
                return
            
            request_line = lines[0]
            
            # Build HTTP response
            response_header = f"HTTP/1.1 200 OK\r\n"
            response_header += f"Content-Type: application/octet-stream\r\n"
            response_header += f"Content-Length: {len(self.test_file_data)}\r\n"
            response_header += f"Server: NetworkAnalyzerTestServer/1.0\r\n"
            response_header += f"Connection: close\r\n"
            response_header += f"\r\n"
            
            # Send response
            client_socket.sendall(response_header.encode('utf-8'))
            client_socket.sendall(self.test_file_data)
            
            duration = time.time() - start_time
            speed_mbps = (len(self.test_file_data) * 8) / (duration * 1024 * 1024)
            
            with self.stats_lock:
                self.successful_transfers += 1
                self.total_bytes_sent += len(self.test_file_data)
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - "
                  f"{len(self.test_file_data)/(1024*1024):.1f}MB "
                  f"in {duration:.2f}s ({speed_mbps:.2f} Mbps)")
            
        except Exception as e:
            with self.stats_lock:
                self.failed_transfers += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"#{conn_num} {address[0]} - ERROR: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Start the HTTPS server."""
        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind and listen
            server_socket.bind((self.host, self.port))
            server_socket.listen(self.max_connections)
            
            # Wrap with SSL
            ssl_context = self._create_ssl_context()
            ssl_socket = ssl_context.wrap_socket(server_socket, server_side=True)
            
            self.running = True
            
            print("=" * 80)
            print("HTTPS TEST FILE SERVER")
            print("=" * 80)
            print(f"Host: {self.host}")
            print(f"Port: {self.port}")
            print(f"File Size: {self.file_size_mb} MB")
            print(f"Max Connections: {self.max_connections}")
            print(f"URL: https://localhost:{self.port}/testfile")
            print("=" * 80)
            print("\nServer ready. Waiting for connections... (Ctrl+C to stop)\n")
            
            while self.running:
                try:
                    client_socket, address = ssl_socket.accept()
                    
                    # Handle in thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
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
        print(f"Total Connections: {self.total_connections}")
        print(f"Successful: {self.successful_transfers}")
        print(f"Failed: {self.failed_transfers}")
        print(f"Total Data Sent: {self.total_bytes_sent / (1024**3):.2f} GB")
        if self.total_connections > 0:
            print(f"Success Rate: {(self.successful_transfers/self.total_connections*100):.1f}%")
        print(f"{'=' * 80}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTPS Test File Server')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                       help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8443,
                       help='Port to listen (default: 8443)')
    parser.add_argument('-s', '--size', type=int, default=10,
                       help='File size in MB (default: 10)')
    parser.add_argument('-c', '--max-connections', type=int, default=50,
                       help='Max connections (default: 50)')
    
    args = parser.parse_args()
    
    server = HTTPSTestServer(
        host=args.host,
        port=args.port,
        file_size_mb=args.size,
        max_connections=args.max_connections
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == '__main__':
    main()
