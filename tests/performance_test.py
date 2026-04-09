#!/usr/bin/env python3
"""
Performance Testing Tool
Tests system performance with multiple concurrent clients

Demonstrates:
- Concurrent client connections (mandatory requirement)
- SSL/TLS performance under load
- Scalability analysis
- Throughput measurement
"""

import socket
import ssl
import time
import threading
import statistics
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse


class PerformanceTester:
    """Performance testing with concurrent clients."""
    
    def __init__(self, server_url: str, timeout: int = 30):
        self.server_url = server_url
        self.timeout = timeout
        self.results_lock = threading.Lock()
        
        # Parse URL
        parsed = urlparse(server_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = (parsed.scheme == 'https')
        self.path = parsed.path or '/'
    
    def _single_download(self, client_id: int) -> Dict:
        """Perform single download from one client."""
        result = {
            'client_id': client_id,
            'success': False,
            'download_time': 0.0,
            'file_size': 0,
            'speed_mbps': 0.0,
            'error': None
        }
        
        sock = None
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect
            sock.connect((self.hostname, self.port))
            
            # SSL if needed
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.hostname)
            
            # Send HTTP request
            request = f"GET {self.path} HTTP/1.1\r\n"
            request += f"Host: {self.hostname}\r\n"
            request += "Connection: close\r\n\r\n"
            sock.sendall(request.encode())
            
            # Receive response
            data = b''
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
            
            download_time = time.time() - start_time
            
            # Parse response
            header_end = data.find(b'\r\n\r\n')
            body = data[header_end + 4:] if header_end != -1 else data
            file_size = len(body)
            
            speed = (file_size * 8) / (download_time * 1024 * 1024) if download_time > 0 else 0
            
            result.update({
                'success': True,
                'download_time': download_time,
                'file_size': file_size,
                'speed_mbps': speed
            })
            
        except Exception as e:
            result['error'] = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def test_concurrent_clients(self, num_clients: int) -> List[Dict]:
        """Test with multiple concurrent clients."""
        print(f"\nTesting with {num_clients} concurrent clients...")
        
        results = []
        threads = []
        
        def download_worker(client_id: int):
            result = self._single_download(client_id)
            with self.results_lock:
                results.append(result)
        
        start_time = time.time()
        
        # Create threads
        for i in range(num_clients):
            thread = threading.Thread(target=download_worker, args=(i+1,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Analyze results
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        print(f"  Completed in: {total_time:.2f}s")
        print(f"  Successful: {len(successful)}/{num_clients}")
        print(f"  Failed: {len(failed)}/{num_clients}")
        
        if successful:
            speeds = [r['speed_mbps'] for r in successful]
            times = [r['download_time'] for r in successful]
            
            print(f"  Avg Speed: {statistics.mean(speeds):.2f} Mbps")
            print(f"  Avg Time: {statistics.mean(times):.2f}s")
            print(f"  Min Speed: {min(speeds):.2f} Mbps")
            print(f"  Max Speed: {max(speeds):.2f} Mbps")
        
        return results
    
    def run_performance_tests(self):
        """Run comprehensive performance tests."""
        print("=" * 80)
        print("PERFORMANCE TESTING - CONCURRENT CLIENTS")
        print("=" * 80)
        print(f"Target: {self.server_url}")
        print(f"SSL/TLS: {'Enabled' if self.use_ssl else 'Disabled'}")
        print("=" * 80)
        
        test_scenarios = [
            ('Single Client (Baseline)', 1),
            ('Light Load (5 clients)', 5),
            ('Medium Load (10 clients)', 10),
            ('Heavy Load (20 clients)', 20),
        ]
        
        all_results = {}
        
        for scenario_name, num_clients in test_scenarios:
            print(f"\n{'=' * 80}")
            print(f"SCENARIO: {scenario_name}")
            print(f"{'=' * 80}")
            
            results = self.test_concurrent_clients(num_clients)
            all_results[scenario_name] = results
            
            time.sleep(2)  # Brief pause between tests
        
        # Generate summary
        self._print_summary(all_results)
    
    def _print_summary(self, all_results: Dict):
        """Print summary of all tests."""
        print(f"\n{'=' * 80}")
        print("PERFORMANCE TEST SUMMARY")
        print(f"{'=' * 80}")
        
        print(f"\n{'Scenario':<30} {'Clients':<10} {'Success Rate':<15} {'Avg Speed (Mbps)':<20} {'Avg Time (s)':<15}")
        print("-" * 80)
        
        for scenario, results in all_results.items():
            successful = [r for r in results if r['success']]
            num_clients = len(results)
            success_rate = (len(successful) / num_clients * 100) if num_clients > 0 else 0
            
            if successful:
                avg_speed = statistics.mean([r['speed_mbps'] for r in successful])
                avg_time = statistics.mean([r['download_time'] for r in successful])
            else:
                avg_speed = 0
                avg_time = 0
            
            print(f"{scenario:<30} {num_clients:<10} {success_rate:<15.1f}% {avg_speed:<20.2f} {avg_time:<15.2f}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Performance testing with concurrent clients')
    parser.add_argument('url', help='Server URL to test')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                       help='Connection timeout (default: 30)')
    
    args = parser.parse_args()
    
    tester = PerformanceTester(args.url, args.timeout)
    
    try:
        tester.run_performance_tests()
    except KeyboardInterrupt:
        print("\n\nTesting interrupted")


if __name__ == '__main__':
    main()
