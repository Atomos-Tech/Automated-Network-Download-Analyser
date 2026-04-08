#!/usr/bin/env python3
"""
Report Generator for Network Analysis Results

Generates comprehensive reports from download analysis data:
- Text reports with detailed statistics
- CSV exports for further analysis
- Markdown reports for documentation
"""

import json
import sys
import statistics
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

# Visualization imports
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for server environments
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available. Skipping visualization generation.")


def load_results(filepath: str) -> Dict:
    """Load results from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        sys.exit(1)


def generate_text_report(data: Dict, output_file: str):
    """Generate detailed text report."""
    report = []
    
    report.append("=" * 100)
    report.append(" " * 35 + "NETWORK DOWNLOAD ANALYSIS REPORT")
    report.append("=" * 100)
    report.append("")
    
    # Session info
    report.append(f"Session ID: {data['session_id']}")
    report.append(f"Target URL: {data['file_url']}")
    report.append(f"Download Interval: {data['download_interval_seconds']}s ({data['download_interval_seconds']/3600:.1f}h)")
    report.append(f"Total Duration: {data['total_duration_seconds']}s ({data['total_duration_seconds']/3600:.1f}h)")
    report.append("")
    
    # Overall stats
    report.append("=" * 100)
    report.append("OVERALL STATISTICS")
    report.append("=" * 100)
    report.append(f"Total Downloads: {data['total_downloads']}")
    report.append(f"Successful: {data['successful_downloads']}")
    report.append(f"Failed: {data['failed_downloads']}")
    
    if data['total_downloads'] > 0:
        success_rate = (data['successful_downloads'] / data['total_downloads']) * 100
        report.append(f"Success Rate: {success_rate:.1f}%")
    report.append("")
    
    # Analyze successful downloads
    successful = [r for r in data['results'] if r['success']]
    
    if successful:
        speeds = [r['download_speed_mbps'] for r in successful]
        times = [r['download_time_seconds'] for r in successful]
        
        report.append("=" * 100)
        report.append("DOWNLOAD SPEED ANALYSIS (Mbps)")
        report.append("=" * 100)
        report.append(f"Average Speed: {statistics.mean(speeds):.2f} Mbps")
        report.append(f"Median Speed: {statistics.median(speeds):.2f} Mbps")
        report.append(f"Minimum Speed: {min(speeds):.2f} Mbps")
        report.append(f"Maximum Speed: {max(speeds):.2f} Mbps")
        report.append(f"Speed Range: {max(speeds) - min(speeds):.2f} Mbps")
        if len(speeds) >= 2:
            report.append(f"Standard Deviation: {statistics.stdev(speeds):.2f} Mbps")
        report.append("")
        
        report.append("=" * 100)
        report.append("DOWNLOAD TIME ANALYSIS (seconds)")
        report.append("=" * 100)
        report.append(f"Average Time: {statistics.mean(times):.2f}s")
        report.append(f"Median Time: {statistics.median(times):.2f}s")
        report.append(f"Minimum Time: {min(times):.2f}s")
        report.append(f"Maximum Time: {max(times):.2f}s")
        report.append("")
        
        # Hourly analysis
        hourly_data = {}
        for result in successful:
            dt = datetime.fromisoformat(result['timestamp'])
            hour = dt.hour
            if hour not in hourly_data:
                hourly_data[hour] = []
            hourly_data[hour].append(result['download_speed_mbps'])
        
        if hourly_data:
            report.append("=" * 100)
            report.append("HOURLY PERFORMANCE ANALYSIS")
            report.append("=" * 100)
            report.append(f"{'Hour':<10} {'Downloads':<15} {'Avg Speed (Mbps)':<20} {'Min':<15} {'Max':<15}")
            report.append("-" * 100)
            
            for hour in sorted(hourly_data.keys()):
                speeds_hour = hourly_data[hour]
                avg = statistics.mean(speeds_hour)
                report.append(f"{hour:02d}:00     {len(speeds_hour):<15} {avg:<20.2f} "
                            f"{min(speeds_hour):<15.2f} {max(speeds_hour):<15.2f}")
            report.append("")
            
            # Congestion analysis
            hourly_avg = {h: statistics.mean(s) for h, s in hourly_data.items()}
            sorted_hours = sorted(hourly_avg.items(), key=lambda x: x[1])
            
            report.append("NETWORK CONGESTION ANALYSIS")
            report.append("-" * 100)
            report.append(f"Slowest Period: {sorted_hours[0][0]:02d}:00 (Avg: {sorted_hours[0][1]:.2f} Mbps)")
            report.append(f"Fastest Period: {sorted_hours[-1][0]:02d}:00 (Avg: {sorted_hours[-1][1]:.2f} Mbps)")
            
            degradation = ((sorted_hours[-1][1] - sorted_hours[0][1]) / sorted_hours[-1][1]) * 100
            report.append(f"Performance Degradation: {degradation:.1f}% during congestion")
            report.append("")
        
        # Detailed log
        report.append("=" * 100)
        report.append("DETAILED DOWNLOAD LOG")
        report.append("=" * 100)
        report.append(f"{'#':<5} {'Timestamp':<25} {'Status':<10} {'Speed (Mbps)':<15} {'Time (s)':<12} {'Size (MB)':<12}")
        report.append("-" * 100)
        
        for idx, result in enumerate(data['results'], 1):
            timestamp = datetime.fromisoformat(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            status = "Success" if result['success'] else "Failed"
            
            if result['success']:
                speed = f"{result['download_speed_mbps']:.2f}"
                time_taken = f"{result['download_time_seconds']:.2f}"
                size = f"{result['file_size_bytes'] / (1024**2):.2f}"
            else:
                speed = "N/A"
                time_taken = "N/A"
                size = "N/A"
            
            report.append(f"{idx:<5} {timestamp:<25} {status:<10} {speed:<15} {time_taken:<12} {size:<12}")
            
            if not result['success'] and result['error']:
                report.append(f"      Error: {result['error']}")
        
        report.append("")
    
    # Failed downloads
    failed = [r for r in data['results'] if not r['success']]
    if failed:
        report.append("=" * 100)
        report.append("FAILED DOWNLOADS ANALYSIS")
        report.append("=" * 100)
        
        error_types = {}
        for result in failed:
            error = result.get('error', 'Unknown error')
            error_types[error] = error_types.get(error, 0) + 1
        
        report.append("Error Summary:")
        for error, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {error}: {count} occurrence(s)")
        report.append("")
    
    # Save report
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"✓ Text report saved: {output_file}")


def generate_csv_export(data: Dict, output_file: str):
    """Export results to CSV."""
    csv_lines = []
    csv_lines.append("Download_Number,Timestamp,Success,Status_Code,File_Size_Bytes,File_Size_MB,"
                    "Download_Time_Seconds,Speed_BPS,Speed_Mbps,Connection_Time_MS,SSL_Handshake_MS,"
                    "Error,Error_Type,MD5_Checksum")
    
    for idx, result in enumerate(data['results'], 1):
        line = (
            f"{idx},"
            f"{result['timestamp']},"
            f"{'TRUE' if result['success'] else 'FALSE'},"
            f"{result['status_code']},"
            f"{result['file_size_bytes']},"
            f"{result['file_size_bytes'] / (1024**2):.2f},"
            f"{result['download_time_seconds']:.2f},"
            f"{result['download_speed_bps']:.2f},"
            f"{result['download_speed_mbps']:.2f},"
            f"{result.get('connection_time_ms', 0):.2f},"
            f"{result.get('ssl_handshake_time_ms', 0):.2f},"
            f"\"{(result.get('error') or '').replace(',', ';')}\","
            f"{result.get('error_type') or ''},"
            f"{result.get('md5_checksum') or ''}"
        )
        csv_lines.append(line)
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(csv_lines))
    
    print(f"✓ CSV export saved: {output_file}")


def generate_markdown_report(data: Dict, output_file: str):
    """Generate Markdown report."""
    md = []
    md.append("# Network Download Analysis Report")
    md.append("")
    md.append(f"**Session ID:** {data['session_id']}")
    md.append(f"**Target URL:** {data['file_url']}")
    md.append(f"**Analysis Period:** {data['total_duration_seconds']/3600:.1f} hours")
    md.append("")
    
    md.append("## Summary Statistics")
    md.append("")
    md.append(f"- **Total Downloads:** {data['total_downloads']}")
    md.append(f"- **Successful:** {data['successful_downloads']}")
    md.append(f"- **Failed:** {data['failed_downloads']}")
    
    if data['total_downloads'] > 0:
        success_rate = (data['successful_downloads'] / data['total_downloads']) * 100
        md.append(f"- **Success Rate:** {success_rate:.1f}%")
    md.append("")
    
    successful = [r for r in data['results'] if r['success']]
    
    if successful:
        speeds = [r['download_speed_mbps'] for r in successful]
        
        md.append("## Performance Metrics")
        md.append("")
        md.append(f"- **Average Download Speed:** {statistics.mean(speeds):.2f} Mbps")
        md.append(f"- **Minimum Download Speed:** {min(speeds):.2f} Mbps")
        md.append(f"- **Maximum Download Speed:** {max(speeds):.2f} Mbps")
        md.append(f"- **Speed Variation:** {max(speeds) - min(speeds):.2f} Mbps")
        md.append("")
        
        # Hourly table
        hourly_data = {}
        for result in successful:
            dt = datetime.fromisoformat(result['timestamp'])
            hour = dt.hour
            if hour not in hourly_data:
                hourly_data[hour] = []
            hourly_data[hour].append(result['download_speed_mbps'])
        
        if hourly_data:
            md.append("## Hourly Performance")
            md.append("")
            md.append("| Hour | Downloads | Avg Speed (Mbps) | Min | Max |")
            md.append("|------|-----------|------------------|-----|-----|")
            
            for hour in sorted(hourly_data.keys()):
                speeds_hour = hourly_data[hour]
                avg = statistics.mean(speeds_hour)
                md.append(f"| {hour:02d}:00 | {len(speeds_hour)} | {avg:.2f} | "
                         f"{min(speeds_hour):.2f} | {max(speeds_hour):.2f} |")
            md.append("")
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(md))
    
    print(f"✓ Markdown report saved: {output_file}")


def generate_visualizations(data: Dict, output_dir: str, session_id: str):
    """Generate visualization charts from download data."""
    if not MATPLOTLIB_AVAILABLE:
        print("  ⚠ Skipping visualizations (matplotlib not installed)")
        return
    
    results = data['results']
    successful = [r for r in results if r.get('success', False)]
    
    if len(successful) < 2:
        print("  ⚠ Not enough data for visualizations (need at least 2 successful downloads)")
        return
    
    # Prepare data
    timestamps = [datetime.fromisoformat(r['timestamp']) for r in successful]
    speeds = [r['download_speed_mbps'] for r in successful]
    
    # Group by hour for hourly chart
    hourly_data = defaultdict(list)
    for r in successful:
        hour = datetime.fromisoformat(r['timestamp']).hour
        hourly_data[hour].append(r['download_speed_mbps'])
    
    hours = sorted(hourly_data.keys())
    hourly_avg = [statistics.mean(hourly_data[h]) for h in hours]
    
    # Set style
    plt.style.use('seaborn-v0_8-darkgrid' if 'seaborn-v0_8-darkgrid' in plt.style.available else 'default')
    
    # Create figure with 3 subplots
    fig = plt.figure(figsize=(15, 12))
    
    # ============ CHART 1: Speed Over Time (Line Graph) ============
    ax1 = plt.subplot(3, 1, 1)
    ax1.plot(timestamps, speeds, marker='o', linewidth=2, markersize=6, 
             color='#2E75B6', label='Download Speed')
    ax1.axhline(y=statistics.mean(speeds), color='#D55E00', linestyle='--', 
                linewidth=2, label=f'Average: {statistics.mean(speeds):.1f} Mbps')
    ax1.set_xlabel('Time', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Speed (Mbps)', fontsize=12, fontweight='bold')
    ax1.set_title('Network Download Speed Over Time', fontsize=14, fontweight='bold', pad=20)
    ax1.legend(loc='upper right', fontsize=10)
    ax1.grid(True, alpha=0.3)
    
    # Format x-axis to show time nicely
    if len(timestamps) > 10:
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(timestamps)//10)))
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # ============ CHART 2: Average Speed Per Hour (Bar Chart) ============
    ax2 = plt.subplot(3, 1, 2)
    colors = ['#27AE60' if speed >= statistics.mean(hourly_avg) else '#E74C3C' for speed in hourly_avg]
    bars = ax2.bar(hours, hourly_avg, color=colors, alpha=0.7, edgecolor='black', linewidth=1.5)
    
    # Add value labels on bars
    for bar, speed in zip(bars, hourly_avg):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{speed:.1f}',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax2.axhline(y=statistics.mean(hourly_avg), color='#D55E00', linestyle='--', 
                linewidth=2, label=f'Overall Average: {statistics.mean(hourly_avg):.1f} Mbps')
    ax2.set_xlabel('Hour of Day', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Average Speed (Mbps)', fontsize=12, fontweight='bold')
    ax2.set_title('Average Download Speed by Hour', fontsize=14, fontweight='bold', pad=20)
    ax2.set_xticks(hours)
    ax2.set_xticklabels([f'{h:02d}:00' for h in hours], rotation=45, ha='right')
    ax2.legend(loc='upper right', fontsize=10)
    ax2.grid(True, alpha=0.3, axis='y')
    
    # ============ CHART 3: Speed Distribution (Histogram) ============
    ax3 = plt.subplot(3, 1, 3)
    n, bins, patches = ax3.hist(speeds, bins=min(15, len(speeds)//2 + 1), 
                                 color='#3498DB', alpha=0.7, edgecolor='black', linewidth=1.5)
    
    # Color code histogram bars
    mean_speed = statistics.mean(speeds)
    for i, patch in enumerate(patches):
        if bins[i] < mean_speed:
            patch.set_facecolor('#E74C3C')  # Red for below average
        else:
            patch.set_facecolor('#27AE60')  # Green for above average
    
    ax3.axvline(x=mean_speed, color='#D55E00', linestyle='--', 
                linewidth=2, label=f'Mean: {mean_speed:.1f} Mbps')
    ax3.axvline(x=statistics.median(speeds), color='#9B59B6', linestyle='--', 
                linewidth=2, label=f'Median: {statistics.median(speeds):.1f} Mbps')
    ax3.set_xlabel('Download Speed (Mbps)', fontsize=12, fontweight='bold')
    ax3.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax3.set_title('Download Speed Distribution', fontsize=14, fontweight='bold', pad=20)
    ax3.legend(loc='upper right', fontsize=10)
    ax3.grid(True, alpha=0.3, axis='y')
    
    # ============ Add Statistics Box ============
    stats_text = f"""Statistics Summary:
    Downloads: {len(successful)}
    Avg Speed: {statistics.mean(speeds):.2f} Mbps
    Median: {statistics.median(speeds):.2f} Mbps
    Std Dev: {statistics.stdev(speeds) if len(speeds) > 1 else 0:.2f} Mbps
    Min: {min(speeds):.2f} Mbps
    Max: {max(speeds):.2f} Mbps"""
    
    fig.text(0.99, 0.01, stats_text, fontsize=9, verticalalignment='bottom', 
             horizontalalignment='right', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    # Adjust layout
    plt.tight_layout(rect=[0, 0.03, 1, 0.97])
    
    # Save figure
    output_file = f"{output_dir}/visualizations_{session_id}.png"
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Visualizations saved: {output_file}")
    
    # ============ Create hourly ranking chart (separate file) ============
    fig2, ax = plt.subplots(figsize=(12, 6))
    
    # Sort hours and speeds for better visualization
    sorted_pairs = sorted(zip(hours, hourly_avg), key=lambda x: x[1], reverse=True)
    sorted_hours, sorted_speeds = zip(*sorted_pairs) if sorted_pairs else ([], [])
    
    colors_sorted = ['#27AE60' if i < len(sorted_speeds)//2 else '#E74C3C' 
                     for i in range(len(sorted_speeds))]
    
    bars = ax.barh(range(len(sorted_hours)), sorted_speeds, color=colors_sorted, 
                   alpha=0.7, edgecolor='black', linewidth=1.5)
    ax.set_yticks(range(len(sorted_hours)))
    ax.set_yticklabels([f'{h:02d}:00' for h in sorted_hours])
    ax.set_xlabel('Average Speed (Mbps)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Hour of Day', fontsize=12, fontweight='bold')
    ax.set_title('Network Performance Ranking by Hour', fontsize=14, fontweight='bold', pad=20)
    
    # Add value labels
    for i, (bar, speed) in enumerate(zip(bars, sorted_speeds)):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f' {speed:.1f} Mbps',
                ha='left', va='center', fontsize=9, fontweight='bold')
    
    ax.axvline(x=statistics.mean(hourly_avg), color='#D55E00', linestyle='--', 
               linewidth=2, label=f'Average: {statistics.mean(hourly_avg):.1f} Mbps')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(True, alpha=0.3, axis='x')
    
    plt.tight_layout()
    output_file2 = f"{output_dir}/hourly_ranking_{session_id}.png"
    plt.savefig(output_file2, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Hourly ranking saved: {output_file2}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate reports from analysis results')
    parser.add_argument('results_file', help='Path to results JSON file')
    parser.add_argument('-o', '--output-dir', default='reports',
                       help='Output directory (default: reports)')
    parser.add_argument('--formats', nargs='+',
                       choices=['text', 'csv', 'markdown', 'all'],
                       default=['all'],
                       help='Report formats (default: all)')
    
    args = parser.parse_args()
    
    print(f"Loading results from: {args.results_file}")
    data = load_results(args.results_file)
    
    # Create output directory
    import os
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate reports
    session_id = data['session_id']
    formats = args.formats if 'all' not in args.formats else ['text', 'csv', 'markdown']
    
    if 'text' in formats:
        output_file = os.path.join(args.output_dir, f"report_{session_id}.txt")
        generate_text_report(data, output_file)
    
    if 'csv' in formats:
        output_file = os.path.join(args.output_dir, f"data_{session_id}.csv")
        generate_csv_export(data, output_file)
    
    if 'markdown' in formats:
        output_file = os.path.join(args.output_dir, f"report_{session_id}.md")
        generate_markdown_report(data, output_file)
    
    # Generate visualizations (ALWAYS generate if matplotlib available)
    print("\nGenerating visualizations...")
    generate_visualizations(data, args.output_dir, session_id)
    
    print("\n✓ Report generation complete!")


if __name__ == '__main__':
    main()
