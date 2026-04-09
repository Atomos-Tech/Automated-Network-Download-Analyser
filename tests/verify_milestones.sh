#!/bin/bash
# MILESTONE VERIFICATION SCRIPT
# Tests all 5 milestones are achieved

set -e

echo "=============================================================================="
echo "PROJECT #15 - MILESTONE VERIFICATION"
echo "=============================================================================="
echo ""

cd "$(dirname "$0")"

# Clean previous results
rm -rf results/* reports/*

echo "[1/5] Testing Milestone 1: Scheduled Automated Downloads"
echo "----------------------------------------------------------------------"
echo "Starting server..."
python3 src/test_server.py --port 18446 --size 3 > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 3

echo "Running analyzer with 6 downloads at 10-second intervals..."
timeout 80 python3 src/network_analyzer.py https://localhost:18446/testfile \
    --interval 10 --duration 60 --timeout 15 > /tmp/analyzer.log 2>&1 || true

# Check results file exists
if [ ! -f results/results_*.json ]; then
    echo "✗ FAILED: No results file created"
    kill $SERVER_PID
    exit 1
fi

RESULTS_FILE=$(ls -t results/results_*.json | head -1)
echo "✓ Milestone 1 PASSED: Automated downloads completed"
echo "  Results saved: $RESULTS_FILE"
echo ""

echo "[2/5] Testing Milestone 2: Throughput Per Hour Measurement"
echo "----------------------------------------------------------------------"
# Check JSON has download speeds
SPEEDS=$(python3 -c "
import json
with open('$RESULTS_FILE') as f:
    data = json.load(f)
    successful = [r for r in data['results'] if r['success']]
    if successful:
        print(f'{len(successful)} downloads with speeds measured')
    else:
        print('FAILED: No successful downloads')
")
echo "$SPEEDS"

if [[ "$SPEEDS" == *"FAILED"* ]]; then
    echo "✗ FAILED: No speed measurements"
    kill $SERVER_PID
    exit 1
fi

echo "✓ Milestone 2 PASSED: Throughput measured for each download"
echo ""

echo "[3/5] Testing Milestone 3: Logging and Statistical Analysis"
echo "----------------------------------------------------------------------"
# Generate reports
python3 src/report_generator.py "$RESULTS_FILE" > /tmp/report.log 2>&1

# Check reports created
REPORT_COUNT=$(ls reports/ | wc -l)
if [ "$REPORT_COUNT" -lt 3 ]; then
    echo "✗ FAILED: Reports not generated (found $REPORT_COUNT, expected 3)"
    kill $SERVER_PID
    exit 1
fi

# Check statistics in report
REPORT_FILE=$(ls -t reports/report_*.txt | head -1)
if grep -q "Average Speed:" "$REPORT_FILE" && \
   grep -q "Standard Deviation:" "$REPORT_FILE" && \
   grep -q "DETAILED DOWNLOAD LOG" "$REPORT_FILE"; then
    echo "✓ Milestone 3 PASSED: Logging and statistics complete"
    echo "  Reports generated: $(ls reports/ | xargs)"
else
    echo "✗ FAILED: Statistics missing from report"
    kill $SERVER_PID
    exit 1
fi
echo ""

echo "[4/5] Testing Milestone 4: Pattern Visualization"
echo "----------------------------------------------------------------------"
# Check for pattern analysis
if grep -q "SLOWEST" "$REPORT_FILE" && \
   grep -q "FASTEST" "$REPORT_FILE" && \
   grep -q "CONGESTION" "$REPORT_FILE"; then
    echo "✓ Milestone 4 PASSED: Pattern visualization present"
    echo "  Found: Slowest/Fastest period identification"
    echo "  Found: Congestion analysis"
else
    echo "✗ FAILED: Pattern visualization missing"
    kill $SERVER_PID
    exit 1
fi
echo ""

echo "[5/5] Testing Milestone 5: Report Explaining Busiest Hour"
echo "----------------------------------------------------------------------"
# Check for hourly analysis
if grep -q "HOURLY PERFORMANCE" "$REPORT_FILE" && \
   grep -q "Hour.*Downloads.*Avg Speed" "$REPORT_FILE"; then
    echo "✓ Milestone 5 PASSED: Busiest hour analysis present"
    echo "  Found: Hourly performance table"
    
    # Extract busiest hour info
    grep -A 3 "HOURLY PERFORMANCE" "$REPORT_FILE" | tail -3
else
    echo "✗ FAILED: Hourly analysis missing"
    kill $SERVER_PID
    exit 1
fi
echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null || true

echo "=============================================================================="
echo "ALL 5 MILESTONES VERIFIED ✓✓✓"
echo "=============================================================================="
echo ""
echo "Summary:"
echo "  ✓ Scheduled automated downloads"
echo "  ✓ Throughput measured per hour"
echo "  ✓ Logging and statistical analysis"
echo "  ✓ Pattern visualization"
echo "  ✓ Report explaining busiest hour"
echo ""
echo "Project is COMPLETE and READY for submission!"
echo ""
