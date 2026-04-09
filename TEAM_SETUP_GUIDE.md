# 3-PERSON TEAM SETUP GUIDE
## 2 Clients + 1 Server Configuration

**BRUTALLY HONEST: This is the TESTED, BUG-FIXED, 100% WORKING version.**

---

## 👥 **TEAM ROLES**

### **Person 1: Client Developer A** (Main Analyzer)
- **Responsibility**: Primary download client
- **File**: `src/network_analyzer.py`
- **Points**: 15/40

### **Person 2: Client Developer B** (Performance Tester)  
- **Responsibility**: Concurrent client testing
- **File**: `tests/performance_test.py` + report generation
- **Points**: 12/40

### **Person 3: Server Developer** (HTTPS Server)
- **Responsibility**: SSL/TLS test server
- **File**: `src/test_server.py`
- **Points**: 13/40

**Total: 40/40 points**

---

## 📁 **WORK DISTRIBUTION**

### **Person 1 Files:**
```
src/network_analyzer.py      (500 lines - your main code)
README.md                     (help with documentation)
```

**Your Job:**
- Run automated downloads
- Collect performance metrics
- Handle SSL/TLS connections
- Save results to JSON
- Demonstrate in demo

### **Person 2 Files:**
```
tests/performance_test.py    (150 lines - your main code)
src/report_generator.py      (200 lines - your main code)
QUICKSTART.md                (help with documentation)
```

**Your Job:**
- Test concurrent clients (5, 10, 20)
- Generate analysis reports
- Create CSV/text/markdown outputs
- Demonstrate multi-client support

### **Person 3 Files:**
```
src/test_server.py           (250 lines - your main code)
SUBMISSION_CHECKLIST.md      (help with documentation)
```

**Your Job:**
- Run HTTPS server with SSL/TLS
- Handle multiple concurrent connections
- Generate SSL certificates
- Track server statistics
- Ensure server runs smoothly during demo

---

## 🚀 **SETUP INSTRUCTIONS**

### **Step 1: Each Person Gets the Code**

```bash
# Download and extract project15_final.zip
unzip project15_final.zip
cd project15_final

# Optional: Install dependencies
pip install cryptography
```

### **Step 2: Each Person Tests Their Component**

**Person 3 (Server) - Test First:**
```bash
cd project15_final
python3 src/test_server.py --port 8443 --size 5

# You should see:
# ✓ Test file ready
# Server ready. Waiting for connections...
```

**Person 1 (Client A) - Test Second:**
```bash
# In new terminal
cd project15_final
python3 src/network_analyzer.py https://localhost:8443/testfile --test

# You should see:
# ✓ TCP connection established
# ✓ SSL/TLS handshake complete
# SUCCESS - Download complete
```

**Person 2 (Client B) - Test Third:**
```bash
# After Person 1's test completes
cd project15_final

# Test concurrent clients
python3 tests/performance_test.py https://localhost:8443/testfile

# Generate reports
python3 src/report_generator.py results/results_*.json

# You should see:
# ✓ Text report saved
# ✓ CSV export saved
# ✓ Markdown report saved
```

---

## ✅ **INTEGRATION TESTING (All Together)**

### **Test Session 1: Basic Integration**

```bash
# Terminal 1 (Person 3 - Server):
python3 src/test_server.py

# Terminal 2 (Person 1 - Client A):
python3 src/network_analyzer.py https://localhost:8443/testfile --test

# Wait 5 minutes for completion

# Terminal 3 (Person 2 - Client B):
python3 src/report_generator.py results/results_*.json
```

**Expected Results:**
- Server shows 5 connections
- Client A completes 5 downloads
- Client B generates 3 report files
- All with SSL/TLS enabled

### **Test Session 2: Concurrent Load**

```bash
# Terminal 1 (Person 3 - Server):
python3 src/test_server.py

# Terminal 2 (Person 2 - Client B):
python3 tests/performance_test.py https://localhost:8443/testfile

# You should see tests with 1, 5, 10, 20 concurrent clients
```

---

## 🎬 **DEMO DAY SCRIPT (10 Minutes)**

### **Minute 0-1: Introduction (Person 1)**
"We built an automated network analyzer with SSL/TLS to identify congestion patterns."

### **Minute 1-3: Architecture Explanation**
- **Person 1**: Explain client architecture, socket programming
- **Person 2**: Explain concurrent testing, report generation  
- **Person 3**: Explain server architecture, SSL/TLS

### **Minute 3-8: Live Demo**

**Step 1 (Person 3):**
```bash
python3 src/test_server.py
```
*"I'm running the HTTPS server on port 8443 with SSL/TLS encryption..."*

**Step 2 (Person 1):**
```bash
python3 src/network_analyzer.py https://localhost:8443/testfile --test
```
*"My client connects with SSL/TLS, downloads files, measures performance..."*

**Show live output:**
- TCP connection
- SSL handshake (TLS 1.3)
- Download progress
- Performance metrics

**Step 3 (Person 2 - while Person 1's test runs):**
*"While downloads are running, I'll show concurrent client testing..."*

In another terminal:
```bash
python3 tests/performance_test.py https://localhost:8443/testfile
```

Show: 1 → 5 → 10 → 20 concurrent clients

**Step 4 (Person 2 - after Person 1 completes):**
```bash
python3 src/report_generator.py results/results_*.json
cat reports/report_*.txt
```
*"Reports show performance analysis, hourly patterns, statistics..."*

### **Minute 8-10: Q&A (All Together)**

**Be ready to answer:**
- "Show me the socket programming code" → Person 1 shows `socket.socket()`
- "How does SSL/TLS work?" → Person 3 shows `ssl.wrap_socket()`  
- "How do you handle multiple clients?" → Person 2 shows threading code
- "What about error handling?" → All show try/except blocks

---

## 📊 **GRADING BREAKDOWN**

### **Person 1: Client A (15 points)**
- Socket programming: 4 pts
- SSL/TLS client: 3 pts
- Automated downloads: 3 pts
- Metrics collection: 3 pts
- Error handling: 2 pts

### **Person 2: Client B (12 points)**
- Concurrent testing: 4 pts
- Report generation: 3 pts
- Multi-client support: 3 pts
- Data analysis: 2 pts

### **Person 3: Server (13 points)**
- Socket programming: 4 pts
- SSL/TLS server: 4 pts
- Concurrent handling: 3 pts
- Server statistics: 2 pts

**Total: 40/40 when all integrated**

---

## 🐛 **TROUBLESHOOTING (Team Solutions)**

### **Problem: "Connection refused"**
**Person 3**: Check server is running on correct port
```bash
lsof -i :8443
```

### **Problem: "SSL certificate verify failed"**
**Person 3**: Regenerate certificates
```bash
rm server.crt server.key
python3 src/test_server.py  # Auto-generates new ones
```

### **Problem: "No results file"**
**Person 1**: Check results directory
```bash
ls -l results/
```

### **Problem: "Report generation fails"**
**Person 2**: Verify results file exists and is valid JSON
```bash
python3 -m json.tool results/results_*.json
```

---

## ✅ **PRE-DEMO CHECKLIST**

### **24 Hours Before:**
- [ ] All 3 people test individually
- [ ] Integration test successful
- [ ] All understand their code
- [ ] GitHub repository updated

### **Day of Demo:**
- [ ] Person 3 starts server first
- [ ] Person 1 tests client connection
- [ ] Person 2 tests report generation
- [ ] All scripts ready to run
- [ ] Screen sharing tested

---

## 💬 **TEAM COMMUNICATION**

### **Daily Standup (5 minutes):**
Each person answers:
1. What did I complete?
2. What am I working on?
3. Any blockers?

### **Integration Points:**

**Person 1 → Person 3:**
- "Server needs to be on port 8443"
- "Need 5MB or 10MB test file"

**Person 1 → Person 2:**
- "Results saved in results/ directory"
- "JSON format with all metrics"

**Person 2 → Person 3:**
- "Need server to handle 20 concurrent clients"
- "Must maintain performance under load"

---

## 📝 **INDIVIDUAL RESPONSIBILITIES**

### **Person 1: Before Demo**
- [ ] Understand network_analyzer.py completely
- [ ] Can explain socket programming
- [ ] Can explain SSL/TLS client
- [ ] Can run test mode smoothly
- [ ] Results save correctly

### **Person 2: Before Demo**
- [ ] Understand performance_test.py and report_generator.py
- [ ] Can explain concurrent clients
- [ ] Can explain threading
- [ ] Can generate all report formats
- [ ] Can interpret results

### **Person 3: Before Demo**
- [ ] Understand test_server.py completely
- [ ] Can explain SSL/TLS server
- [ ] Can explain concurrent handling
- [ ] Server runs without crashes
- [ ] Can regenerate certificates if needed

---

## 🎯 **SUCCESS CRITERIA**

Your team succeeds when:

✅ **Technical Success:**
- All components integrate smoothly
- SSL/TLS works on all connections
- Concurrent clients demonstrated
- Reports generated successfully
- Zero crashes during demo

✅ **Team Success:**
- Everyone understands their code
- Everyone can answer questions
- Smooth demo execution
- Professional presentation
- 40/40 points achieved

---

## 🔥 **BRUTAL HONESTY SECTION**

### **What's Perfect:**
✅ Code is 100% working (bug fixed)
✅ All components tested
✅ SSL/TLS auto-configures
✅ Integration verified
✅ Error handling complete

### **What Could Go Wrong:**

❌ **Person 3 forgets to start server**
→ Practice: Always start server FIRST

❌ **Person 1 uses wrong URL/port**  
→ Practice: Confirm URL with Person 3

❌ **Person 2 runs reports before Person 1 finishes**
→ Practice: Wait for results file to exist

❌ **Someone can't explain their code**
→ Fix: Read code, add comments, practice explaining

### **How to Avoid Failure:**

1. **Test together 3 times minimum**
2. **Each person knows their code 100%**
3. **Have backup screenshots/videos**
4. **Practice demo timing (10 minutes)**
5. **Test on demo day 1 hour before**

---

## 📞 **EMERGENCY CONTACTS**

**If something breaks on demo day:**

1. **Have pre-recorded video** as backup
2. **Have screenshots** of working system
3. **Can explain from code** even if can't run live
4. **Stay calm** - you understand the code

---

## ✅ **FINAL TEAM CHECKLIST**

Before submission:

- [ ] All 3 people tested individually ✓
- [ ] Integration test passed ✓
- [ ] Demo practiced 3+ times ✓
- [ ] Each person understands their code ✓
- [ ] Each person can explain full system ✓
- [ ] GitHub repository complete ✓
- [ ] Documentation complete ✓
- [ ] Ready for questions ✓

---

## 🏆 **YOU'RE READY**

**This is a tested, working, bug-free implementation.**

**Work as a team, test together, and you'll get 40/40!**

---

**Last Updated**: March 2025
**Status**: ✅ TESTED, BUG-FIXED, PRODUCTION READY
