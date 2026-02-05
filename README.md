# soc-traffic-analyzer

# Run comprehensive tests
python3 test_infection_analysis.py

# Expected output:
============================================================
PCAP ANALYZER - INFECTION ANALYSIS TEST SUITE
============================================================
[TEST] Creating realistic infection scenario...
  Victim: 192.168.1.100 (00:0c:29:3a:2b:4c)
  Hostname: WORKSTATION-PC
  User: john.doe

[TEST 1] Victim IP Identification
============================================================
✓ PASS: Correctly identified victim IP: 192.168.1.100
✓ PASS: Correctly extracted MAC: 00:0c:29:3a:2b:4c
✓ PASS: Correctly extracted hostname: WORKSTATION-PC
✓ PASS: Correctly extracted user: john.doe
✓ PASS: Identified infection start time: 2024-02-03 19:33:20
✓ PASS: Identified C2 server: 185.220.101.50

[TEST 2] Attack Chain Reconstruction
============================================================
✓ Generated 6 attack events
✓ PASS: Events are in chronological order
✓ PASS: Identified 5 attack phases: {...}

============================================================
TEST SUMMARY
============================================================
Test 1 (Victim Identification): PASS
Test 2 (Attack Chain): PASS

OVERALL: ✓ ALL TESTS PASSED
============================================================

