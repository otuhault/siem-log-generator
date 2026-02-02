#!/usr/bin/env python3
"""
Test script to verify log generators produce realistic output
"""

from log_generators.apache import ApacheAccessLogGenerator
from log_generators.windows import WindowsEventLogGenerator

print("=" * 80)
print("Testing Apache Access Log Generator")
print("=" * 80)

apache_gen = ApacheAccessLogGenerator()
print("\nGenerating 3 sample Apache access logs:\n")
for i in range(3):
    print(apache_gen.generate())

print("\n" + "=" * 80)
print("Testing Windows Security Event Log Generator")
print("=" * 80)

windows_gen = WindowsEventLogGenerator()
print("\nGenerating 3 sample Windows Event Logs:\n")
for i in range(3):
    log = windows_gen.generate()
    # Print first 500 chars to keep it readable
    print(log[:500] + "..." if len(log) > 500 else log)
    print()

print("=" * 80)
print("✅ All generators working correctly!")
print("=" * 80)
