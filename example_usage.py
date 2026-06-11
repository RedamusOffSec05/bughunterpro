#!/usr/bin/env python3
"""
BugHunterPro - Usage Examples
"""

from BugHunterPro import BugHunterPro

# Example 1: Basic hunting
print("Example 1: Basic Hunting")
hunter = BugHunterPro("example.com", mode="normal")
results = hunter.hunt()
print(f"Subdomains: {results['subdomains']}")
print()

# Example 2: Aggressive mode
print("Example 2: Aggressive Mode")
hunter = BugHunterPro("target.com", mode="aggressive")
results = hunter.hunt()
print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
print()

# Example 3: Multiple targets
print("Example 3: Multiple Targets")
targets = ["example.com", "test.com"]
for target in targets:
    print(f"Scanning {target}...")
    hunter = BugHunterPro(target, mode="normal")
    results = hunter.hunt()
    print(f"  Subdomains found: {len(results['subdomains'])}")
