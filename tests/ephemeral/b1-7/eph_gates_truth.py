#!/usr/bin/env python3
"""Read-only B1.7 checks; run from the repository root."""

import re
import subprocess


failures = []


def check(name, condition):
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


sha = subprocess.run(
    ["sha256sum", "--check", "--strict", "SHA256SUMS"],
    cwd="agent-secretless-vault-spec", capture_output=True, text=True,
)
check("spec checksums return 0", sha.returncode == 0)
if sha.returncode:
    print(sha.stdout, end="")
    print(sha.stderr, end="")

gates = subprocess.run(
    ["python3", "tools/check-gates.py"], capture_output=True, text=True,
)
check("check-gates returns 0", gates.returncode == 0)
check("hard defects:           0", "hard defects:           0" in gates.stdout)
count = re.search(r"^\s*warnings:\s+(\d+)\s*$", gates.stdout, re.M)
check("warnings count == 5", count is not None and int(count.group(1)) == 5)
section = re.search(r"^== warnings ==\n(.*?)^== summary ==", gates.stdout, re.M | re.S)
warnings = [line for line in section.group(1).splitlines() if line.strip().startswith("WARN ")] if section else []
expected = {
    "uat_010_connect_allow_list.rs": "010",
    "uat_011_redirect_denier.rs": "011",
    "uat_012_trust_injection.rs": "012",
    "uat_017_env_scan.rs": "017",
    "uat033_live.rs": "033",
}
matched = []
for filename, uid in expected.items():
    matches = [line for line in warnings if re.search(
        rf"^\s*WARN \S*/{re.escape(filename)} is named uat_{uid} but declares no UAT id; the filename claims UAT-{uid} \(.*\)$",
        line,
    )]
    check(f"exactly one filename-only WARN for {filename} (UAT-{uid})", len(matches) == 1)
    matched.extend(matches)
check("no other WARN lines", section is not None and len(warnings) == 5 and sorted(matched) == sorted(warnings))
if failures:
    print("Observed warning list:")
    print("\n".join(warnings) or "(none)")
    if gates.returncode:
        print(gates.stdout, end="")
        print(gates.stderr, end="")
raise SystemExit(1 if failures else 0)
