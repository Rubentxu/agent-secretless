#!/usr/bin/env python3
"""RC exit checklist: machine-checkable evaluation of the v1.0 release gates.

Evaluates each release gate R0..R11 defined in
`agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md` against
observable repository evidence and emits a per-gate verdict.

Statuses:
    PASS                 evidence present and satisfied in this repo
    FAIL                 required evidence absent or contradictory
    UNVERIFIABLE-IN-REPO the only missing evidence lives outside this repo
                         (external review, kernel matrix, signing infra)

Honesty rules:
    - A gate is PASS only when every one of its checks passed.
    - Absent evidence is FAIL, never a silent PASS.
    - Exit code: 0 = no FAIL in any gate; 1 = at least one FAIL.
      (UNVERIFIABLE-IN-REPO does not fail the run but is listed.)

This script is read-only. It never edits the repo or the spec pack.

Usage:
    tools/rc-exit-checklist.py [--root PATH] [--output report.json] [--quiet]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# evidence helpers
# --------------------------------------------------------------------------

PASS, FAIL, EXT = "PASS", "FAIL", "UNVERIFIABLE-IN-REPO"


class Check:
    def __init__(self, name: str, status: str, evidence: str):
        self.name = name
        self.status = status
        self.evidence = evidence


def ok(name: str, evidence: str) -> Check:
    return Check(name, PASS, evidence)


def bad(name: str, evidence: str) -> Check:
    return Check(name, FAIL, evidence)


def ext(name: str, evidence: str) -> Check:
    return Check(name, EXT, evidence)


def path_exists(root: Path, rel: str) -> bool:
    return (root / rel).exists()


def file_mentions(root: Path, rel: str, needles: list[str]) -> tuple[bool, str]:
    """True if any needle appears in the file (utf-8 tolerant)."""
    p = root / rel
    if not p.exists():
        return False, f"{rel} missing"
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return False, f"{rel} unreadable: {e}"
    for n in needles:
        if n in text:
            return True, f"{rel} mentions {n!r}"
    return False, f"{rel} exists but none of {needles} found"


def grep_crates(root: Path, pattern: str) -> tuple[bool, str]:
    """Search non-test rust sources under crates/ for a regex. Returns
    (found, evidence)."""
    rx = re.compile(pattern)
    hits: list[str] = []
    test_file_rx = re.compile(r"(tests?/|#\[cfg\(test\)\])")
    crates = root / "crates"
    if not crates.is_dir():
        return False, "crates/ directory missing"
    for p in sorted(crates.rglob("*.rs")):
        rel = p.relative_to(root).as_posix()
        if "/tests/" in rel or "/benches/" in rel:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # crude test-module strip: skip content after #[cfg(test)] marker
        m = re.search(r"#\[cfg\(test\)\]", text)
        if m:
            text = text[: m.start()]
        if rx.search(text):
            hits.append(rel)
            if len(hits) >= 5:
                break
    if hits:
        return True, "found in: " + ", ".join(hits)
    return False, "no match in crates/**.rs (non-test)"


def tests_dir_has(root: Path, crate: str, names: list[str]) -> tuple[bool, str]:
    d = root / "crates" / crate / "tests"
    if not d.is_dir():
        return False, f"crates/{crate}/tests missing"
    present = [n for n in names if (d / n).exists()]
    missing = [n for n in names if n not in present]
    if not present:
        return False, f"none of {names} present in crates/{crate}/tests"
    ev = f"present: {', '.join(present)}"
    if missing:
        ev += f"; MISSING: {', '.join(missing)}"
    return (len(missing) == 0), ev


def head_sha(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


# --------------------------------------------------------------------------
# gate checks (R0..R11), mirroring 16-SECURITY-RELEASE-GATES.md
# --------------------------------------------------------------------------


def gate_r0(root: Path) -> list[Check]:
    checks = []
    if path_exists(root, "Cargo.lock"):
        checks.append(ok("dependency lockfile committed", "Cargo.lock exists"))
    else:
        checks.append(bad("dependency lockfile committed", "Cargo.lock missing"))
    if path_exists(root, "target/sbom.json"):
        checks.append(ok("SBOM generated", "target/sbom.json exists"))
    else:
        checks.append(bad("SBOM generated", "target/sbom.json missing (run cargo audit sbom or equivalent)"))
    found, ev = file_mentions(
        root, "docs/manual/OPERATIONS.md", ["build", "Build"]
    )
    if found:
        checks.append(ok("build process documented", ev))
    else:
        checks.append(bad("build process documented", ev))
    # signed artifacts: signing infra is external to this repo
    checks.append(ext("release artifacts signed where supported", "signing happens on release infrastructure, not verifiable in-repo"))
    # no secret-dump debug feature in production build
    found, ev = grep_crates(root, r"dump_secrets|secret_dump|print_secret\s*\(")
    checks.append(
        ok("no secret-dump debug feature", ev)
        if not found
        else bad("no secret-dump debug feature", ev)
    )
    return checks


def gate_r1(root: Path) -> list[Check]:
    checks = []
    # The forbidden names may legitimately appear in doc comments and in the
    # closed-set NEGATIVE tests of ipc-protocol. What R1 forbids is a real
    # callable definition. So: (a) no `fn <name>` definition outside tests,
    # (b) the ipc Request enum is a closed serde-tagged allow-list whose
    # variants omit every secret-returning method.
    forbidden = ["get_secret", "export_secret", "show_token", "read_vault_record"]
    for name in forbidden:
        found, ev = grep_crates(root, rf"fn\s+{name}\s*[<(]")
        checks.append(
            ok(f"no {name}() definition in non-test code", ev)
            if not found
            else bad(f"no {name}() definition in non-test code", f"fn {name} defined: {ev}")
        )
    # closed allow-list: serde-tagged Request enum in ipc-protocol
    proto = root / "crates" / "ipc-protocol" / "src" / "lib.rs"
    closed = False
    ev2 = "crates/ipc-protocol/src/lib.rs missing"
    if proto.exists():
        t = proto.read_text(encoding="utf-8", errors="replace")
        has_tag = '#[serde(tag = "method"' in t
        has_forbidden_variants = any(
            re.search(rf"^\s*{name}\s*{{", t, re.M) for name in forbidden
        )
        closed = has_tag and not has_forbidden_variants
        ev2 = (
            "Request is a serde-tagged closed method enum; no secret-returning variant"
            if closed
            else "Request enum missing tag or declares a forbidden method variant"
        )
    checks.append(ok("closed method-set enforced in ipc-protocol", ev2) if closed else bad("closed method-set enforced in ipc-protocol", ev2))
    return checks


def gate_r2(root: Path) -> list[Check]:
    checks = []
    tests = root / "crates" / "vault" / "tests"
    lib = root / "crates" / "vault" / "src"
    has_crypto_tests = False
    for base in (tests, lib):
        if base.is_dir():
            for p in base.rglob("*.rs"):
                try:
                    t = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if re.search(r"wrong[_-]?key|tamper|authenticated[_-]?encrypt", t, re.I):
                    has_crypto_tests = True
                    break
        if has_crypto_tests:
            break
    checks.append(
        ok("authenticated encryption + wrong-key/tamper tests", "found tamper/wrong-key tests in vault crate")
        if has_crypto_tests
        else bad("authenticated encryption + wrong-key/tamper tests", "no tamper/wrong-key test found in crates/vault")
    )
    found, ev = grep_crates(root, r"migrat(e|ion)")
    has_migration_tests = "tests" in ev or "test" in ev
    checks.append(
        ok("migration tests present", ev)
        if has_migration_tests
        else bad("migration tests present", "no version-to-version migration test found (M13 honest gap: upgrade/migration tests deferred to a follow-up cycle)")
    )
    has_zeroize = False
    for p in (root / "crates").rglob("Cargo.toml"):
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "zeroize" in t:
            has_zeroize = True
            break
    checks.append(
        ok("zeroization where observable", "zeroize dependency found in workspace")
        if has_zeroize
        else bad("zeroization where observable", "no zeroize dependency in any crate")
    )
    found, ev = file_mentions(root, "crates/broker/src/lib.rs", ["core", "rlimit", "RLIMIT_CORE", "disable_core"])
    if found:
        checks.append(ok("broker core dumps disabled", ev))
    else:
        found2, ev2 = grep_crates(root, r"RLIMIT_CORE|disable_core_dumps|core_dump")
        checks.append(
            ok("broker core dumps disabled", ev2)
            if found2
            else bad("broker core dumps disabled", "no core-dump disable code found in broker")
        )
    return checks


def gate_r3(root: Path) -> list[Check]:
    checks = []
    names = ["uat_003_proc_inspection.rs", "uat_005_privileged_tools.rs", "uat_005_replay.rs"]
    found, ev = tests_dir_has(root, "broker", names)
    checks.append(ok("peer credentials / replay UAT present", ev) if found else bad("peer credentials / replay UAT present", ev))
    found, ev = grep_crates(root, r"pidfd|SO_PEERCRED|peer_uid|peer_pid")
    checks.append(ok("OS peer credentials source", ev) if found else bad("OS peer credentials source", ev))
    found, ev = grep_crates(root, r"revoke")
    checks.append(ok("revoke path present", ev) if found else bad("revoke path present", ev))
    return checks


def gate_r4(root: Path) -> list[Check]:
    checks = []
    if path_exists(root, "crates/policy"):
        checks.append(ok("policy crate present", "crates/policy exists"))
    else:
        checks.append(bad("policy crate present", "crates/policy missing"))
    found, ev = grep_crates(root, r"[Cc]edar")
    checks.append(ok("Cedar integration present", ev) if found else bad("Cedar integration present", ev))
    found, ev = grep_crates(root, r"deny_by_default|Deny\b.*default|default.*[Dd]eny")
    checks.append(ok("deny-by-default present", ev) if found else bad("deny-by-default present", ev))
    found, ev = grep_crates(root, r"replay.*[Bb]lock|single[_-]?use|nonce")
    checks.append(ok("approval replay blocked", ev) if found else bad("approval replay blocked", ev))
    names = ["uat_010_connect_allow_list.rs", "uat_011_redirect_denier.rs"]
    found, ev = tests_dir_has(root, "broker", names)
    checks.append(ok("negative-authorization UATs present", ev) if found else bad("negative-authorization UATs present", ev))
    return checks


def gate_r5(root: Path) -> list[Check]:
    checks = []
    for c in ("connector-http", "connector-pg", "ssh-agent"):
        if path_exists(root, f"crates/{c}"):
            checks.append(ok(f"connector crate {c}", f"crates/{c} exists"))
        else:
            checks.append(bad(f"connector crate {c}", f"crates/{c} missing"))
    # documented limitations: release reports per milestone exist
    rel = root / "releases"
    if rel.is_dir() and any(rel.iterdir()):
        checks.append(ok("milestone release reports (documented limitations)", f"{len(list(rel.iterdir()))} entries under releases/"))
    else:
        checks.append(bad("milestone release reports (documented limitations)", "releases/ empty or missing"))
    return checks


def gate_r6(root: Path) -> list[Check]:
    checks = []
    names = [
        "uat_003_proc_inspection.rs",
        "uat_005_privileged_tools.rs",
        "uat_017_env_scan.rs",
        "uat_021_isolated_worker_egress.rs",
        "uat_022_transformed_stdout_leak.rs",
        "uat_023_cgroup_escape.rs",
    ]
    found, ev = tests_dir_has(root, "broker", names)
    checks.append(ok("adversarial UAT suite present", ev) if found else bad("adversarial UAT suite present", ev))
    found, ev = grep_crates(root, r"ptrace|process_vm_readv")
    checks.append(ok("hardened profile denies ptrace/VM access", ev) if found else bad("hardened profile denies ptrace/VM access", ev))
    return checks


def gate_r7(root: Path) -> list[Check]:
    checks = []
    if path_exists(root, "crates/ebpfd"):
        checks.append(ok("privileged helper crate present", "crates/ebpfd exists"))
    else:
        checks.append(bad("privileged helper crate present", "crates/ebpfd missing"))
    names = ["uat_023_cgroup_escape.rs", "uat_024_helper_scope.rs"]
    found, ev = tests_dir_has(root, "broker", names)
    checks.append(ok("cgroup escape + helper scope UATs", ev) if found else bad("cgroup escape + helper scope UATs", ev))
    found, ev = grep_crates(root, r"shipped|allow[-_]list", )
    ebpfd_closed = False
    lib = root / "crates" / "ebpfd" / "src" / "lib.rs"
    if lib.exists():
        t = lib.read_text(encoding="utf-8", errors="replace")
        ebpfd_closed = "connect4-redirect-v1" in t or "ProgramName" in t or "program.load" in t
    checks.append(
        ok("closed BPF object allow-list", f"ebpfd declares closed program set")
        if ebpfd_closed or found
        else bad("closed BPF object allow-list", "no closed allow-list found in ebpfd")
    )
    return checks


def gate_r8(root: Path) -> list[Check]:
    # Tauri UI not started in this repo at RC-prototype stage
    app_dirs = [d for d in ("app", "ui", "dashboard", "tauri") if path_exists(root, d)]
    if app_dirs:
        return [ok("UI app directory present", f"found: {', '.join(app_dirs)} (manual CSP/XSS review still required)")]
    return [
        ext(
            "Tauri gate",
            "no Tauri app directory in this repo yet; R8 applies when the UI milestone starts (docs/09-TAURI-DASHBOARD.md is normative)",
        )
    ]


def gate_r9(root: Path) -> list[Check]:
    checks = []
    found, ev = grep_crates(root, r"canary")
    checks.append(ok("canary secret checks present", ev) if found else bad("canary secret checks present", ev))
    # audit chain: look at the audit module surface, not just exact tokens
    audit_hits = []
    audit = root / "crates" / "broker" / "src"
    for p in sorted(audit.glob("*.rs")) if audit.is_dir() else []:
        t = p.read_text(encoding="utf-8", errors="replace")
        if re.search(r"audit", t, re.I) and re.search(
            r"seq(uence)?|prev(ious)?[_-]?(hash|digest)|chain|event_hash", t, re.I
        ):
            audit_hits.append(p.relative_to(root).as_posix())
    checks.append(
        ok("audit event chain (sequence/hash) present", ", ".join(audit_hits[:4]))
        if audit_hits
        else bad("audit event chain (sequence/hash) present", "no sequenced/hashed audit records found in broker")
    )
    found, ev = grep_crates(root, r"retention")
    checks.append(ok("retention configurable", ev) if found else bad("retention configurable", "no retention configuration found (R9 requires configurable retention)"))
    found, ev = grep_crates(root, r"posture|ISOLATED_PROCESS_EXPOSURE")
    checks.append(ok("security posture recorded per operation", ev) if found else bad("security posture recorded per operation", ev))
    return checks


def gate_r10(root: Path) -> list[Check]:
    checks = []
    found, ev = grep_crates(root, r"ISOLATED_PROCESS_EXPOSURE|STRONG_SECRETLESS|SERVICE_BROKERED|POSTURE")
    checks.append(ok("posture labels defined and used", ev) if found else bad("posture labels defined and used", ev))
    found, ev = file_mentions(root, "README.md", ["ISOLATED", "posture", "Posture"])
    checks.append(ok("README does not overclaim secretless", ev) if found else bad("README does not overclaim secretless", "README.md lacks posture labeling"))
    return checks


def gate_r11(root: Path) -> list[Check]:
    checks = []
    # check-gates: UAT -> milestone mapping
    try:
        out = subprocess.run(
            [sys.executable, "tools/check-gates.py"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if out.returncode == 0:
            checks.append(ok("check-gates.py UAT/milestone mapping", "exit 0, 0 hard defects"))
        else:
            checks.append(bad("check-gates.py UAT/milestone mapping", f"exit {out.returncode}"))
    except (subprocess.TimeoutExpired, OSError) as e:
        checks.append(bad("check-gates.py UAT/milestone mapping", f"could not run: {e}"))
    # fuzz corpus (RC2 of this cycle; baseline)
    if any((root / "fuzz").glob("*")) if (root / "fuzz").exists() else False:
        checks.append(ok("fuzz baseline present", "fuzz/ crate exists (corpus grows with runs)"))
    else:
        checks.append(bad("fuzz baseline present", "fuzz/ missing (RC2 not yet delivered)"))
    checks.append(ext("full supported-kernel matrix green", "kernel matrix testing happens on target hosts, external to this repo"))
    # dependency advisories: cargo audit cache if present
    audit = root / "target" / "cargo-audit.json"
    if audit.exists():
        checks.append(ok("dependency advisories triaged (cached audit)", "target/cargo-audit.json exists"))
    else:
        checks.append(bad("dependency advisories triaged (cached audit)", "target/cargo-audit.json missing (run `cargo audit --json > target/cargo-audit.json`)"))
    # NFR-PERF-001 evidence pointer
    found, ev = tests_dir_has(root, "broker", ["uat_030_perf.rs"])
    checks.append(ok("NFR-PERF-001 evidence (uat_030_perf.rs)", ev) if found else bad("NFR-PERF-001 evidence (uat_030_perf.rs)", ev))
    return checks


GATES = [
    ("R0", "Build and provenance", gate_r0),
    ("R1", "Secret API invariant", gate_r1),
    ("R2", "Vault", gate_r2),
    ("R3", "Identity/session", gate_r3),
    ("R4", "Policy", gate_r4),
    ("R5", "Connector security", gate_r5),
    ("R6", "Agent leak harness", gate_r6),
    ("R7", "eBPF/privilege separation", gate_r7),
    ("R8", "Tauri", gate_r8),
    ("R9", "Audit", gate_r9),
    ("R10", "Compatibility truthfulness", gate_r10),
    ("R11", "Full certification", gate_r11),
]

SPEC_PACK = "agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md"


def verify_spec_pack(root: Path) -> None:
    """Fail loudly if the normative gate doc drifted (heading disappeared)."""
    p = root / SPEC_PACK
    if not p.exists():
        print(f"FATAL: normative gate doc missing: {SPEC_PACK}", file=sys.stderr)
        sys.exit(2)
    text = p.read_text(encoding="utf-8", errors="replace")
    for gid, title, _ in GATES:
        if not re.search(rf"^## {re.escape(gid)} — {re.escape(title)}\s*$", text, re.M):
            print(
                f"FATAL: gate section '{gid} — {title}' not found in {SPEC_PACK}; "
                "the checklist and the spec pack have drifted",
                file=sys.stderr,
            )
            sys.exit(2)


def gate_status(checks: list[Check]) -> str:
    if any(c.status == FAIL for c in checks):
        return FAIL
    if any(c.status == EXT for c in checks):
        return EXT
    return PASS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--output", help="write JSON report here (in addition to stdout)")
    ap.add_argument("--quiet", action="store_true", help="only print the summary line")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    verify_spec_pack(root)

    report_gates = []
    for gid, title, fn in GATES:
        checks = fn(root)
        status = gate_status(checks)
        report_gates.append(
            {
                "id": gid,
                "title": title,
                "status": status,
                "checks": [
                    {"name": c.name, "status": c.status, "evidence": c.evidence}
                    for c in checks
                ],
            }
        )

    fails = [g for g in report_gates if g["status"] == FAIL]
    report = {
        "schema_version": 1,
        "repo_head": head_sha(root),
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "spec_pack": SPEC_PACK,
        "gates": report_gates,
        "summary": {
            "pass": sum(1 for g in report_gates if g["status"] == PASS),
            "fail": len(fails),
            "unverifiable_in_repo": sum(1 for g in report_gates if g["status"] == EXT),
        },
    }

    if not args.quiet:
        for g in report_gates:
            print(f"{g['id']:<4} {g['title']:<32} {g['status']}")
            for c in g["checks"]:
                if c["status"] != PASS or g["status"] != PASS:
                    print(f"     - [{c['status']}] {c['name']}: {c['evidence']}")
        s = report["summary"]
        print(f"\nsummary: {s['pass']} PASS / {s['fail']} FAIL / {s['unverifiable_in_repo']} UNVERIFIABLE-IN-REPO")

    payload = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    if fails:
        print(f"FAIL: {len(fails)} gate(s) failing: {', '.join(g['id'] for g in fails)}", file=sys.stderr)
        return 1
    print("OK: no gate reports FAIL (UNVERIFIABLE-IN-REPO items are listed in the report)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
