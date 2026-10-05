#!/usr/bin/env python3
"""Falsification for the substrate guards across the isolation suites.

Eighteen rows across `r1_isolated_reachability.rs`, `r1_isolated_e2e.rs` and
`uat_040_isolated_worker_runtime.rs` returned early when unprivileged user namespaces were unavailable, and Cargo
reports a `return` as **passed**. A row that examined nothing was
indistinguishable from a row that passed — the same failure R1 was reopened for
in `9d3d556`, where a test that never ran was indistinguishable from one that
passed.

They now call `require_userns(row)`, which panics with `UNAVAILABLE_SUBSTRATE`
instead. This campaign proves that: it makes the probe answer "unavailable" the
way a locked-down host would, and asserts that exactly the guarded rows go red
and that the unguarded ones do not.

A campaign that only checks the rows go red would pass if `require_userns`
panicked unconditionally, which would turn eleven evidence rows into eleven
refusals. So there is a second pass that leaves the probe honest and asserts
everything is green again — the mutation has to be the *availability*, not the
guard.

Run:  python3 r1_substrate_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

REACHABILITY = f.REPO / "crates/broker/tests/r1_isolated_reachability.rs"
E2E = f.REPO / "crates/broker/tests/r1_isolated_e2e.rs"
UAT040 = f.REPO / "crates/broker/tests/uat_040_isolated_worker_runtime.rs"

# The eighteen rows that call the guard. Named rather than counted, because a
# count would also be satisfied by the guard panicking in a row that never
# needed it.
GUARDED = [
    "r1_a_request_on_the_public_surface_runs_a_real_isolated_process",
    "r1_caller_arguments_reach_the_child_as_arguments",
    "r1_an_unpinned_session_is_refused",
    "r1_an_isolated_run_is_recorded_in_the_audit_chain",
    "r1_a_lent_credential_does_not_come_back_in_the_response",
    "r1_the_injected_credential_reaches_the_child",
    "an_operator_declared_worker_runs_and_answers_through_the_cli",
    "a_worker_the_file_does_not_declare_is_refused",
    "uat_040_deny_worker_sees_only_loopback_and_cannot_reach_out",
    "uat_040_env_injection_reaches_child_only",
    "uat_040_file_injection_is_0600_and_cleaned_up",
    "uat_040_landlock_profile_denies_unlisted_paths",
    "uat_040_read_allow_does_not_grant_execute",
    "uat_040_large_stdout_and_stderr_are_drained_concurrently",
    "uat_040_seccomp_bite_kills_worker_calling_bpf",
    "uat_040_runaway_worker_is_killed_at_timeout",
    "uat_040_secret_in_stdout_is_redacted_transformed_is_not",
    "uat_040_completed_run_is_audited_with_metadata_only",
]

# The fourteen that do not, and must keep passing: the guard is not allowed to
# be a blanket refusal.
UNGUARDED = [
    "r1_the_audit_log_type_is_the_one_the_broker_holds",
    "r1_a_broker_with_no_declared_workers_runs_nothing",
    "r1_a_session_the_peer_does_not_own_is_refused",
    "r1_an_unregistered_worker_is_refused_before_anything_executes",
    "r1_a_refused_isolated_run_is_also_audited",
    "a_file_asking_for_unenforceable_egress_is_refused_at_the_file",
    "a_broker_whose_workers_file_is_unreadable_does_not_start",
    "a_misspelled_key_is_refused_rather_than_defaulted",
    "a_broker_declared_no_workers_runs_nothing",
    "uat_040_unregistered_name_is_refused_and_audited",
    "uat_040_allow_policy_is_refused_not_downgraded",
    "uat_040_pre_exec_isolation_failure_is_classified_and_audited",
    "uat_040_exec_failure_without_hook_marker_remains_io_error",
    "uat_040_missing_binary_refusal_is_audited",
]

# `unshare -Ur true` is what the probe actually runs, so refusing it is what a
# host without the substrate does. Anything else — a missing binary, a timeout —
# would be testing the mutation rather than the guard.
MAKE_UNAVAILABLE = ("fn userns_available() -> bool {\n", "fn userns_available() -> bool {\n    return false;\n")

# The three files, in the order they are reported.
REACHABILITY_ROWS, E2E_ROWS, UAT040_ROWS = GUARDED[:6], GUARDED[6:8], GUARDED[8:]
REACHABILITY_FAST, E2E_FAST, UAT040_FAST = UNGUARDED[:5], UNGUARDED[5:9], UNGUARDED[9:]


def run(target: str, rows: list[str], prefix: str = "") -> list[tuple[str, str]]:
    import subprocess

    verdicts = []
    for row in rows:
        # `f"--test {target}"` as one argument is a different argv from
        # `--test <target>`, and cargo silently matches nothing for the first
        # — which is how a campaign ends up reporting `no-run` for all of its
        # rows and looks like a finding about the guard.
        proc = subprocess.run(
            ["cargo", "test", "-p", "asv-broker", "--test", target,
             prefix + row, "--", "--exact"],
            cwd=f.REPO, env=f.ENV, capture_output=True, text=True, timeout=1200,
        )
        out = proc.stdout + proc.stderr
        ran = "running 1 test" in out
        failed = "test result: FAILED" in out
        verdicts.append((row, "red" if failed else ("green" if ran else "no-run")))
    return verdicts


def main() -> int:
    original = {p: p.read_text() for p in (REACHABILITY, E2E, UAT040)}
    red = green = no_run = 0
    try:
        for path in (REACHABILITY, E2E, UAT040):
            if original[path].count(MAKE_UNAVAILABLE[0]) != 1:
                print(f"SKIP  the probe signature in {path.name} is not unique")
                return 1
            path.write_text(
                original[path].replace(MAKE_UNAVAILABLE[0], MAKE_UNAVAILABLE[1], 1)
            )

        print("pass 1 — the host cannot run these rows, so the eighteen must go red\n")
        for target, rows in (("r1_isolated_reachability", REACHABILITY_ROWS),
                             ("r1_isolated_e2e", E2E_ROWS),
                             ("uat_040_isolated_worker_runtime", UAT040_ROWS)):
            for row, verdict in run(target, rows):
                print(f"  {verdict:<7} {row}")
                red += verdict == "red"
                green += verdict == "green"
                no_run += verdict == "no-run"

        print("\npass 2 — the probe is honest again, so the fourteen unguarded must be green\n")
        for target, rows in (("r1_isolated_reachability", REACHABILITY_FAST),
                             ("r1_isolated_e2e", E2E_FAST),
                             ("uat_040_isolated_worker_runtime", UAT040_FAST)):
            for row, verdict in run(target, rows):
                print(f"  {verdict:<7} {row}")
                red += verdict == "red"
                green += verdict == "green"
                no_run += verdict == "no-run"
    finally:
        for path, text in original.items():
            path.write_text(text)

    print(f"\nrows: {red + green + no_run}")
    print(f"  red (guard fired)  : {red}")
    print(f"  green (still pass) : {green}")
    print(f"  measured nothing   : {no_run}")
    ok = red == 18 and green == 14 and no_run == 0
    print("\nOK: 18 guarded rows refuse, 14 unguarded rows unaffected" if ok
          else "\nFAILED: the guard is not doing what it claims")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
