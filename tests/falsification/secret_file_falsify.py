#!/usr/bin/env python3
"""Falsification for B1.2, refusing `SecretInjectionPlan::File`.

M10-R3 is normative and says the broker MUST materialise secret bytes ONLY
inside the worker's mount namespace. The implementation did the opposite: the
parent resolved the secret and wrote it to an absolute host path, then a `Drop`
guard unlinked it when the run ended. So the credential lived in the parent
filesystem for the whole life of the worker -- readable by anything running as
the broker's uid, which is the same uid as every tool the operator runs -- and
the guard was a `Drop`, so SIGKILL skipped it entirely.

The fix was to stop serving the plan rather than to approximate the isolation:
`File` is modelled but refused, because honouring M10-R3 needs a mount point
contract no spec states, and guessing which host directories a worker's tmpfs
may mask would be inventing policy.

**The row under test lives in the integration suite**, not in the lib, because
the property it holds is about the host filesystem as observed from outside the
broker. A unit test inside `worker.rs` could assert the refusal but would be
asserting it against the same module that writes the file, which is the
arrangement that let the original defect look correct.

The two mutations worth reading first are "accept the File plan" and "stage it
on the host again". The first is the lazy half — the plan is simply not
refused, the worker runs with no credential, and the caller is told nothing. The
second is the dangerous half: it recreates exactly the shape that was removed,
including the `create_dir_all` on the parent, so AAT-RUNTIME-06's directory
assertion is what turns it red. Note the file assertion alone would not be
enough: the original code unlinked the file on the way out and left an empty
staging directory behind, so a row that only checked "the file is gone" would
have passed against the defect it was written to forbid.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sts_falsify", HERE / "sts_falsify.py")
assert spec and spec.loader, "sts_falsify.py did not load"
f = importlib.util.module_from_spec(spec)
sys.modules["sts_falsify"] = f
spec.loader.exec_module(f)

REPO = HERE.parent.parent
WORKER = REPO / "crates/broker/src/worker.rs"

# The exact arm, and the exact fall-back that puts the refused plan in the
# record. Both are mutated, so the rows they feed are the ones that must go red.
REFUSAL_ARM = "        SecretInjectionPlan::File { .. } => Err(SpawnError::FileInjectionUnsupported),"
# Every refusal call site passes `None` for the plan, and `audit_worker` fills
# it in from the template. This is the only thing that makes the record name
# the plan that was refused, and `uat_040_file_injection_is_refused_and_leaves_
# nothing_on_the_host` is the only row that measures it.
AUDIT_FALLBACK = "    let (egress, injection) = match (template, plan.or(template.map(|t| &t.secret_injection))) {"

MUTATIONS: list[tuple[str, str, str, str]] = [
    (
        # The lazy half: stop refusing. The plan is accepted, the worker runs,
        # and it runs with no credential at all -- so this is not "the secret
        # leaks", it is "the caller is told the run succeeded and silently got
        # nothing", which is its own failure mode.
        "accept the File plan",
        REFUSAL_ARM,
        "        SecretInjectionPlan::File { .. } => Ok(()),",
        "uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host",
    ),
    (
        # The dangerous half: put the staging back. The bytes here are a
        # placeholder on purpose -- the property under test is that NOTHING
        # appears on the host, so reproducing the real secret would add nothing
        # to the evidence and would put a credential in this file's failure
        # messages. The `create_dir_all` is load-bearing, not incidental: it is
        # what makes the directory assertion bite.
        "stage the secret on the host filesystem again",
        REFUSAL_ARM,
        """        SecretInjectionPlan::File { .. } => {
            if let SecretInjectionPlan::File { path, .. } = &template.secret_injection {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(path, b"staged");
            }
            Ok(())
        }""",
        "uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host",
    ),
    (
        # Classify the refusal as the caller's mistake. `InvalidRequest` tells a
        # caller to fix the request; `Denied` tells it the template itself is
        # not honourable, which is the truth and is what stops a retry loop
        # against a configuration that can never work.
        "report the refusal as a caller mistake",
        REFUSAL_ARM,
        '        SecretInjectionPlan::File { .. } => Err(SpawnError::InjectionMismatch("secret file")),',
        "uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host",
    ),
    (
        # Stop naming the plan in the record. The refusal still happens and the
        # caller still gets the typed error, so nothing about the worker changes
        # -- but every refusal call site passes `None` for the plan and relies on
        # `audit_worker` falling back to the template's own, so this leaves an
        # operator reading "a worker was refused" with no way to tell WHICH plan.
        # This mutation was re-anchored: it was first written against the call
        # site, and it survived there, because passing the plan explicitly made
        # the call site and the fall-back two independent defences for the same
        # fact. Re-anchoring to the single mechanism that actually carries the
        # property is what makes the row falsifiable instead of redundant.
        "stop naming the refused plan in the audit record",
        AUDIT_FALLBACK,
        "    let (egress, injection) = match (template, plan) {",
        "uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host",
    ),
    (
        # Record the refusal as an error. The distinction is the whole reason
        # the row exists: a refusal is the broker declining a template it will
        # always decline, and an error is the broker failing at something it
        # should have been able to do. Collapsing them tells an operator to
        # retry a configuration that can never work.
        #
        # The `if let Err(e) = plan_matches` line above is carried in the
        # snippet because the audit call itself is byte-identical to four other
        # refusal sites in this function -- and mutating one of those would
        # have measured the wrong row.
        "record the refusal as an error instead of a refusal",
        """    if let Err(e) = plan_matches {
        // `None` for the plan, like every other refusal here: `audit_worker`
        // falls back to the template's own injection plan, which is the one
        // that was just refused.
        audit_worker(audit, name, Some(template), None, "refused", None, None);""",
        """    if let Err(e) = plan_matches {
        // `None` for the plan, like every other refusal here: `audit_worker`
        // falls back to the template's own injection plan, which is the one
        // that was just refused.
        audit_worker(audit, name, Some(template), None, "error", None, None);""",
        "uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host",
    ),
]


def main() -> int:
    f.STS = WORKER
    f.TEST_PREFIX = ""
    f.CARGO_TARGET = "--test uat_040_isolated_worker_runtime"
    f.PACKAGE = "asv-broker"
    f.MUTATIONS[:] = MUTATIONS
    original = WORKER.read_text()
    print(f"# falsifying {WORKER.relative_to(REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert WORKER.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())