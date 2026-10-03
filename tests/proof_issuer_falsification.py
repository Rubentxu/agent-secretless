#!/usr/bin/env python3
"""Falsification harness for the proof issuer and its agent client.

`crates/ssh-agent/src/client.rs` answers the question the roadmap had open:
who owns the counter. The answer is `ProofIssuer` — one per session, holding
the only counter that session spends — and the answer is only worth something
if the properties that make it the answer can each be seen to fail.

The counter is the part that is easy to get quietly wrong. A non-atomic
increment passes every sequential test. A counter that is read but not spent
passes every "the proof verifies" test. A counter handed back after a failed
signing passes every test in which signing never fails. Each of those is a
mutant here, and each has a named test that must go red.

The client half is falsified against a real `AgentSession` socket, because the
thing under test is that two halves of one crate agree across a length-prefixed
frame. A fake would agree with a misreading of the format, and the first
version of the identities reader *was* a misreading — it forgot that every
identity carries a comment as well as a blob, and it failed against the real
socket on the first run.

Run with `--dry-run` to list mutations and their targets without building.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "ssh-agent" / "src" / "client.rs"

MUTATIONS: dict[str, tuple[str, str, str, list[str]]] = {
    "counter_never_advances": (
        "the counter is incremented by zero, so every proof repeats itself",
        "let counter = self.counter.fetch_add(1, Ordering::SeqCst);",
        "let counter = self.counter.fetch_add(0, Ordering::SeqCst);",
        ["every_proof_spends_a_distinct_counter"],
    ),
    "counter_read_not_spent": (
        "the counter is read without being claimed, so two callers can take the same one",
        "let counter = self.counter.fetch_add(1, Ordering::SeqCst);",
        "let counter = self.counter.load(Ordering::SeqCst);",
        ["concurrent_issuers_never_repeat_a_counter"],
    ),
    "counter_returned_on_failure": (
        "a failed signing hands the counter back, so it can be walked backwards",
        "        let counter = self.counter.fetch_add(1, Ordering::SeqCst);\n        let signature = self\n            .client\n            .sign(&self.key_blob, &proof_nonce(&self.key_blob, host, port, counter))?;",
        "        let counter = self.counter.load(Ordering::SeqCst);\n        let signature = match self\n            .client\n            .sign(&self.key_blob, &proof_nonce(&self.key_blob, host, port, counter))\n        {\n            Ok(s) => { self.counter.store(counter + 1, Ordering::SeqCst); s }\n            Err(e) => { self.counter.store(counter, Ordering::SeqCst); return Err(e); }\n        };",
        ["a_failed_signing_still_spends_its_counter"],
    ),
    "counter_not_in_the_proof": (
        "the proof carries a constant counter while the nonce uses the real one",
        "        Ok(SessionProof {\n            key: self.key_blob.clone(),\n            signature,\n            counter,\n        })",
        "        Ok(SessionProof {\n            key: self.key_blob.clone(),\n            signature,\n            counter: 0,\n        })",
        ["every_proof_spends_a_distinct_counter"],
    ),
    "nonce_ignores_destination": (
        "the nonce is derived without the destination, so a proof is good for any host",
        "            .sign(&self.key_blob, &proof_nonce(&self.key_blob, host, port, counter))?;",
        "            .sign(&self.key_blob, &proof_nonce(&self.key_blob, \"\", 0, counter))?;",
        # The destination test was only negatives and could not see this, so it
        # now carries its own positive half. The round trip is listed too
        # because it is the other place the real nonce is checked.
        [
            "a_proof_is_refused_for_a_destination_it_was_not_minted_for",
            "a_minted_proof_verifies_against_the_nonce_the_broker_will_derive",
        ],
    ),
    "client_ignores_the_named_key": (
        "the client asks for a signature without naming the key it wants signed",
        "        put_string(&mut payload, key_blob);",
        "        put_string(&mut payload, &[]);",
        # Only the positive control. Naming no key makes the agent refuse
        # *everything*, and "refuses the wrong key" is still true of an agent
        # that refuses every key — so the wrong-key test cannot see this, and
        # expecting it to was my error, not a hole in the code.
        ["a_minted_proof_verifies_against_the_nonce_the_broker_will_derive"],
    ),
    "refusal_read_as_a_signature": (
        "a FAILURE response is not distinguished from a signature",
        "            return Err(if response.first().copied() == Some(FAILURE) {\n                AgentError::Refused\n            } else {\n                AgentError::Malformed\n            });",
        "            return Err(AgentError::Malformed);",
        [
            "a_wrong_key_blob_is_refused_by_the_agent",
            "a_refusal_is_distinguishable_from_a_missing_socket",
        ],
    ),
    "algorithm_not_checked": (
        "a signature blob naming another algorithm is passed on as a signature",
        "        if algorithm != ED25519_ALGORITHM {\n            return Err(AgentError::Unsupported);\n        }",
        "        let _ = algorithm;",
        ["a_signature_blob_naming_another_algorithm_is_refused"],
    ),
    "trailing_bytes_ignored": (
        "a signature blob with extra bytes after it is accepted",
        "        let signature = inner.string()?;\n        if !inner.done() {\n            return Err(AgentError::Malformed);\n        }",
        "        let signature = inner.string()?;",
        ["a_response_with_trailing_bytes_is_refused"],
    ),
    "identity_comment_skipped": (
        "the identity reader forgets that every identity carries a comment",
        "            let _comment = cursor.string()?;",
        "            // MUTATION: comment not read",
        ["the_client_reads_the_agents_only_identity"],
    ),
    "first_of_several_identities_chosen": (
        "an agent offering two identities has the first one picked",
        "        if blobs.len() != 1 {",
        "        if blobs.is_empty() {",
        ["two_identities_are_refused_rather_than_one_being_picked"],
    ),
    "empty_identity_list_accepted": (
        "an agent holding no identity is treated as usable",
        "        if count == 0 {\n            return Err(AgentError::NoIdentities);\n        }",
        "        if false {\n            return Err(AgentError::NoIdentities);\n        }",
        ["an_agent_with_no_identities_is_refused"],
    ),
    "frame_bound_dropped": (
        "a length field off the socket is no longer bounded before it allocates",
        "    if size == 0 || size > MAX_AGENT_MESSAGE {\n        return Err(AgentError::Malformed);\n    }\n    let mut payload = vec![0u8; size];",
        "    if size == 0 {\n        return Err(AgentError::Malformed);\n    }\n    let mut payload = vec![0u8; size];",
        ["a_frame_claiming_more_than_the_bound_is_refused"],
    ),
    "oversized_payload_sent": (
        "an unbounded payload is framed instead of refused before it leaves",
        "        if data.len() > MAX_AGENT_MESSAGE {\n            return Err(AgentError::Malformed);\n        }",
        "        if false {\n            return Err(AgentError::Malformed);\n        }",
        ["an_unbounded_payload_is_refused_before_it_is_sent"],
    ),
}

TESTS = [
    "the_client_reads_the_agents_only_identity",
    "a_minted_proof_verifies_against_the_nonce_the_broker_will_derive",
    "a_proof_is_refused_for_a_destination_it_was_not_minted_for",
    "every_proof_spends_a_distinct_counter",
    "a_second_issuer_starts_its_own_counter_and_that_is_visible",
    "concurrent_issuers_never_repeat_a_counter",
    "a_failed_signing_still_spends_its_counter",
    "a_revoked_session_stops_signing_and_says_so",
    "a_socket_that_is_not_there_is_an_io_error_not_a_refusal",
    "a_socket_pointed_at_something_else_cannot_mint_a_proof",
    "a_wrong_key_blob_is_refused_by_the_agent",
    "an_unbounded_payload_is_refused_before_it_is_sent",
    "a_signature_blob_naming_another_algorithm_is_refused",
    "a_response_with_trailing_bytes_is_refused",
    "two_identities_are_refused_rather_than_one_being_picked",
    "an_agent_with_no_identities_is_refused",
    "a_frame_claiming_more_than_the_bound_is_refused",
    "a_refusal_is_distinguishable_from_a_missing_socket",
]


def run_tests() -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-ssh-agent", "--lib"],
        capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def failing_tests(output: str) -> set[str]:
    failed: set[str] = set()
    for line in output.splitlines():
        if line.startswith("test client::") and " ... FAILED" in line:
            failed.add(line.split("client::", 1)[1].split(" ", 1)[0].split("::", 1)[-1])
    return failed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    original = TARGET.read_text(encoding="utf-8")

    if args.dry_run:
        for key in sorted(MUTATIONS):
            description, find, _, must = MUTATIONS[key]
            print(f"{key}: {description}")
            print(f"    site {'present' if find in original else 'MISSING'}")
            print(f"    must redden: {', '.join(must)}")
        return 0

    missing = [k for k, (_, f, _, _) in MUTATIONS.items() if f not in original]
    if missing:
        print("MUTATION SITES MISSING from the live file:")
        for k in missing:
            print(f"  - {k}")
        return 1

    code, output = run_tests()
    if code != 0:
        print("CONTROL IS RED — the unmutated client does not pass its own tests.")
        print(output[-3000:])
        return 1
    print(f"ok control: {len(TESTS)} client tests pass unmutated\n")

    failures: list[str] = []
    for key in sorted(MUTATIONS):
        description, find, replace, must = MUTATIONS[key]
        backup = original
        try:
            TARGET.write_text(original.replace(find, replace, 1), encoding="utf-8")
            rc, out = run_tests()
        finally:
            TARGET.write_text(backup, encoding="utf-8")
        if "could not compile" in out:
            failures.append(f"{key}: the mutation does not compile, so it proves nothing")
            print(f"XX {key}: {description}\n     does not compile — proves nothing")
            continue
        red = failing_tests(out)
        caught = set(must) <= red
        others = sorted(red - set(must))
        detail = "red: " + ", ".join(sorted(red)) if red else "nothing went red"
        if others:
            detail += f"  (also red: {', '.join(others)})"
        print(f"{'ok' if caught else 'XX'} {key}: {description}\n     {detail}")
        if not caught:
            failures.append(f"{key}: expected {sorted(must)} red, saw {sorted(red)}")
            print(out[-1200:])

    print()
    if failures:
        print(f"FALSIFICATION FAILED ({len(failures)}):")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"All {len(MUTATIONS)} mutations killed, control green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
