#!/usr/bin/env python3
"""Falsification harness for the shared session-proof format.

`crates/ssh-agent/src/proof.rs` is the single definition of the CONNECT
session-proof wire format, and the pinned vector in
`the_nonce_layout_is_pinned` is the only thing standing between a refactor and
a silent change to the digest every deployed proof is computed over.

This harness exists because a pinned vector is only worth what it can catch.
Each mutation below changes exactly one property of the format and the harness
requires a *named* test to go red. A mutation that makes the crate fail to
compile counts against the harness: a format test that dies on any
perturbation cannot tell "the property broke" from "the test broke".

The two halves are falsified separately because they fail for different
reasons. A digest mutation is caught by the vector and by nothing else — the
round-trip test signs and verifies with the same function, so it would agree
with any layout at all. A parser mutation is caught by the arity and strictness
tests and by nothing else. A harness that only ran one half would leave the
other untested while reporting coverage.

Run with `--dry-run` to list the mutations and their targets without building.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "ssh-agent" / "src" / "proof.rs"

# name -> (description, find, replace, tests that must go red)
MUTATIONS: dict[str, tuple[str, str, str, list[str]]] = {
    "drop_domain_separation": (
        "the domain constant is no longer hashed in first",
        "    hasher.update(PROOF_DOMAIN);",
        "    // MUTATION: domain dropped",
        ["the_nonce_layout_is_pinned"],
    ),
    "drop_key_length_prefix": (
        "the key is hashed without its length prefix",
        "    hasher.update((presented_key.len() as u64).to_be_bytes());",
        "    // MUTATION: length prefix dropped",
        ["the_nonce_layout_is_pinned"],
    ),
    "drop_port": (
        "the destination port stops being bound into the nonce",
        "    hasher.update((port as u64).to_be_bytes());",
        "    // MUTATION: port dropped",
        ["the_nonce_layout_is_pinned"],
    ),
    "drop_counter": (
        "the counter stops being bound into the nonce, so one signature covers every counter",
        "    hasher.update(counter.to_be_bytes());",
        "    // MUTATION: counter dropped",
        ["the_nonce_layout_is_pinned"],
    ),
    "swap_port_and_counter": (
        "port and counter are hashed in the opposite order",
        "    hasher.update((port as u64).to_be_bytes());\n    // Fixed width, so no choice of counter bytes can be confused with a\n    // shorter host or a different port.\n    hasher.update(counter.to_be_bytes());",
        "    hasher.update(counter.to_be_bytes());\n    hasher.update((port as u64).to_be_bytes());",
        ["the_nonce_layout_is_pinned"],
    ),
    "counter_swallowed": (
        "a counter that is not a number parses as zero instead of being refused",
        "let counter: u64 = parts.next()?.parse().ok()?;",
        "let counter: u64 = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0);",
        ["a_proof_without_a_numeric_counter_is_not_a_proof"],
    ),
    "missing_signature_defaulted": (
        "a proof that stops after the counter gets a default signature",
        "        let signature = base64_decode(parts.next()?)?;",
        "        let signature = match parts.next() { Some(t) => base64_decode(t)?, None => vec![0u8; 64] };",
        ["a_two_segment_proof_is_not_a_proof"],
    ),
    "extra_segments_ignored": (
        "trailing segments after the signature are ignored",
        "        if parts.next().is_some() {\n            return None;\n        }",
        "        // MUTATION: trailing segments ignored",
        ["a_four_segment_proof_is_not_a_proof"],
    ),
    "empty_half_allowed": (
        "an empty key or signature is treated as a malformed proof rather than no proof",
        "        if key.is_empty() || signature.is_empty() {\n            return None;\n        }",
        "        // MUTATION: empty halves allowed",
        ["an_empty_half_is_no_proof_at_all"],
    ),
    "truncated_group_allowed": (
        "a base64 group of one character is decoded instead of refused",
        "    if text.len() % 4 == 1 {\n        return None;\n    }",
        "    // MUTATION: truncated group allowed",
        ["a_truncated_base64_group_is_refused"],
    ),
    "unknown_characters_skipped": (
        "characters outside the alphabet are skipped instead of refused",
        "        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;",
        "        let Some(found) = ALPHABET.iter().position(|c| *c == byte) else { continue };\n        let value = found as u32;",
        ["a_character_outside_the_alphabet_is_refused"],
    ),
    "encoder_pads": (
        "the encoder emits padded base64, a second spelling of the same proof",
        "        if chunk.len() > 1 {\n            out.push(ALPHABET[(packed >> 6) as usize & 63] as char);\n        }",
        "        if chunk.len() > 1 {\n            out.push(ALPHABET[(packed >> 6) as usize & 63] as char);\n        } else {\n            out.push('=');\n        }",
        ["base64_survives_every_tail_length"],
    ),
    "encoder_drops_counter": (
        "the encoder forgets the counter, so every proof on the wire is a replay of the first",
        "            base64_encode(&self.key),\n            self.counter,",
        "            base64_encode(&self.key),\n            0u64,",
        ["a_minted_proof_verifies_after_travel"],
    ),
}

TESTS = [
    "the_nonce_layout_is_pinned",
    "a_minted_proof_verifies_after_travel",
    "a_two_segment_proof_is_not_a_proof",
    "a_four_segment_proof_is_not_a_proof",
    "a_proof_without_a_numeric_counter_is_not_a_proof",
    "an_empty_half_is_no_proof_at_all",
    "base64_survives_every_tail_length",
    "a_truncated_base64_group_is_refused",
    "a_character_outside_the_alphabet_is_refused",
]


def run_tests() -> tuple[int, str]:
    # The whole lib, not a filter list. libtest takes at most one positional
    # filter, and a harness that passes nine of them is a harness that errors
    # out on every run for a reason that has nothing to do with the format.
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-ssh-agent", "--lib"],
        capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def failing_tests(output: str) -> set[str]:
    """Names of the pinned tests that reported a failure."""
    failed: set[str] = set()
    for line in output.splitlines():
        if line.startswith("test proof::tests::") and " ... FAILED" in line:
            failed.add(line.split("proof::tests::", 1)[1].split(" ", 1)[0])
    return failed


def apply_and_run(original: str, find: str, replace: str) -> tuple[int, str]:
    """Apply a mutation to a pristine copy and run the pinned tests on it.

    The pristine text is read once and never written back, so a mutation that
    fails to apply is reported rather than silently leaving the tree alone.
    """
    if find not in original:
        return 2, "MUTATION SITE NOT FOUND"
    mutated = original.replace(find, replace, 1)
    target = TARGET
    backup = target.read_text(encoding="utf-8")
    try:
        target.write_text(mutated, encoding="utf-8")
        return run_tests()
    finally:
        target.write_text(backup, encoding="utf-8")


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
        print("The spike drifted from its harness. Fix the harness or the format.")
        return 1

    code, output = run_tests()
    if code != 0:
        print("CONTROL IS RED — the unmutated format does not pass its own tests.")
        print(output[-3000:])
        return 1
    print(f"ok control: {len(TESTS)} pinned tests pass unmutated\n")

    failures: list[str] = []
    for key in sorted(MUTATIONS):
        description, find, replace, must = MUTATIONS[key]
        rc, out = apply_and_run(original, find, replace)
        if rc == 2:
            failures.append(f"{key}: mutation site vanished mid-run")
            print(f"XX {key}: {description}\n     site not found")
            continue
        if "error[" in out and "could not compile" in out:
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
