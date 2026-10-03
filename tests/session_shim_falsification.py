#!/usr/bin/env python3
"""Falsification harness for the session shim.

`crates/cli/src/session_shim.rs` is the component that makes CONNECT usable by
an ordinary HTTP client. Every property it claims is one where a plausible
simplification looks like progress and is the opposite:

- Inject the proof by *appending* a header, which loses a race against a client
  that sent its own — and the broker reads the first one.
- Read the head with a `BufReader`, which buffers past `\\r\\n\\r\\n` and eats
  the first bytes of the TLS ClientHello.
- Answer a client with a reason for a refusal the broker issued, which makes
  the shim the policy engine it was built not to be.
- Skip minting when the request is not a well-formed CONNECT, which spends a
  counter on nothing and, worse, makes a malformed request look authorised.

The counter mutations are not here: `ProofIssuer` already owns the counter and
`tests/proof_issuer_falsification.py` falsifies it. This harness is about what
the shim does *around* the issuer.

Run with `--dry-run` to list mutations and their targets without building.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "cli" / "src" / "session_shim.rs"

MUTATIONS: dict[str, tuple[str, str, str, list[str]]] = {
    "proof_appended_not_replaced": (
        "the shim adds its proof beside the client's instead of replacing it",
        "        if name.trim().eq_ignore_ascii_case(SESSION_PROOF_HEADER) {\n            continue;\n        }",
        "        if false {\n            continue;\n        }",
        ["a_client_supplied_proof_is_replaced_not_appended"],
    ),
    "head_read_overreads": (
        "the head is read with buffering that may pass the terminator",
        "        out.push(byte[0]);\n        if out.len() >= 4 && out[out.len() - 4..] == *b\"\\r\\n\\r\\n\" {\n            return Ok(true);\n        }",
        "        out.push(byte[0]);\n        if out.len() >= 4 && out[out.len() - 4..] == *b\"\\r\\n\\r\\n\" {\n            let mut scratch = [0u8; 64];\n            let _ = stream.read(&mut scratch);\n            return Ok(true);\n        }",
        ["the_tunnel_carries_bytes_in_both_directions"],
    ),
    "refusal_explained_by_the_shim": (
        "the shim answers a silent upstream with a reason it does not have",
        'const NO_UPSTREAM_REPLY: &[u8] = b"HTTP/1.1 502 Bad Gateway\\r\\n\\r\\n";',
        'const NO_UPSTREAM_REPLY: &[u8] =\n    b"HTTP/1.1 502 Bad Gateway\\r\\nX-Asv-Reason: proof refused\\r\\n\\r\\n";',
        ["a_silent_upstream_becomes_a_bad_gateway"],
    ),
    "refusal_rewritten": (
        "the shim restates a broker refusal in its own words",
        "        client.write_all(&response)?;",
        '        client.write_all(if response.starts_with(ESTABLISHED) {\n            &response[..]\n        } else {\n            b"HTTP/1.1 403 Forbidden\\r\\n\\r\\n"\n        })?;',
        ["a_refusal_is_forwarded_verbatim"],
    ),
    "non_connect_minted_anyway": (
        "a request that is not a well-formed CONNECT still reaches the issuer",
        "    let target = match ConnectTarget::from_request_line(request_line) {\n        Ok(target) => target,\n        Err(_) => return Err(b\"HTTP/1.1 400 Bad Request\\r\\n\\r\\n\"),\n    };",
        "    let target = match ConnectTarget::from_request_line(request_line) {\n        Ok(target) => target,\n        Err(_) => asv_domain::ConnectTarget::from_request_line(\"CONNECT api.example.com:443 HTTP/1.1\")\n            .map_err(|_| NO_UPSTREAM_REPLY)?,\n    };",
        ["a_non_connect_request_is_refused_and_costs_no_counter"],
    ),
    "destination_dropped": (
        "the proof is minted for a fixed destination rather than the requested one",
        "    let proof = match issuer.issue(target.host(), target.port()) {",
        "    let _ = target;\n    let proof = match issuer.issue(\"api.example.com\", 443) {",
        # Only the two-destination test. The canonicalisation test asks for
        # `API.Example.COM:443`, which canonicalises to exactly the hardcoded
        # destination, so it is right that it stays green.
        ["a_proof_is_not_good_for_another_destination"],
    ),
    "no_proof_at_all": (
        "the shim forwards the CONNECT without minting anything",
        "    let proof = match issuer.issue(target.host(), target.port()) {\n        Ok(proof) => proof,",
        "    let proof = match Ok::<_, ()>(asv_ssh_agent::SessionProof {\n        key: Vec::new(),\n        signature: Vec::new(),\n        counter: 0,\n    }) {\n        Ok(proof) => proof,",
        ["the_injected_proof_verifies_for_the_requested_destination"],
    ),
    "tunnel_not_relayed": (
        "the shim answers 200 and then drops the tunnel instead of piping it",
        "        relay(&client, &upstream);",
        "        // MUTATION: tunnel dropped",
        ["the_tunnel_carries_bytes_in_both_directions"],
    ),
    "no_head_bound": (
        "a head larger than the bound is read anyway",
        "        if out.len() > MAX_HEAD {\n            return Err(io::Error::new(\n                io::ErrorKind::InvalidData,\n                \"head is larger than the shim will read\",\n            ));\n        }",
        "        // MUTATION: bound removed",
        ["an_oversized_head_is_refused_without_reaching_the_broker"],
    ),
}

TESTS = [
    "the_injected_proof_verifies_for_the_requested_destination",
    "a_proof_is_not_good_for_another_destination",
    "the_canonical_host_is_what_both_sides_derive",
    "a_client_supplied_proof_is_replaced_not_appended",
    "a_non_connect_request_is_refused_and_costs_no_counter",
    "a_silent_upstream_becomes_a_bad_gateway",
    "a_refusal_is_forwarded_verbatim",
    "the_tunnel_carries_bytes_in_both_directions",
    "an_unreachable_broker_is_a_bad_gateway",
    "a_second_connect_on_the_same_socket_gets_its_own_counter",
]


def run_tests() -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-cli", "--bin", "asv"],
        capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def failing_tests(output: str) -> set[str]:
    failed: set[str] = set()
    for line in output.splitlines():
        if line.startswith("test session_shim::") and " ... FAILED" in line:
            failed.add(line.split("session_shim::tests::", 1)[1].split(" ", 1)[0])
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
        print("CONTROL IS RED — the unmutated shim does not pass its own tests.")
        print(output[-3000:])
        return 1
    print(f"ok control: {len(TESTS)} shim tests pass unmutated\n")

    failures: list[str] = []
    for key in sorted(MUTATIONS):
        description, find, replace, must = MUTATIONS[key]
        try:
            TARGET.write_text(original.replace(find, replace, 1), encoding="utf-8")
            rc, out = run_tests()
        finally:
            TARGET.write_text(original, encoding="utf-8")
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
