#!/usr/bin/env python3
"""Falsification for the CLI's two secret-bearing buffers.

`asv add-credential` is the one command in the product that puts a credential on
the client's own heap, and this campaign is about the two buffers that hold it:

- what the operator typed, and
- the serialized request, which carries it because the protocol requires the
  secret on the wire.

The first version of both was careless. The read made two unzeroized copies
(`String::new()`, then `to_string()`, then the original shadowed), and the
serialized payload was a plain `Vec<u8>` handed back to the allocator. The
mutations below are the ways this comes back: reintroduce a copy, reintroduce a
plain buffer, and change the newline rule.

Two of them are **compiler refusals**, and that is the honest report rather than
a defect. The rows that name the property bind the result to
`zeroize::Zeroizing<Vec<u8>>` and `OpaqueSecret` explicitly, so returning a plain
`Vec<u8>` or a `String` does not compile. That is the strongest form the
property can take: the type system holds it, and a test cannot be written that
asserts it wrongly. A mutation that does not compile is not a break, and the
four-bucket accounting says so rather than counting it as a survivor.

Run:  python3 cli_buffers_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

MAIN = f.REPO / "crates/cli/src/main.rs"

MUTATIONS = [
    # --- the newline rule, which is the one with real behaviour ---------------
    (
        "strip every trailing newline rather than one",
        "    if secret.ends_with('\\n') {\n        secret.pop();\n    }",
        "    while secret.ends_with('\\n') {\n        secret.pop();\n    }",
        "only_one_trailing_newline_is_stripped",
    ),
    (
        "store the trailing newline with the credential",
        "    if secret.ends_with('\\n') {\n        secret.pop();\n    }",
        "",
        "a_trailing_newline_is_not_part_of_the_credential",
    ),
    (
        "trim both ends rather than the one byte a shell adds",
        "    if secret.ends_with('\\n') {\n        secret.pop();\n    }",
        "    let trimmed = secret.trim().to_string();\n    *secret = trimmed;",
        "a_leading_space_is_part_of_the_credential",
    ),
    # --- the copy that was there first ---------------------------------------
    # A recorded survivor, kept rather than deleted, and the reason it survives
    # is the point of the whole file.
    #
    # Replacing the `mem::take` with a `to_string()` produces the same bytes
    # through the same type, so every behavioural row stays green. The copy
    # count is invisible at runtime: the first version of this campaign had a
    # row that appeared to assert it, that row could not fail, and it was
    # replaced rather than kept. A copy here is a leak, not a wrong answer, and
    # a test that cannot see a leak is not evidence that there is none.
    #
    # The property is therefore held by the source having one `mem::take`
    # between stdin and `OpaqueSecret`, and it is a code-review property. It is
    # named here so that whoever next changes that line knows the campaign
    # cannot tell them they broke it, and did not try to make it look as if it
    # could.
    (
        "copy the credential instead of moving it",
        "    Ok(OpaqueSecret::new(std::mem::take(&mut *secret).into_bytes()))",
        "    let copy = secret.to_string();\n    Ok(OpaqueSecret::new(copy.into_bytes()))",
        "a_leading_space_is_part_of_the_credential",
    ),
    # --- the two that the type system holds ---------------------------------
    (
        "return the serialized request in a plain buffer",
        "fn encode(request: &Request) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {\n"
        "    Ok(zeroize::Zeroizing::new(\n"
        "        serde_json::to_vec(request).map_err(|e| std::io::Error::other(e.to_string()))?,\n"
        "    ))\n"
        "}",
        "fn encode(request: &Request) -> std::io::Result<Vec<u8>> {\n"
        "    serde_json::to_vec(request).map_err(|e| std::io::Error::other(e.to_string()))\n"
        "}",
        "the_serialized_request_lives_in_a_buffer_that_zeroizes",
    ),
    (
        "return the typed credential as a plain string",
        "fn read_credential(input: &mut impl std::io::Read) -> std::io::Result<OpaqueSecret> {\n"
        "    let mut secret = zeroize::Zeroizing::new(String::new());\n"
        "    std::io::Read::read_to_string(input, &mut secret)?;\n"
        "    if secret.ends_with('\\n') {\n"
        "        secret.pop();\n"
        "    }\n"
        "    Ok(OpaqueSecret::new(std::mem::take(&mut *secret).into_bytes()))\n"
        "}",
        "fn read_credential(input: &mut impl std::io::Read) -> std::io::Result<String> {\n"
        "    let mut secret = String::new();\n"
        "    std::io::Read::read_to_string(input, &mut secret)?;\n"
        "    if secret.ends_with('\\n') {\n"
        "        secret.pop();\n"
        "    }\n"
        "    Ok(std::mem::take(&mut secret))\n"
        "}",
        "the_typed_credential_is_read_into_a_buffer_that_zeroizes",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "tests::"
    f.CARGO_TARGET = "--bin asv"
    f.PACKAGE = "asv-cli"
    f.STS = MAIN
    f.MUTATIONS[:] = MUTATIONS
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
