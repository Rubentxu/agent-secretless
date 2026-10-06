#!/usr/bin/env python3
"""Falsifying the Gradle family, in `crates/integrations/src/gradle.rs`.

The npm and Maven families each arrived with a harness. This one does not
arrive without one, and two of its mutations are here for a specific reason:
they are **the two bugs the rows caught while this file was being written**, so
the campaign also proves those rows are capable of failing rather than merely
being the thing that found a defect once.

Four buckets, run one per invocation like every other harness here:

    python3 gradle_falsify.py leak          # what reaches the wire
    python3 gradle_falsify.py classify     # what counts as a credential
    python3 gradle_falsify.py reference    # the ${...} rule
    python3 gradle_falsify.py parser       # the two bugs the rows found

`parser` is the bucket worth reading first. Both of its mutations were once the
real implementation:

- the key and value were joined into one `key=value` string and split apart
  again, which ate any key containing an *escaped* separator: `a\\=b=value`
  came back as the key `a`;
- `push_unescaped` decoded `\\uXXXX` and its caller advanced two characters, so
  the four hex digits were read again as literals and `\\u00e9` measured six
  bytes instead of two.

A mutation that was once the code is the strongest kind, because the row that
catches it is demonstrably capable of catching the shape of defect it names.
"""

import sys
from pathlib import Path

import sts_falsify as f

GRADLE = f.REPO / "crates/integrations/src/gradle.rs"

# ---------------------------------------------------------------- what ships

# The report carries `len`, never `value`.
#
# **The obvious mutation does not compile**, which is worth recording rather
# than working around: writing the value where the length belongs is
# `E0308: mismatched types`, because `len` is `Option<usize>`. The type makes
# the single most likely leak unexpressible, so the attack has to go through a
# field that can hold a string. `env_reference` is the honest one to use: it is
# a field whose entire job is to carry text that came out of the file, which is
# exactly what makes it a good place to smuggle a value through.
LEN_FIELD = """                    len,
                    is_env_reference,
                    env_reference,"""

LEN_AS_VALUE = """                    len,
                    is_env_reference,
                    env_reference: Some(value.clone()),"""

# `describe_value` is where the `${...}` rule lives. Removing the special case
# makes an environment reference measure like a literal, which is the failure
# the row names: the number describes text standing in for a credential.
REFERENCE_RULE = """    if let Some(name) = trimmed
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {"""

REFERENCE_RULE_REMOVED = """    if let Some(name) = None::<&str>
        .and_then(|rest| rest.strip_suffix('}'))
    {"""

# ---------------------------------------------------------------- what counts

# Every entry an adapter treats as a credential. This is the mutation the whole
# family is built against: most of a `gradle.properties` is JVM flags, and an
# adapter that called each of them a credential would report four credentials
# on a file holding two settings.
# Every key an adapter treats as a credential. The mutation is on the function
# that *decides*, not on the `match` that consumes the decision: replacing the
# `Some(kind)` arm with `_` was compiler-refused, because it drops the `kind`
# binding. A malformed mutation measures nothing about the property it names,
# so the attack goes where the decision actually lives.
CREDENTIAL_FALLBACK = """        "systemProp.http.proxyPassword" => GradleCredential::ProxyPassword,
        _ => return None,
    })"""

CREDENTIAL_FALLBACK_EVERYTHING = """        "systemProp.http.proxyPassword" => GradleCredential::ProxyPassword,
        _ => GradleCredential::RepositoryStorePassword,
    })"""

# ----------------------------------------------------------------- the parser

# The round-trip that ate escaped separators in a key.
PARSER_PUSH = """        let key = pending_key
            .take()
            .expect("the key is set on every path that reaches here");
        pairs.push((key, std::mem::take(&mut pending_value)));"""

PARSER_PUSH_ROUNDTRIP = """        let key = pending_key
            .take()
            .expect("the key is set on every path that reaches here");
        let joined = format!("{key}={}", std::mem::take(&mut pending_value));
        let (key, value) = joined.split_once('=').expect("joined around an '='");
        pairs.push((key.to_string(), value.to_string()));"""

# The consumer that advanced two characters past a six-character escape.
VALUE_ADVANCE = """                Some(next) => {
                    rest += push_unescaped(&mut value, *next, &bytes, rest);
                }"""

VALUE_ADVANCE_TWO = """                Some(next) => {
                    push_unescaped(&mut value, *next, &bytes, rest);
                    rest += 2;
                }"""

BUCKETS = {
    "leak": [
        (
            # The titular one. A `len` that became a `value` compiles everywhere
            # and leaks everywhere, which is why the row asserts over the
            # serialised JSON rather than over the struct: a field added
            # tomorrow is caught there and not by a shape assertion written
            # today.
            "report the credential's value instead of its length",
            LEN_FIELD,
            LEN_AS_VALUE,
            "the_serialised_report_contains_no_credential",
        ),
    ],
    "classify": [
        (
            # Every key becomes a credential. The JVM-flag row is the one that
            # sees it, because that row is about what this adapter *refuses* to
            # claim, and refusing is only a property while something could
            # claim it.
            "call every property a credential",
            CREDENTIAL_FALLBACK,
            CREDENTIAL_FALLBACK_EVERYTHING,
            "a_jvm_flag_is_named_and_measured_rather_than_called_a_credential",
        ),
    ],
    "reference": [
        (
            # The `${...}` rule removed. An environment reference then measures
            # like a literal, and the row catches it because the length reported
            # becomes the 44 characters standing in for a credential.
            "measure an environment reference like a literal",
            REFERENCE_RULE,
            REFERENCE_RULE_REMOVED,
            "a_dollar_reference_is_named_never_resolved_and_never_measured",
        ),
    ],
    "parser": [
        (
            # **The bug this file shipped with.** Key and value were joined and
            # split apart again, and an escaped separator inside a key survived
            # the join and was mistaken for the real one.
            "join the key and value and split them apart again",
            PARSER_PUSH,
            PARSER_PUSH_ROUNDTRIP,
            "an_escaped_separator_does_not_end_the_key",
        ),
        (
            # **The other bug this file shipped with.** `\\uXXXX` consumes six
            # source characters, not two, and the four hex digits were read
            # again as literals — so the reported length described a string the
            # file does not contain.
            "advance two characters past a six-character escape",
            VALUE_ADVANCE,
            VALUE_ADVANCE_TWO,
            "a_unicode_escape_is_decoded_rather_than_left_as_seven_characters",
        ),
    ],
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "leak"
    f.PACKAGE = "asv-integrations"
    f.CARGO_TARGET = "--lib"
    f.TEST_PREFIX = "gradle::tests::"
    f.STS = GRADLE
    f.BUCKET_COUNT_LABEL = "four"
    mutations = BUCKETS[mode]
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    raise SystemExit(main())