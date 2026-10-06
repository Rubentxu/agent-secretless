#!/usr/bin/env python3
"""Falsifying the curl family, in `crates/integrations/src/curl.rs`.

`r3b3_curl_discovery.rs` asserts nine properties of the curl adapter. Until this
harness existed they were nine rows that passed, which is the weakest thing a row
can be: a row nobody has tried to break measures nothing about whether it can
fail.

Four buckets, run one per invocation like every other harness here:

    python3 curl_falsify.py precedence  # which file curl would actually use
    python3 curl_falsify.py compound    # the two halves of user:password
    python3 curl_falsify.py separator   # where the option name stops
    python3 curl_falsify.py ceiling     # the file and line ceilings

**The precedence bucket exists because of a bug this family actually shipped.**
The first version listed the project `.curlrc` before the home files, on the
reasoning that every other family reads a project file and `Origin::Project` was
already there. That made the project file shadow the home file, and the report
told an operator their credential lived in the one curl never reads
automatically. Every vertical row passed while that was true, because each used
a project file *or* a home file. Putting the project candidate back at the front
is therefore the one mutation here whose symptom is a wrong answer rather than a
red row — which is what makes it worth having in a campaign.
"""

import sys
from pathlib import Path

import sts_falsify as f

CURL = f.REPO / "crates/integrations/src/curl.rs"

# The whole automatic-lookup block, in curl's order. The mutation below restores
# a project-first ordering inside it, which is the shape that was wrong.
LOOKUP_HEAD = """            // curl's second entry, at its default location. `$XDG_CONFIG_HOME`
            // when set is not resolvable here — see the module docs.
            Candidate {
                path: home.join(".config").join("curlrc"),
                origin: crate::Origin::User,
            },"""

# curl splits `user` on its **first** colon. Splitting on the last one turns the
# username into everything before the final colon, so a password containing a
# colon reports a user nobody has.
SPLIT = """    let (user, password) = match value.split_once(':') {"""
SPLIT_LAST = """    let (user, password) = match value.rsplit_once(':') {"""

# The separator skip. Without consuming the `=`, `user = "x"` keeps `= "x"` as
# its value and every length downstream measures a character not in the file.
SEPARATOR = """    let mut rest = body[end..].trim_start();
    if let Some(&c) = rest.as_bytes().first() {
        if c == b':' || c == b'=' {
            rest = rest[1..].trim_start();
        }
    }"""

# The byte ceiling, checked against metadata before the file is read.
SIZE_CEILING = """    if metadata.len() > MAX_CURLRC_BYTES {"""
SIZE_CEILING_OFF = """    if metadata.len() > u64::MAX {"""

# The line ceiling, counted as options are appended.
LINE_CEILING = """        if options.len() >= MAX_CURLRC_LINES {"""
LINE_CEILING_OFF = """        if options.len() >= usize::MAX {"""

PRECEDENCE = [
    (
        # The project `.curlrc` becomes the first thing the lookup considers, so
        # it wins over `~/.config/curlrc` and `~/.curlrc` — which is the wrong
        # answer, because curl reaches a project file only through an explicit
        # `--config` and never automatically.
        #
        # `the_home_file_wins_because_curl_never_reads_a_project_file_on_its_own`
        # is the row that sees it. Every other row in this file uses a project
        # file *or* a home file, so they all pass with the bug present, which is
        # why this mutation is in the campaign and not merely in the changelog.
        "let the project file win the automatic lookup",
        LOOKUP_HEAD,
        """            Candidate {
                path: cwd.join(".curlrc"),
                origin: crate::Origin::Project,
            },
""" + LOOKUP_HEAD,
        "the_home_file_wins_because_curl_never_reads_a_project_file_on_its_own",
    ),
    (
        # The other half of the same bug: the project candidate is dropped from
        # the lookup entirely, so a repository that ships a `.curlrc` and calls
        # `curl -K .curlrc` gets no report at all about it.
        "drop the project file from the report",
        """            Candidate {
                path: cwd.join(".curlrc"),
                origin: crate::Origin::Project,
            },
""",
        "",
        "a_project_file_alone_is_reported_and_labelled_not_auto_discovered",
    ),
]

COMPOUND = [
    (
        # A password containing a colon is legal. Splitting on the last colon
        # makes the reported user `alice:pass` — 10 bytes for a user called
        # `alice` — and the row that checks the two halves go red on the
        # username alone.
        "split user:password on the last colon instead of the first",
        SPLIT,
        SPLIT_LAST,
        "the_credential_splits_on_the_first_colon_not_the_last",
    ),
    (
        # Report the whole line's length as the password. The two questions an
        # operator has — who, and how long is the secret — collapse into one
        # number that answers neither.
        "report one length for the whole pair instead of two",
        """    CurlCredentialEntry {
        option: option.name,
        kind,
        user_len: user.len(),
        password_len: password.map_or(0, str::len),
        has_password: password.is_some(),
    }""",
        """    CurlCredentialEntry {
        option: option.name,
        kind,
        user_len: 0,
        password_len: value.len(),
        has_password: password.is_some(),
    }""",
        "a_user_with_no_colon_authenticates_with_an_empty_password",
    ),
    (
        # Treat `user` as an ordinary option, so a credential-bearing line lands
        # in the unmodelled bucket and the report says nothing about a secret.
        # The option is still named and still measured, which is exactly why
        # this mutation is worth carrying: "we found the line" and "we know
        # what it is" are different claims.
        "treat user as an ordinary option",
        """            "user" | "u" => Some(CurlCredential::User),""",
        """            "u-disabled" => Some(CurlCredential::User),""",
        "both_credential_options_are_named_and_nothing_else_is",
    ),
]

SEPARATOR = [
    (
        # `user = "x"` and `user "x"` become the same string `= "x"` and `"x"`,
        # and every length downstream is a measurement of a character the file
        # does not contain. This is the row the Gradle family found in its own
        # unescaper, reappearing in a different separator.
        "stop at the whitespace and leave the '=' in the value",
        SEPARATOR,
        """    let mut rest = body[end..].trim_start();""",
        "a_separator_and_whitespace_around_it_are_all_consumed",
    ),
    (
        # Accept `:` and `=` after a dashed option. curl does not, and the line
        # it accepts is one a reader would believe was read correctly.
        "accept ':' and '=' after a dashed option",
        """    if dashed && (name.contains(':') || name.contains('=')) {
        return Err(CurlParseError::DashedSeparator {
            name: name.to_string(),
        });
    }
""",
        "",
        "a_dashed_option_may_not_use_colon_or_equals_as_its_separator",
    ),
    (
        # curl's escape table drops the backslash before an unknown letter; a
        # shell keeps it. `C:\dir` comes back a byte short under the shell
        # reading, and the length in the report describes a path that does not
        # exist.
        "keep the backslash before a letter curl ignores",
        """            // "A backslash preceding any other letter is ignored."
            other => out.push(other),""",
        """            other => {
                out.push('\\\\');
                out.push(other);
            }""",
        "a_backslash_before_any_other_letter_is_dropped_and_the_letter_kept",
    ),
]

CEILING = [
    (
        # `u64::MAX` cannot be exceeded, so the ceiling is a line that always
        # evaluates false — the shape of a guard that reads as protection and
        # protects nothing.
        "raise the file ceiling above anything a filesystem can hold",
        SIZE_CEILING,
        SIZE_CEILING_OFF,
        "a_curlrc_past_the_size_ceiling_is_refused_rather_than_truncated",
    ),
    (
        # Same for the line ceiling. A `.curlrc` with a million option lines is
        # not refused, and the report is built by holding all of them.
        "raise the line ceiling above anything a file can hold",
        LINE_CEILING,
        LINE_CEILING_OFF,
        "a_curlrc_past_the_line_ceiling_is_refused_rather_than_partly_read",
    ),
]

# The two buckets that go through the product surface run the broker's
# integration target; the two parser buckets run the integrations crate's own
# library tests, because that is where the rows stating those rules live.
VERTICAL_PKG, VERTICAL_TGT = "asv-broker", "--test r3b3_curl_discovery"
LIB_PKG, LIB_TGT = "asv-integrations", "--lib"
LIB_PREFIX = "curl::tests::"

# **One target per bucket, because the rows live in two different places.**
# `precedence` and `ceiling` are properties of the adapter an operator reaches,
# so they are measured through the CLI. `compound` and `separator` are parser
# rules, and the rows that state them precisely live in the crate's own test
# module. Pointing a bucket at a target that does not contain its row produces
# `no-run`, which measures nothing — and a mutation that measures nothing is
# the one failure mode this framework exists to make loud.
BUCKETS = {
    "precedence": (VERTICAL_PKG, VERTICAL_TGT, "", PRECEDENCE),
    "ceiling": (VERTICAL_PKG, VERTICAL_TGT, "", CEILING),
    "compound": (LIB_PKG, LIB_TGT, LIB_PREFIX, COMPOUND),
    "separator": (LIB_PKG, LIB_TGT, LIB_PREFIX, SEPARATOR),
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "precedence"
    package, target, prefix, mutations = BUCKETS[mode]
    f.PACKAGE = package
    f.CARGO_TARGET = target
    # Integration-test row names are already fully qualified; the crate's own
    # unit rows live under the module path.
    f.TEST_PREFIX = prefix
    f.STS = CURL
    f.BUCKET_COUNT_LABEL = "four"
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {CURL.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    raise SystemExit(main())