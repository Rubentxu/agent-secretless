#!/usr/bin/env python3
"""Falsification for the npm discovery adapter (R3.A.1).

`discover` exists to describe a tool's configuration **without reading its
secrets**, so the campaign is ordered by which claim a mutation would break:

* **leak** -- a secret reaching the report. This is the property the crate
  exists for, and it is the one that has to be measured against the *serialised*
  report, because a struct-shape assertion only describes today's fields.
* **parse** -- the safe-parser properties: no interpolation, no `include`, no
  last-`=`, no dropped line. Each of these is a way a report ends up
  describing something the file does not say.
* **fingerprint** -- the refusals, and one deliberate non-refusal: a
  world-readable file is *reported*, because refusing it would refuse almost
  every real `.npmrc` npm itself writes at 0644.
* **audience** -- `RegistryAudience`, which exists because `Authority` refuses
  a port and `localhost:4873` is Verdaccio's default.

Run:  python3 npm_discover_falsify.py leak
      python3 npm_discover_falsify.py parse
      python3 npm_discover_falsify.py fingerprint
      python3 npm_discover_falsify.py audience
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

NPM = f.REPO / "crates/integrations/src/npm.rs"
FINGERPRINT = f.REPO / "crates/integrations/src/fingerprint.rs"
AUDIENCE = f.REPO / "crates/integrations/src/registry_audience.rs"

# What a secret reaching the report looks like from the outside. Every mutation
# here is judged by a substring search in the JSON a caller would receive.
LEAK = [
    (
        # **The mutation the whole crate is built to survive.** Add a field
        # carrying the value, which is what a future feature ("show the operator
        # a masked prefix") invites. Nothing about the type system stops it; the
        # row does, and only because the row reads the *output*.
        #
        # Two substitutions, because the field has to be added to the struct as
        # well as filled in at the construction site. The first version supplied
        # only the second, and the harness reported `compiler-refused` — which
        # is a stronger answer than green and a much weaker one than red: a
        # compile error says the mutation was malformed, not that the report
        # would have leaked. A mutation that cannot compile has measured
        # nothing about the property it was written to attack.
        "carry the auth value in the selector",
        # `old` is unused when `new` is a list of pairs, which is how the base
        # harness expresses a multi-site mutation.
        "",
        [
            (
                "    pub value_len: usize,",
                "    pub value_len: usize,\n    pub value: String,",
            ),
            (
                "                value_len: value.len(),\n                value_is_env_reference: env_reference(value).is_some(),",
                "                value_len: value.len(),\n                value: value.to_string(),\n                value_is_env_reference: env_reference(value).is_some(),",
            ),
        ],
        "the_serialised_report_contains_no_credential",
    ),
    (
        # The `Debug` path is a different code path from `Serialize`, and a
        # report that is safe in JSON routinely is not in a log line. Two
        # substitutions again, for the same reason as the mutation above.
        "carry the auth value in the parse result",
        "",
        [
            (
                "    pub value_len: usize,",
                "    pub value_len: usize,\n    pub raw_value: String,",
            ),
            (
                "                value_len: value.len(),",
                "                value_len: value.len(),\n                raw_value: value.to_string(),",
            ),
        ],
        "the_debug_rendering_contains_no_credential_either",
    ),
    (
        # "Read the environment so the report can say whether the variable is
        # set" is a small, friendly-sounding change and it puts the caller's
        # environment into a document that travels to a terminal, a log and an
        # agent. The length assertion is what catches it.
        "resolve an environment reference instead of naming it",
        '''                value_len: value.len(),
                value_is_env_reference: env_reference(value).is_some(),
                env_reference: env_reference(value),
            }),''',
        '''                value_len: env_reference(value)
                    .and_then(|name| std::env::var(name).ok())
                    .map_or_else(|| value.len(), |resolved| resolved.len()),
                value_is_env_reference: env_reference(value).is_some(),
                env_reference: env_reference(value),
            }),''',
        "an_env_reference_is_reported_by_name_and_never_read",
    ),
    (
        # An opaque setting is the other place a value could sit, and this is the
        # only path a value actually travels on for a key the parser does not
        # model. The first version of this mutation put the literal on the *auth
        # selector*, which no setting ever reaches, so it would have survived a
        # run looking like coverage; the second pointed it at a row whose
        # fixture is an `//`-prefixed key, which returns before this branch and
        # also survived. An unrecognised *auth field* is `AuthField::Unrecognised`
        # and never becomes a `SettingValue` -- two rows ending in the same word,
        # neither measuring the other.
        "print an unmodelled setting verbatim",
        '''    out.settings
        .insert(key.to_string(), SettingValue::Opaque { len: value.len() });''',
        '''    out.settings
        .insert(key.to_string(), SettingValue::Literal(value.to_string()));''',
        "an_unmodelled_setting_is_reported_by_length_and_never_by_value",
    ),
]

# The safe-parser properties. Each is a way the report ends up describing
# something the file does not say, which is the failure mode a security report
# cannot have.
PARSE = [
    (
        # Following an `include` would describe a file the operator did not
        # name, and `plan` cannot revalidate what `discover` never read.
        #
        # The replacement is a dead branch rather than a deletion. The first
        # version removed the two lines, which moved `key` and `value` and left
        # E0382 for every later use of them -- a compile error says the mutation
        # was malformed, and a malformed mutation measures nothing about the
        # property it was written to attack. An `if false` still type-checks,
        # still borrows, and does not run.
        "follow an include directive",
        '''        if key == "include" || key.starts_with("include:") {
            return Err(ParseError::IncludeRefused {
                at_line: line_number,
            });
        }''',
        '''        if false {
            return Err(ParseError::IncludeRefused {
                at_line: line_number,
            });
        }''',
        "an_include_directive_refuses_the_whole_file",
    ),
    (
        # npm splits on the *first* `=`, so a registry URL with a query string
        # is ordinary. Splitting on the last one rewrites the audience.
        "split a key from its value on the last equals sign",
        "        let Some((key, value)) = trimmed.split_once('=') else {",
        "        let Some((key, value)) = trimmed.rsplit_once('=') else {",
        "a_value_containing_equals_is_kept_whole",
    ),
    (
        # The field is read after the **last** colon, because a local registry
        # on a port has one of its own. First-colon reads the port as the field
        # name and reports a credential npm would never send.
        "read the auth field after the first colon",
        "    let (_, suffix) = key.rsplit_once(':')?;",
        "    let (_, suffix) = key.split_once(':')?;",
        "a_local_registry_on_a_port_keeps_its_port",
    ),
    (
        # A line this parser cannot read means the file's meaning is not known,
        # and reporting the lines that did parse would be a report that reads
        # complete.
        "skip a line that is not a key=value pair",
        '''        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(ParseError::NotAKeyValue {
                at_line: line_number,
            });
        };''',
        '''        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };''',
        "a_line_that_is_not_a_key_value_refuses_the_file",
    ),
    (
        # A megabyte of key is a way to put a megabyte into a terminal.
        "stop bounding the length of a key",
        "        if key.len() > MAX_KEY_BYTES {",
        "        if false {",
        "an_absurdly_long_key_is_refused_rather_than_reported",
    ),
    (
        # Dropping an unrecognised key leaves an operator believing no
        # credential is configured, when the truth is that one is and it is
        # misspelled. Aimed, like the mutation above, at the branch that
        # actually records it -- the first version aimed it at the auth-field
        # row, whose fixture never reaches this code.
        "drop a key this parser does not model",
        '''    out.settings
        .insert(key.to_string(), SettingValue::Opaque { len: value.len() });''',
        "    let _ = value;",
        "an_unmodelled_setting_is_reported_by_length_and_never_by_value",
    ),
    (
        # The other half of the same idea, on the `//` branch: a misspelled
        # auth field reported as a *known* one is worse than dropping it,
        # because the report would name a credential npm never sends. Before
        # this mutation the row had none of its own, which meant a whole path
        # through `auth_field` was unmeasured.
        "report an unrecognised auth field as a known one",
        "        other => AuthField::Unrecognised(other.to_string()),",
        "        other => AuthField::Email,",
        "an_unrecognised_auth_field_is_reported_rather_than_dropped",
    ),
    (
        # The section header is a *slice*, not two independent strips. The first
        # version invented a section called `[scope`, and every key in it came
        # out as `[scope:key` in a report nobody had reason to doubt.
        "strip only the closing bracket of a section header",
        '''            let Some(inner) = trimmed
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            else {
                return Err(ParseError::NotAKeyValue {
                    at_line: line_number,
                });
            };''',
        '''            let Some(inner) = trimmed.strip_suffix(']') else {
                return Err(ParseError::NotAKeyValue {
                    at_line: line_number,
                });
            };''',
        "comments_blank_lines_and_sections_are_handled",
    ),
]

# The refusals, and the one deliberate non-refusal.
FINGERPRINT_MUTATIONS = [
    (
        # Readability is reported, not refused. npm writes these files at 0644
        # and refusing them would make discovery fail on almost every real
        # machine — a tool that cannot see the file it exists to fix.
        "refuse a world-readable file too",
        "const UNTRUSTED_WRITE_BITS: u32 = 0o022;",
        "const UNTRUSTED_WRITE_BITS: u32 = 0o077;",
        "a_world_readable_file_is_reported_and_not_refused",
    ),
    (
        # Writability is refused, because a file somebody else can edit makes
        # every dimension of the fingerprint true about bytes the operator did
        # not choose.
        "accept a group-writable file",
        "        if mode & UNTRUSTED_WRITE_BITS != 0 {",
        "        if mode & UNTRUSTED_WRITE_BITS == 0 {",
        "a_group_writable_file_is_refused_rather_than_reported",
    ),
    (
        # The digest is what catches "same length, different bytes". A cache of
        # size alone would let a swapped registry pass revalidation.
        "fingerprint the size instead of the contents",
        "            digest,",
        '''            digest: format!("sha256:{:x}", meta.size()),''',
        "the_digest_covers_the_bytes_and_nothing_else",
    ),
    (
        # Following the link before checking it would make the check
        # unreachable, because by then the link is a regular file with a
        # regular file's inode.
        "do not check whether the path is a symlink",
        "        if link_meta.file_type().is_symlink() {",
        "        if false && link_meta.file_type().is_symlink() {",
        "a_symlink_is_refused_by_default_and_allowed_only_named_roots",
    ),
    (
        # A string prefix would hand out `/home/u/.config-backup` to an
        # allowance meant for `/home/u/.config`, which is the whole reason the
        # comparison is component-wise.
        "compare a symlink allowance by string prefix",
        '''            target.len() > root.len()
                && target
                    .iter()
                    .zip(root.iter())
                    .all(|(inside, boundary)| inside == boundary)''',
        '''            let inside = target_path.to_string_lossy();
            let boundary = root_path.to_string_lossy();
            inside.starts_with(boundary.as_ref())''',
        "a_symlink_allowance_is_not_a_string_prefix",
    ),
    (
        # The inode is what says "replaced" rather than "edited". Two files
        # with identical bytes have identical digests, so without it a file
        # swapped for an identical copy passes every comparison.
        "stop carrying the inode",
        "            inode: meta.ino(),",
        "            inode: 0,",
        "a_replacement_is_caught_by_the_inode_and_not_only_the_digest",
    ),
]

# The registry audience, which exists because `Authority` refuses a port.
AUDIENCE_MUTATIONS = [
    (
        # Two spellings of one endpoint have to be one endpoint, or a binding
        # made against one spelling would not cover the other.
        "stop folding the case of a host",
        "        labels.push(label.to_ascii_lowercase());",
        "        labels.push(label.to_string());",
        "case_is_folded_and_the_port_is_kept",
    ),
    (
        # `u16` accepts zero; an endpoint does not, and a report naming
        # `host:0` names an endpoint that does not exist.
        "accept port zero",
        '''    if port == 0 {
        return Err(RegistryAudienceError::PortOutOfRange { raw: raw.into() });
    }''',
        "",
        "a_port_outside_the_valid_range_is_refused",
    ),
    (
        # `::1` could be a host and a port, and reading it either way sends a
        # credential to a service the operator did not name.
        "guess at an unbracketed IPv6 literal",
        '''    if colons > 1 {
        return Err(RegistryAudienceError::AmbiguousIpv6 { raw: raw.into() });
    }''',
        "",
        "an_unbracketed_ipv6_literal_is_refused_rather_than_guessed",
    ),
    (
        # The row that justifies the whole type. If it stops being an audience
        # the adapter goes back to refusing the most common private registry npm
        # has.
        "refuse a registry on a port",
        '''    let (host, port) = split_host_and_port(raw)?;''',
        '''    let (host, port) = split_host_and_port(raw)?;
    if port.is_some() {
        return Err(RegistryAudienceError::PortOutOfRange { raw: raw.into() });
    }''',
        "a_local_registry_on_a_port_is_an_audience_not_a_refusal",
    ),
    (
        # A host that resolves nowhere is a worse thing to name in a report than
        # to refuse.
        "accept a name with an empty label",
        '''        if label.is_empty() {
            return Err(RegistryAudienceError::EmptyLabel { host: raw.into() });
        }''',
        "",
        "an_empty_label_is_refused",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "leak"
    f.PACKAGE = "asv-integrations"
    f.CARGO_TARGET = "--lib"
    f.STS = NPM
    mutations = LEAK
    if mode == "parse":
        mutations = PARSE
    elif mode == "fingerprint":
        f.STS = FINGERPRINT
        mutations = FINGERPRINT_MUTATIONS
    elif mode == "audience":
        f.STS = AUDIENCE
        mutations = AUDIENCE_MUTATIONS
    # `run_test` passes `--exact`, which matches the **full** test path, so the
    # module prefix is part of the name and not a decoration. The first version
    # of this harness left it empty, cargo matched nothing, and all four
    # mutations came back `no-run` — which is the harness correctly reporting
    # that it had measured nothing, and a reminder that the empty result of a
    # filter is a claim about the filter, not about the property.
    f.TEST_PREFIX = {
        "fingerprint": "fingerprint::tests::",
        "audience": "registry_audience::tests::",
    }.get(mode, "npm::tests::")
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
