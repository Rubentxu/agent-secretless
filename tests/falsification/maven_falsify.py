#!/usr/bin/env python3
"""Falsification for the Maven family (R3.B.1).

The second family, and the one that had to earn R3's exit criterion rather than
assert it. `maven.rs` groups its mutations by what a mistake here costs:

* **leak** -- something the file wrote reaches a report, a log line or a refusal
  an operator pastes into an issue. Two of the three mutations in this bucket are
  aimed at places no `grep` for `<password>` would look.
* **parser** -- §5's four requirements. This is where the family is genuinely
  different from npm, so it is where most of the work is.
* **claim** -- the report asserting something the file did not say. A report that
  invents is worse than one that is silent, because it is believed.
* **policy** -- what `discover` does about a file it will not read.

**Two rows here have no mutation, and saying so is part of the result.**

`the_maven_report_reaches_the_envelope_the_cli_prints` is structural by
construction: the mutation that would break it is deleting a variant from
`AnyReport`, which does not compile. That is the property working, not a gap in
the campaign -- but it is also why R3.A.2 could report forty green tests for a
module nobody compiled, and the row exists to make that state unreachable.

`the_schema_location_is_parsed_as_text_and_never_fetched` cannot be attacked
from here either: `roxmltree` declares no dependencies and is
`#![forbid(unsafe_code)]`, so there is no code in this crate that *could* fetch
anything. The row is a regression guard against a future "helpful" resolver, and
the mutation that would make it red is adding one -- not breaking one.

Run:  python3 maven_falsify.py leak
      python3 maven_falsify.py parser
      python3 maven_falsify.py claim
      python3 maven_falsify.py policy
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

MAVEN = f.REPO / "crates/integrations/src/maven.rs"

LEAK = [
    (
        # A `<mirror><url>` is the credential vector no one greps for.
        # `https://token@github.com/acme/repo` is a documented, supported Maven
        # form. The report is the artefact in R3 that travels furthest before
        # anything is written, so a URL printed verbatim puts a credential in
        # front of an agent.
        "print a mirror url with its userinfo intact",
        """                let (url, url_credential_len) = match child_text(mirror, "url") {
                    Some(url) => {
                        let (stripped, len) = strip_userinfo(&url);
                        (Some(stripped), len)
                    }
                    None => (None, None),
                };""",
        """                let (url, url_credential_len) = match child_text(mirror, "url") {
                    Some(url) => (Some(url), Some(0)),
                    None => (None, None),
                };""",
        "a_mirror_url_with_embedded_credentials_is_reported_without_them",
    ),
    (
        # Same vector, entered from the other end: the split point rather than
        # the call. Removing the redaction at the call site could be undone by
        # someone who trusted it; removing the split leaves nothing to trust.
        # `rfind` rather than `find` is what makes `user:p@ss@host` one
        # credential instead of a mangled URL.
        "split a url on an at-sign anywhere in the string, not just in the authority",
        """    let Some(at) = authority.rfind('@') else {
        return (url.to_string(), None);
    };""",
        """    let Some(at) = url.rfind('@') else {
        return (url.to_string(), None);
    };
    let authority = &url[..at + 1];
    let authority_end = authority.len();""",
        "an_at_sign_outside_the_authority_is_not_treated_as_a_credential",
    ),
    (
        # `roxmltree`'s `Display for Error` prints `row:col` and the *name* of
        # whatever it choked on -- never the surrounding text, which is why this
        # mutation has to go through `other.to_string()` reaching a message at
        # all. Reaching for the document to be helpful is the natural next edit
        # and it is exactly the one this row exists to refuse.
        #
        # This one is a **close call rather than a certainty**: an entity name is
        # XML `Name` syntax, so it cannot hold most punctuation, but it is
        # attacker-controlled and unbounded up to `MAX_SETTINGS_BYTES`. So the
        # honest statement is that this row measures the ordinary path, and the
        # bounded-but-named case is a deliberate trade documented on the error.
        "quote the document text in a refusal",
        """            other => MavenError::Malformed {
                message: other.to_string(),
            },""",
        """            other => MavenError::Malformed {
                message: format!("{other} near `{}`", &text[..text.len().min(80)]),
            },""",
        "a_refusal_message_carries_no_value",
    ),
    (
        # The titular row. A `password_len` that became a `password` compiles
        # everywhere and leaks everywhere, which is why the assertion is made
        # against the serialised JSON: a field added tomorrow is caught here and
        # not by a struct-shape assertion written today.
        "measure the placeholder text as if it were the credential",
        """fn credential_len(value: Option<&str>, is_env_reference: bool) -> Option<usize> {
    if is_env_reference {
        None
    } else {
        value.map(|value| value.len())
    }
}""",
        """fn credential_len(value: Option<&str>, is_env_reference: bool) -> Option<usize> {
    if is_env_reference && value.is_none() {
        None
    } else {
        value.map(|value| value.len())
    }
}""",
        "an_env_reference_is_named_never_resolved_and_never_measured",
    ),
]

PARSER = [
    (
        # §5's first requirement, and the one that is structural rather than
        # merely configured. `roxmltree`'s default is already `false`, so this
        # mutation is the one that catches someone "simplifying" it back to the
        # default on the grounds that it was the same either way.
        "accept a DTD",
        """        allow_dtd: false,
        nodes_limit: MAX_NODES,""",
        """        allow_dtd: true,
        nodes_limit: MAX_NODES,""",
        "a_document_with_a_dtd_is_refused_before_its_contents_are_read",
    ),
    (
        # §5's second requirement. With the DTD accepted, a `SYSTEM
        # "file:///etc/passwd"` entity becomes reachable -- and the row also
        # proves the refusal is *named* rather than reported as "not
        # well-formed", because an operator reading the latter would not know a
        # document type declaration was attempted at all.
        "report an undeclared entity as an ordinary syntax error",
        """            E::UnknownEntityReference(name, _) => MavenError::DtdRefused {""",
        """            E::UnknownEntityReference(_, _) => MavenError::Malformed {
                message: "malformed entity reference".to_string(),
            },
            #[allow(unreachable_patterns)]
            E::UnknownEntityReference(name, _) => MavenError::DtdRefused {""",
        "an_undeclared_entity_reference_is_refused_and_named",
    ),
    (
        # **The mutation that was a lie for a whole block of work.**
        #
        # The first version of this file documented `MAX_NODES` as "the ceiling
        # on nesting", reasoning that `nodes_limit` bounds the nodes and a node
        # is appended per element. The row aimed at removing the depth check then
        # aborted the process: `roxmltree` appends an element's node when it
        # reaches the element's *closing* tag (`parse.rs:781`, in the `Close`
        # arm), so the recursion has already gone as deep as the document nests
        # before a single node exists to count. 2049 levels exhausted a 2 MiB
        # stack and `nodes_limit` was never consulted.
        #
        # So the ceiling this module needs is its own, checked on the text, and
        # this mutation is the one that proves it is load-bearing.
        "stop checking depth before parsing",
        """    check_depth(text)?;""",
        "",
        "a_document_past_the_depth_ceiling_is_refused_before_the_parser_sees_it",
    ),
    (
        # And the other ceiling, which is what `nodes_limit` genuinely is. The
        # two rows exist as a pair because either one alone passes trivially: a
        # depth check that refuses everything passes the first, and a node check
        # that refuses everything passes the second.
        "stop bounding the total node count",
        """        nodes_limit: MAX_NODES,""",
        """        nodes_limit: u32::MAX,""",
        "a_document_past_the_node_ceiling_is_refused",
    ),
    (
        # The scanner is quote-aware because `<a b="x>y">` has a `>` that does
        # not end the tag, and a scanner that believes it does **fails open**:
        # it reads an opening tag, then a stray `y">`, and every count after that
        # point is desynchronised. The row is built so the document is 70 real
        # levels deep, which is over the ceiling; a naive scanner reads it as
        # depth 1 and parses successfully.
        # A **raw** string, and the reason is worth recording: the function's
        # body contains `b'\''`, a character literal for a single quote. In an
        # ordinary triple-quoted Python string `\'` collapses to `'`, the
        # snippet becomes `b''`, and the harness reports `snippet not unique` —
        # which reads as "the mutation did not bite" and is actually "the
        # mutation was never written". Those are the same-looking mistake with
        # opposite meanings, and only one of them is a finding.
        "skip a tag without respecting quoted attribute values",
        r"""fn skip_tag(bytes: &[u8], mut index: usize) -> Result<usize, MavenError> {
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match (quote, byte) {
            (Some(open), b) if b == open => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(byte),
            (None, b'>') => return Ok(index + 1),
            _ => {}
        }
        index += 1;
    }
    Err(MavenError::Malformed {
        message: "a tag is never closed".to_string(),
    })
}""",
        r"""fn skip_tag(bytes: &[u8], mut index: usize) -> Result<usize, MavenError> {
    while index < bytes.len() {
        if bytes[index] == b'>' {
            return Ok(index + 1);
        }
        index += 1;
    }
    Err(MavenError::Malformed {
        message: "a tag is never closed".to_string(),
    })
}""",
        "a_gt_inside_an_attribute_value_does_not_end_the_tag",
    ),
    (
        # Comments and CDATA are skipped whole rather than scanned, because a
        # `<` inside one opens nothing -- and `settings.xml` files routinely
        # carry commented-out profile blocks eight levels deep. Scanning them is
        # the version that refuses a legitimate file, which is a refusal an
        # operator cannot act on.
        "scan the contents of a comment instead of skipping it",
        """        if rest.starts_with(b"<!--") {
            index = skip_past(bytes, index + 4, b"-->")?;
        } else if rest.starts_with(b"<![CDATA[") {""",
        """        if rest.starts_with(b"<!--") {
            index += 4;
        } else if rest.starts_with(b"<![CDATA[") {""",
        "markup_inside_a_comment_or_cdata_does_not_count_towards_the_depth",
    ),
    (
        # §5's size limit. `metadata` first and a bounded read: a plain
        # `read_to_string` has already allocated whatever the file is, which is
        # the opposite of what a size limit is for.
        "drop the byte ceiling",
        """    if len > MAX_SETTINGS_BYTES {
        return Err(MavenError::TooLarge {
            path: path.to_path_buf(),
        });
    }""",
        "",
        "a_file_over_the_ceiling_is_refused_without_being_read",
    ),
    (
        # Local name, not namespace. A `settings.xml` normally carries
        # `xmlns="http://maven.apache.org/SETTINGS/1.0.0"` and sometimes does not,
        # and matching only the namespaced form finds *nothing* in the second
        # case -- which reads exactly like "you have no credentials", the one
        # ambiguity a credential report cannot have.
        "require a namespace to match a server element",
        """        .filter(move |node| node.is_element() && node.has_tag_name(name))""",
        """        .filter(move |node| {
            node.is_element()
                && node.tag_name().namespace().is_some()
                && node.tag_name().name() == name
        })""",
        "a_document_without_the_namespace_still_parses",
    ),
]

CLAIM = [
    (
        # `None` means "the file said nothing"; `Some(0)` means "the file said
        # zero". Only the first is true, and an operator reading the second
        # would go looking for an empty password that is not there.
        # The snippet runs to `undescribed:` because `password_len` appears twice --
        # once here and once in `proxy_from`, with the same three lines around
        # it. `snippet not unique` is the harness saying "this mutation was
        # never aimed at anything", which looks like a survivor in the summary
        # and is not one.
        "turn an absent password into a zero-length one",
        """        username_len: child_text(node, "username").map(|value| value.len()),
        password_len: credential_len(password.as_deref(), is_env),
        password_is_env_reference: is_env,
        env_reference: reference,
        undescribed: node""",
        """        username_len: child_text(node, "username").map(|value| value.len()),
        password_len: Some(credential_len(password.as_deref(), is_env).unwrap_or(0)),
        password_is_env_reference: is_env,
        env_reference: reference,
        undescribed: node""",
        "a_server_with_no_password_reports_none_rather_than_zero",
    ),
    (
        # Same mistake on a field where the wrong default is a *live* proxy: an
        # operator told a proxy is in use will act on a credential path Maven is
        # not going to take.
        "default an unstated proxy to active",
        """            .unwrap_or(false),""",
        """            .unwrap_or(true),""",
        "a_proxy_without_an_active_element_is_inactive_rather_than_active",
    ),
    (
        # `70000` is not a port and `0` is a *different wrong* claim rather than
        # an absent one. This is the same shape as the password row above, in a
        # field where the wrong value looks plausible enough to be acted on.
        "turn an unparseable port into zero",
        """        port: child_text(node, "port").and_then(|value| value.parse::<u16>().ok()),""",
        """        port: Some(
            child_text(node, "port")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0),
        ),""",
        "a_port_that_is_not_a_port_is_absent_rather_than_zero",
    ),
    (
        # **The row the second family forced.**
        #
        # `<server><configuration>` is where Artifactory and Nexus keep an API
        # key. An adapter that modelled only `<username>`/`<password>` reports one
        # credential and silently omits the second, and a report that says "here
        # is the credential" while another is invisible is worse than one that
        # says nothing. Dropping the collection is what an adapter written to the
        # obvious shape does.
        "stop reporting the elements the adapter does not model",
        """                child.is_element()
                    && !MODELLED_SERVER_CHILDREN.contains(&child.tag_name().name())""",
        """                false""",
        "an_artifactory_key_under_configuration_is_named_and_not_read",
    ),
    (
        # And measured across the subtree rather than on direct text.
        # `Node::text()` returns `None` unless there is exactly one text child,
        # and a `<configuration>` holding one `<property>` has none of its own --
        # so this version reports 0 bytes and looks like it found nothing. A
        # ceiling that measures zero finds zero, and that is how a real key gets
        # described as absent.
        "measure only an element's direct text",
        """fn text_length(node: roxmltree::Node<'_, '_>) -> usize {
    node.descendants()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .map(|text| text.trim().len())
        .sum()
}""",
        """fn text_length(node: roxmltree::Node<'_, '_>) -> usize {
    node.text().unwrap_or_default().trim().len()
}""",
        "an_artifactory_key_under_configuration_is_named_and_not_read",
    ),
    (
        # `${env.X}` is named and never resolved, and this row also pins the
        # property a resolver here would have to break: the test process's own
        # variables are visible to it, so a resolver that *worked* would find
        # the one the row sets.
        "resolve an env reference to measure it",
        """fn env_reference(value: Option<&str>) -> (bool, Option<String>) {
    let Some(value) = value else {
        return (false, None);
    };""",
        """fn env_reference(value: Option<&str>) -> (bool, Option<String>) {
    let Some(value) = value else {
        return (false, None);
    };
    if let Some(inner) = value
        .strip_prefix("${env.")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    {
        if let Ok(resolved) = std::env::var(inner) {
            return (true, Some(resolved));
        }
    }""",
        "the_environment_is_never_read_to_resolve_a_reference",
    ),
]

POLICY = [
    (
        # Refuse the *file*, keep the report. A world-writable `settings.xml` is
        # refused by the fingerprint, and the question this answers is what
        # happens to the rest of the run — the answer is a finding, and nothing
        # about the file is claimed.
        "describe a file the fingerprint refused",
        """                    findings.push(Finding {
                        severity: crate::Severity::Refused,
                        subject: candidate.path.display().to_string(),
                        message: error.to_string(),
                    });
                    continue;""",
        """                    files.push(MavenFile {
                        origin: candidate.origin,
                        fingerprint: crate::fingerprint::FileFingerprint {
                            path: candidate.path.clone(),
                            resolved_path: candidate.path.clone(),
                            inode: 0,
                            owner_uid: 0,
                            mode: 0o666,
                            size: 0,
                            digest: "sha256:0".to_string(),
                        },
                        local_repository: None,
                        servers: Vec::new(),
                        mirrors: Vec::new(),
                        proxies: Vec::new(),
                    });
                    continue;""",
        "a_world_writable_settings_file_is_refused_and_reported_as_a_finding",
    ),
    (
        # Absence is not a finding. Most machines have no `settings.xml` at all,
        # and this row exists because the mutation above would also be satisfied
        # by a version that reported every absence -- two different bugs, one
        # honest way to catch each.
        "report the absence of a settings file as a finding",
        """            if !candidate.path.exists() {
                // Absence is not a finding. Most machines have no `settings.xml`
                // at all and that is not something an operator needs told.
                continue;
            }""",
        """            if !candidate.path.exists() {
                findings.push(Finding {
                    severity: crate::Severity::Refused,
                    subject: candidate.path.display().to_string(),
                    message: "not found".to_string(),
                });
                continue;
            }""",
        "a_machine_with_no_settings_file_gets_an_empty_report_and_no_findings",
    ),
    (
        # A parse failure is a finding, not a run failure. Propagating it makes
        # one broken `settings.xml` look like "Maven is not configured", which is
        # the answer most operators will accept and act on.
        "fail the whole discovery when one file will not parse",
        """                Err(error) => findings.push(Finding {
                    severity: crate::Severity::Refused,
                    subject: candidate.path.display().to_string(),
                    message: error.to_string(),
                }),""",
        """                Err(error) => return Err(error),""",
        "a_malformed_settings_file_is_refused_and_reported_as_a_finding",
    ),
]

BUCKETS = {
    "leak": LEAK,
    "parser": PARSER,
    "claim": CLAIM,
    "policy": POLICY,
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "leak"
    f.PACKAGE = "asv-integrations"
    f.CARGO_TARGET = "--lib"
    f.TEST_PREFIX = "maven::tests::"
    f.STS = MAVEN
    mutations = BUCKETS[mode]
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())