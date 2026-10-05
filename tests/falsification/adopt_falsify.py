#!/usr/bin/env python3
"""Falsification for the npm adoption step (R3.A.3).

`adopt` is the first step in this crate where a credential exists in the
process, so its mutations are grouped by what a mistake here costs:

* **identity** -- the bytes are not the ones the operator acted on. §6 is the
  whole of the drift control, and a control that cannot fire is not a control.
* **selection** -- the wrong credential is moved. A field name is half a
  selector's identity, and the half that is easy to check is the half that was
  checked first here and then forgotten.
* **refusal** -- an import that should not happen happens, or happens without
  the operator being able to see that it did not.
* **scrub** -- the file is modified as a side effect. This is the one the design
  doc spends a section forbidding, and the only way to know it does not happen is
  to assert the bytes afterwards.

**One row in `adopt/tests.rs` is not attackable from this file, and saying so is
part of the result.** `a_configuration_another_user_may_write_is_refused` asserts
that a group-writable `.npmrc` is refused, but the mechanism is in
`fingerprint.rs`, not here, and it is measured by the `fingerprint` bucket of
`npm_discover_falsify.py`. `adopt` inherits the refusal by calling that function;
there is nothing in this file to mutate.

Run:  python3 adopt_falsify.py identity
      python3 adopt_falsify.py selection
      python3 adopt_falsify.py refusal
      python3 adopt_falsify.py scrub
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

ADOPT = f.REPO / "crates/integrations/src/adopt.rs"

IDENTITY = [
    (
        # §6. The bytes must be the ones the plan recorded; without the
        # comparison the import is a read of whatever happens to be there now.
        "import from a configuration that changed",
        """        let drift = expected.drift_from(&current);
        if !drift.is_empty() {""",
        """        let drift = Vec::new();
        if !drift.is_empty() {""",
        "a_changed_configuration_refuses_before_the_value_is_read",
    ),
    (
        # A replacement is not an edit. Two files with identical bytes have
        # identical digests, so a digest-only check lets a file swapped for an
        # identical copy through -- and the swap is the attack, because the bytes
        # are the same by construction.
        #
        # The first version of this mutation used `FileFingerprint::matches`,
        # on the assumption that it was a digest comparison. It is not: it
        # compares path, inode, owner, mode, size **and** digest, so it still
        # caught the replacement and the row stayed green. **A mutation that
        # does not remove the thing the row is about is not a failed
        # falsification, it is a failed experiment** -- and reporting it as a
        # survivor would have been the honest-looking mistake, because the row
        # genuinely did not go red.
        "compare the file's identity by digest alone",
        "        let drift = expected.drift_from(&current);",
        "        let drift = if expected.digest == current.digest { Vec::new() } else { vec![Drift::Contents] };",
        "a_replaced_file_is_refused_even_with_identical_bytes",
    ),
]

SELECTION = [
    (
        # **This was a real bug.** `extract` matched on the field name alone, so
        # an operator asking for `other.example.test` was served the value
        # written for `registry.example.test` -- the wrong credential imported,
        # under a receipt naming the wrong audience, looking like a success. The
        # row that caught it is
        # `a_selector_the_file_does_not_declare_is_refused`.
        "match a selector on its field alone",
        """            if !registry_of(key).is_some_and(|found| found == selector.audience) {
                continue;
            }""",
            "",
        "a_selector_the_file_does_not_declare_is_refused",
    ),
    (
        # Two lines set the same field for one registry. npm's effective value is
        # the last, so taking the first imports something other than what the
        # tool would use.
        "take the first of two lines setting the same field",
        """            if found.is_some() {
                // Two lines set the same field for the same registry. npm's
                // effective value is the last one, and `discover` reports both,
                // so this is a real shape and not a corrupt file. Guessing here
                // would import something other than what the tool would use.
                return Err(AdoptError::AmbiguousLine {
                    field: selector.field.clone(),
                    audience: selector.audience.clone(),
                });
            }
""",
        "",
        "a_field_set_twice_is_refused_rather_than_guessed",
    ),
    (
        # A selector is file + audience + field. Matching on any one of them lets
        # an operator adopt `_authToken` when they meant `_auth`.
        "match a selector on the field alone",
        """        self.file == file.to_string_lossy() && self.audience == audience && self.field == *field""",
        "        self.field == *field",
        "a_selector_is_matched_on_file_audience_and_field",
    ),
    (
        # A receipt naming one spelling of an endpoint is a receipt that cannot
        # be looked up, and the whole point of `RegistryAudience` is that two
        # spellings are one endpoint.
        "echo the audience as written instead of canonicalising it",
        "        audience: selector.registry.audience.to_string(),",
        "        audience: selector.registry.audience.host().to_string(),",
        "a_selector_built_from_a_parsed_one_carries_the_canonical_audience",
    ),
]

REFUSAL = [
    (
        # `${VAR}` has no value in the file. Importing the name stores a
        # credential that cannot work, and it looks like a success.
        "import an environment reference as a credential",
        """        if value.starts_with("${") && value.ends_with('}') {""",
        "        if false {",
        "an_environment_reference_is_refused_rather_than_imported",
    ),
    (
        # An empty credential is not a credential, and importing one creates a
        # vault entry indistinguishable from a working one until npm fails.
        "import an empty value",
        """        if value.is_empty() {""",
        "        if false {",
        "an_empty_value_is_refused",
    ),
    (
        # The error type is the one place a value could leak without anyone
        # deciding to put it there: an arm that reaches for `value` to be
        # helpful reads as better diagnostics.
        "name the value in the refusal",
        """                return Err(AdoptError::AmbiguousLine {
                    field: selector.field.clone(),
                    audience: selector.audience.clone(),
                });""",
        """                return Err(AdoptError::AmbiguousLine {
                    field: selector.field.clone(),
                    audience: format!("{} (already set to {})", selector.audience, found.unwrap_or("")),
                });""",
        "a_refusal_message_carries_no_value",
    ),
    (
        # §10's five steps are what is left after an import. A receipt that
        # reported nothing outstanding would claim all five happened.
        #
        # This was first pointed at the *vertical's* row of the same subject,
        # which lives in another crate. `--exact` matched no test at all and the
        # harness said `no-run` -- the outcome that exists so a mutation aimed at
        # nothing is never mistaken for one that failed to bite.
        "report the scrub as done",
        """            outstanding: vec![
                PendingStep::VerifyVault,
                PendingStep::VerifyNewIntegration,
                PendingStep::NegativeBypassTest,
                PendingStep::HumanApproval,
                PendingStep::ScrubAndRescan,
            ],""",
        "            outstanding: vec![],",
        "the_receipt_names_the_binding_and_what_is_still_outstanding",
    ),
]

SCRUB = [
    (
        # **The mutation doc 04 §10 exists to forbid.** Import finishes, scrub
        # happens "while we are here". The row asserts the bytes are identical
        # afterwards, so this is the only way to know: a code review of a scrub
        # that looks like a tidy-up is exactly the review that misses it.
        "scrub the original once the value has been read",
        "        Ok(SecretString::new(value.to_string().into_boxed_str()))",
        """        let _ = std::fs::write(file, "");
        Ok(SecretString::new(value.to_string().into_boxed_str()))""",
        "importing_does_not_touch_the_file",
    ),
]

BUCKETS = {
    "identity": IDENTITY,
    "selection": SELECTION,
    "refusal": REFUSAL,
    "scrub": SCRUB,
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "identity"
    f.PACKAGE = "asv-integrations"
    f.CARGO_TARGET = "--lib"
    f.TEST_PREFIX = "adopt::tests::"
    f.STS = ADOPT
    mutations = BUCKETS[mode]
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())