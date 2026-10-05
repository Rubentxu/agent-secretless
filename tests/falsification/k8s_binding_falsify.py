#!/usr/bin/env python3
"""Falsification for R2.D.3.1c, the deployment declaration.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the eight that are not are
counted as such rather than quietly folded into the total.**

The binding has twenty rows. This campaign files twelve mutations, and they take
twelve rows red one-for-one — no overlap between them, which is a fact about the
filing rather than an assumption, and the reason the account below is shorter
than the ones in the earlier harnesses.

**Five are positive.** `a_declared_cluster_name_is_accepted_for_a_private_audience`,
`a_cluster_local_name_is_accepted_too`, `a_public_audience_without_the_exception_is_accepted`,
`a_binding_serves_the_credential_it_declares` and
`a_deployment_that_is_correct_would_not_pass_a_check_that_refused_everything`.
A declaration module is almost entirely refusals, and that is exactly the shape
where a `check` that returned `Err` unconditionally would look perfect. These
are what it would fail.

**Two are held by the type in front of them.**
`a_bare_suffix_is_refused_before_the_in_cluster_check_ever_sees_it` asserts that
`.svc` cannot be constructed as an `Authority` at all — so no edit here can undo
it, and the suffix check is not what saves us. And the two rows about what a
`Debug` says of the exception ride on a derived `Debug` for a struct field,
which no single edit here changes. The row about the *binding's* own `Debug` is
different and is filed, because `finish_non_exhaustive` is a line.

**What this campaign is mostly about.** Kubernetes is the one provider here
whose correct audience is normally a private address: `kubernetes.default.svc`
resolves to a ClusterIP, and `AddressPolicy` refuses private addresses because
that is where cloud metadata services live. So the module exists to make that
one unavoidable exception narrow. Most of the twelve mutations below are
attempts to widen it — an IP literal that declares itself in-cluster, a name
that merely *contains* `.svc`, an exception on a public audience — and the rows
that catch them are the reason this is a control rather than a comment.

Run:  python3 k8s_binding_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

BINDING = f.REPO / "crates/broker/src/k8s/binding.rs"

MUTATIONS = [
    # ---- the exception, widened --------------------------------------------
    (
        # The single most damaging edit available here: a private audience with
        # no declaration becomes fine. Every cluster deployment stops needing
        # the exception, which means nobody ever writes it down, which means the
        # audit record cannot tell a deliberate in-cluster deployment from an
        # accidental reach into a private network.
        "accept a private audience nobody declared",
        "        match self.in_cluster {\n            None => Err(DeploymentError::PrivateAudienceUndeclared {\n                audience: self.audience.clone(),\n            }),",
        "        match self.in_cluster {\n            None => Ok(()),\n            Some(_) if false => Err(DeploymentError::PrivateAudienceUndeclared {\n                audience: self.audience.clone(),\n            }),",
        "a_private_audience_is_refused_when_the_operator_did_not_declare_it",
    ),
    (
        # Drop the cluster-name check entirely. This is what the exception looks
        # like one week later, when somebody needs to reach a non-Kubernetes
        # service on the same private network and reasons that the declaration
        # already said "private is fine".
        "let any declared private audience through",
        "            Some(_) if !InCluster::matches(&self.audience) => {\n                Err(DeploymentError::NotAClusterName {\n                    audience: self.audience.clone(),\n                })\n            }\n",
        "",
        "an_ip_literal_may_not_declare_itself_in_cluster",
    ),
    (
        # Suffix becomes substring. `kubernetes.default.svc.attacker.example`
        # is a name an attacker controls and it contains `.svc`, so a
        # containment check is the whole difference between pinning the
        # audience to cluster DNS and pinning it to nothing at all.
        "match a substring of the name instead of its end",
        "        name.ends_with(\".svc\")",
        "        name.contains(\".svc\")",
        "a_name_that_only_looks_like_a_cluster_name_is_refused",
    ),
    (
        # The exception is for a private audience. Carrying it on a public one
        # does nothing today and means something the day the public audience
        # starts resolving privately — which is what a split-horizon DNS answer
        # looks like from here.
        "let a public audience carry the exception",
        "                Some(_) => Err(DeploymentError::ExceptionOnAPublicAudience {\n                    audience: self.audience.clone(),\n                }),\n                None => Ok(()),",
        "                _ => Ok(()),",
        "a_public_audience_may_not_carry_the_exception",
    ),
    # ---- the load-time checks ----------------------------------------------
    (
        "load a relative token path",
        "        if !self.token_path.is_absolute() {",
        "        if false {",
        "a_relative_token_path_is_refused_at_load",
    ),
    (
        "load a deployment whose port is zero",
        "        if self.port == 0 {",
        "        if false {",
        "a_port_of_zero_is_refused",
    ),
    (
        # Order is a decision. A deployment that is wrong in two ways should be
        # told about the one that is cheaper to fix and would have stopped the
        # broker at load anyway; naming the audience first sends an operator
        # through a DNS question when the answer is "your port is zero".
        "check the audience before the port",
        "        if self.port == 0 {\n            return Err(DeploymentError::ZeroPort);\n        }",
        "        if self.in_cluster.is_none() && self.port == 0 {\n            // moved below the audience check\n        }",
        "the_port_refusal_comes_before_the_audience_refusal",
    ),
    (
        # The obvious "be helpful" change, and it turns a rotated-away mount
        # into a broker that will not start. The path is checked for shape
        # here; whether the kubelet has projected the file yet is a lend-time
        # question, and a broker restarted before its pod would fail on it.
        "require the token file to exist at load",
        "        if !self.token_path.is_absolute() {",
        "        if !self.token_path.is_absolute() || !self.token_path.exists() {",
        "a_deployment_whose_token_file_does_not_exist_still_loads",
    ),
    # ---- what an operator is told ------------------------------------------
    (
        "drop the advice from the undeclared-audience refusal",
        '        "audience {audience} is a private address; an in-cluster deployment must \\\n         declare it with K8sDeployment::in_cluster so the exception is on the record"',
        '        "audience {audience} is a private address"',
        "the_refusal_says_what_to_do_rather_than_only_what_failed",
    ),
    (
        # The path is a fact about Kubernetes that the rows above would not
        # catch: every refusal row passes with the wrong path, and every real
        # deployment fails. It lived in a test fixture until this row was
        # rewritten to compare the product constant against the documented
        # string, which is the only version of it that can fail.
        "move the projected token path",
        'pub const PROJECTED_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";',
        'pub const PROJECTED_TOKEN_PATH: &str = "/var/run/secrets/tokens/serviceaccount";',
        "the_projected_token_path_is_the_one_kubernetes_actually_uses",
    ),
    # ---- the binding -------------------------------------------------------
    (
        # The row this one is filed against is the *other* half of a positive
        # pair: a binding that serves every credential passes it, because it
        # serves the declared one too. The row that catches it is
        # `a_binding_serves_nothing_else`, and the pair is why the positive row
        # is not decoration.
        "let a binding serve any credential",
        "        &self.deployment.credential == credential",
        "        let _ = credential;\n        true",
        "a_binding_serves_nothing_else",
    ),
    (
        # `finish_non_exhaustive` is the line that stops a later-added field
        # from being printed without anyone deciding to. Replacing it with a
        # plain `finish` is a four-character change that silently widens what a
        # `{:?}` of a live binding reveals.
        "print every field of the binding",
        "            .finish_non_exhaustive()",
        "            .field(\"lending_port\", &self.port)\n            .finish()",
        "the_bindings_debug_carries_the_declaration_and_nothing_else",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "k8s::binding::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = BINDING
    f.MUTATIONS[:] = MUTATIONS
    original = BINDING.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert BINDING.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
