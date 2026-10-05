#!/usr/bin/env python3
"""Falsification for R2.C.3's product-surface rows.

Same four-bucket accounting as the other harnesses. These rows are about the
broker's decision, so the mutations that matter are the ones that would let a
request reach AWS without the operator having said yes -- or let a credential
nobody configured be used anyway.

Run:  python3 r2c3_falsify.py broker
      python3 r2c3_falsify.py binding
"""

import sys
from pathlib import Path

# The base harness lives beside this one. `python3 tests/falsification/x.py`
# already puts this directory on `sys.path`, so the insert is only load-
# bearing for a runner that imports it as a module instead of executing
# it -- and a campaign that only works one way is a campaign that stops
# being reproducible the first time someone automates it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

LIB = f.REPO / "crates/broker/src/lib.rs"
BINDING = f.REPO / "crates/broker/src/aws_binding.rs"
SELFREPORT_FILE = f.REPO / "crates/broker/src/selfreport.rs"

# The policy decision is the control, so removing it is the mutation that
# matters most: it is the difference between "an operator permitted this" and
# "the code path exists".
BROKER = [
    (
        "ask no policy before acting as a role",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::AwsStsCallerIdentity,\n"
        "            Resource::Api {\n"
        "                audience: binding.deployment.audience.clone(),\n"
        "            },\n"
        "        )?;",
        "        let _ = (session, peer, &binding.deployment.audience);",
        "a_stock_policy_refuses_the_operation_before_any_socket",
    ),
    (
        # The reachability of a deployment nobody configured. The message this
        # replaces names exactly what an operator needs to see, so a fallback is
        # not a convenience -- it is a grant nobody made.
        "use the first configured deployment when the request names none",
        "            None => {\n"
        '                let configured: Vec<String> = self',
        "            None if !self.aws.is_empty() => Ok(&self.aws[0]),\n"
        "            None => {\n"
        '                let configured: Vec<String> = self',
        "a_credential_no_deployment_names_is_refused_before_any_socket",
    ),
    (
        # `authorize_github` opens with the same two guards, so the snippet is
        # anchored on the line only `authorize_aws` has. Without that the
        # harness counts two matches and measures nothing -- which is what
        # "not unique" means here, and why it is a skip and not a pass.
        "act without asking whether the session belongs to this peer",
        "        if !self.session_owned_by(session, peer)? {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "session is not owned by the authenticated peer".into(),\n'
        "            }));\n"
        "        }\n"
        "        if self.secrets.is_none() {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.aws_binding(credential)?;",
        "        if false {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "session is not owned by the authenticated peer".into(),\n'
        "            }));\n"
        "        }\n"
        "        if self.secrets.is_none() {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.aws_binding(credential)?;",
        "a_session_this_peer_does_not_own_is_refused_before_any_socket",
    ),
    (
        "attempt the call with no vault open",
        '        if self.secrets.is_none() {\n'
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.aws_binding(credential)?;",
        "        if false {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.aws_binding(credential)?;",
        "a_broker_with_no_vault_open_refuses_before_any_socket",
    ),
    (
        # A refusal the operator cannot act on. `Upstream` says "the provider or
        # the network did not", and a policy denial is neither.
        "report a policy denial as a provider failure",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::AwsStsCallerIdentity,\n"
        "            Resource::Api {\n"
        "                audience: binding.deployment.audience.clone(),\n"
        "            },\n"
        "        )?;",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::AwsStsCallerIdentity,\n"
        "            Resource::Api {\n"
        "                audience: binding.deployment.audience.clone(),\n"
        "            },\n"
        "        )\n"
        "        .map_err(|_| Box::new(Response::Error {\n"
        "            code: ErrorCode::Upstream,\n"
        "            message: \"AWS refused the call\".into(),\n"
        "        }))?;",
        "a_stock_policy_refuses_the_operation_before_any_socket",
    ),
]

# The binding is the operator's declaration, so a sloppy match there is a grant
# by accident rather than a bug somewhere else.
BINDINGS = [
    (
        "treat any credential as the configured one",
        "        &self.deployment.credential == credential",
        "        let _ = credential;\n        true",
        "a_credential_no_deployment_names_is_refused_before_any_socket",
    ),
    (
        # **This one survives, and keeping it is the point.** It was written
        # expecting a derived `Debug` on `AwsSecretPort` to spill a session into
        # the binding's printed form. It does not: `AwsSecretPort` has a
        # hand-written `Debug` that prints the margin and the credential ids and
        # nothing else -- which is exactly the property `port_falsify.py` already
        # falsifies with two mutations of its own.
        #
        # So the defence is two layers down, and this row is a regression net
        # rather than the evidence. Deleting the mutation would hide that; the
        # honest record is that the row is defended elsewhere and says so.
        "print the port and its sessions in Debug",
        '            .field("deployment", &self.deployment)\n'
        "            .finish_non_exhaustive()",
        '            .field("deployment", &self.deployment)\n'
        '            .field("port", &format_args!("{:?}", self.port))\n'
        "            .finish()",
        "a_binding_printed_never_prints_a_session",
    ),
]


# The advertisement is a promise to an agent, so the mutations that matter are
# the ones that break it: an operation nobody is told about, and a name that
# tells them it returns something.
SELFREPORT = [
    (
        "build the operation and never announce it",
        '        "aws.sts.caller_identity".to_string(),\n',
        "",
        "an_agent_asking_what_the_broker_can_do_is_told_about_aws",
    ),
    (
        # Named after the AWS API action rather than after what the caller gets.
        # `selfreport::no_advertised_capability_names_a_retrieval` refuses this
        # spelling as a substring match; this row is the same rule at the
        # surface, and it is here so the substring check is not the only thing
        # standing between the two.
        "announce it under a name that reads like a retrieval",
        '        "aws.sts.caller_identity".to_string(),\n',
        '        "aws.sts.get_caller_identity".to_string(),\n',
        "the_advertised_aws_capability_does_not_name_a_retrieval",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "broker"
    f.TEST_PREFIX = ""
    f.CARGO_TARGET = "--test r2c3_aws_vertical"
    if mode == "selfreport":
        f.STS = SELFREPORT_FILE
        mutations = SELFREPORT
    elif mode == "binding":
        f.STS = BINDING
        mutations = BINDINGS
    else:
        f.STS = LIB
        mutations = BROKER
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
