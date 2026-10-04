#!/usr/bin/env python3
"""C4 / M12 — falsifying the TPM 2.0 client.

The property being claimed is narrow, and it is the whole direction of the
increment: this module **refuses** where a placeholder used to answer, and it
speaks to a real device rather than to a mock.

    crates/vault/src/tpm2.rs   R1, R2, R3, R4, R5

and, for the authorization session that `TPM2_PCR_Extend` needs and six
matrices of session fields could not produce:

    crates/vault/src/tpm2.rs   R6, R7, R8, R9, R10

and, for the policy route — the session a PCR-bound object is sealed to, and
the digest the client has to be able to state before it seals anything:

    crates/vault/src/tpm2.rs   R11, R12, R13, R14, R15

**The wire layout is pinned without a device** by
`a_password_session_sits_between_the_handles_and_the_parameters`, which
transcribes the 65 bytes `tpm2-tools` sends rather than generating them with
the code under test. R6 to R8 are the three placements of the authorization
area — ahead of the handles, behind the parameters, or in the one place that
works — and each is required to put the *device* test in red, which is the
claim: a layout the device accepts is not a layout the client should ship.

The policy route is pinned the same way and against the same reference client,
with `a_policy_session_is_the_request_the_reference_client_sends` (59 bytes) and
`a_policy_pcr_is_the_request_the_reference_client_sends` (58 bytes). Both
transcriptions read as wrong against the rest of this module: one carries a byte
this client cannot name, and the other carries **no authorization area at all**.

## Why these rows and not others

*   **R1** puts `pcrUpdateCounter` back into the `PCR_Read` request. It is the
    exact bug the encoding work found: `pcrUpdateCounter` is declared in-out, so
    sending a zero for it reads as the obviously-correct thing to do, and a real
    TPM answers `TPM_RC_SIZE`. This row is worth more than the others because it
    runs against a device rather than against a parser, so a green campaign
    cannot be explained by the fixture agreeing with the client.
*   **R2** drops the check that a frame has no bytes left over. Every other
    check in the parser can pass on a frame that is four bytes too long, and a
    parser that stops after the last digest accepts it — which is how an
    off-by-one in an offset becomes a wrong PCR instead of an error.
*   **R3** drops the check that the device echoed the selection that was asked
    for. Without it a device that read a different PCR would be believed.
*   **R4** makes `is_hardware` true for any endpoint that exists. This is the
    substitution the whole distinction exists to keep out: a fixture answering
    where a deployment believes hardware does. It is the row a reviewer would
    call pedantic, and it is the row that matters most.
*   **R5** makes `seal` fabricate a `TpmSealed` instead of refusing. The
    placeholder this module replaced did exactly that for the whole life of M12,
    and the milestone exists because a mechanism that looks healthy while
    protecting nothing is the failure being removed.
*   **R11** puts the password session area back into `PolicyPCR`. This is the
    row that keeps the two halves of the file from being one habit: a policy
    command that authorizes nothing must send no area, and the area is the one
    piece of this module that *looks* right everywhere else. It is refused
    `0x184`, which is the same code six earlier attempts read as a session
    problem.
*   **R12** replaces the `pcrDigest` with thirty-two zero bytes. The digest is
    the hash of the PCR values the selection names, and the device checks it —
    so this row is the difference between "the command is well formed" and "the
    command says something true". A client that sent zeros would be sealing to a
    policy no PCR meets.
*   **R13** stops sorting the values by PCR index, and **R14** stops folding the
    `pcrDigest` into the policy chain. Both leave a chain that still advances
    and still looks like a digest; neither names the PCRs the policy is about.
    They run without a device because the chain this client computes is pinned
    to values the device reported, so a wrong formula cannot agree with the
    fixture unless the fixture is also wrong.
*   **R15** flips the one byte in `TPM2_StartAuthSession` this client cannot
    name. It is a field the device admits exactly one value for, so a client
    that guessed wrong gets `0x2DA` or `0x2D5`; the row is what keeps the
    admission honest.

## What this campaign cannot falsify, and says so

**That the device is silicon.** Every device row runs against `swtpm`, a
software TPM 2.0 implementation. It speaks the real protocol, which is what the
rows exercise; it is not hardware, and `is_hardware` is false throughout. A host
with a real TPM would be a different run on a different machine.

**That a sealed object can be created and unsealed.** `TPM2_CreatePrimary`,
`TPM2_Create` and `TPM2_Load` are still not implemented, and R5 measures that
the refusal is real, not that sealing works. What the policy route adds is the
state a seal would be *to*: R11 to R15 establish that a client can open a policy
session, satisfy a PCR condition in it, and compute the digest that condition
produces. A session that satisfies a policy and an object sealed to that policy
are two different claims, and only the first has been measured.

**That the policy digest this client computes is what another TPM would
compute.** The chain is pinned against `swtpm` 0.10.2. The formula is the
specified one and the seed was measured, but a different implementation is a
different measurement, and this campaign does not claim otherwise.

**That a PCR write is durable.** R6 to R8 and R10 run against `swtpm`, whose
PCRs live in a process that the fixture kills. What they establish is that the
write was accepted and folded in, not that it survives a reboot. R11 and R12
are in the same position: the policy is satisfied by PCR values that die with
the process.

## Running it

    python3 tests/tpm2_falsification.py            # all rows
    python3 tests/tpm2_falsification.py --list
    python3 tests/tpm2_falsification.py R1 R4

Requires `swtpm` on PATH for the device row; the other four need nothing.
The campaign restores every file it touches in a `finally`, and refuses to
report a pass if anything is left modified.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "vault" / "src" / "tpm2.rs"
ALL = [TARGET]
TIMEOUT = 1800
ORIGINAL: dict[Path, str] = {}


@dataclass
class Mutation:
    name: str
    why: str
    path: Path
    suite: str
    must_fail: str = ""
    edits: list[tuple[str, str]] = field(default_factory=list)


MUTATIONS = [
    Mutation(
        name="R1 pcrUpdateCounter goes back into the PCR_Read request",
        why="the exact bug the encoding work found, against a real device",
        path=TARGET,
        suite="device",
        edits=[
            # The `PCR_Read` body is built by `pcr_selection_body` now, shared
            # with `PolicyPCR` so the policy chain hashes the bytes that go on the
            # wire. The mutation belongs where the body is assembled, not where
            # the comment about it used to live.
            (
                "    body.push(PC_CLIENT_PCR_SELECTION_BYTES);\n"
                "    body.extend_from_slice(&bitmap);\n"
                "    Ok(body)",
                "    body.push(PC_CLIENT_PCR_SELECTION_BYTES);\n"
                "    body.extend_from_slice(&bitmap);\n"
                "    body.extend_from_slice(&0u32.to_be_bytes());\n"
                "    Ok(body)",
            )
        ],
    ),
    Mutation(
        name="R2 a frame with bytes left over is accepted anyway",
        why="an off-by-one in an offset becomes a wrong PCR instead of an error",
        path=TARGET,
        suite="default",
        edits=[
            (
                "    if cursor != answer.len() {",
                "    if false && cursor != answer.len() {",
            )
        ],
    ),
    Mutation(
        name="R3 the device's selection is trusted without checking the echo",
        why="a device that read a different PCR would be believed",
        path=TARGET,
        suite="default",
        # The first formulation of this row neutralised only the width half of
        # the condition, and it **escaped**. That is worth recording rather than
        # quietly rewriting: a device whose banks are a different width also
        # echoes a bitmap of a different length, so `implemented != asked`
        # already catches every case the width comparison catches. The two
        # halves cannot be separated by these tests, and the width comparison is
        # subsumed. It is kept because it names the failure in the message an
        # operator reads, not because a test distinguishes it.
        edits=[
            (
                "    if sizeof_select as usize != asked.len() || implemented != asked {",
                "    if false && (sizeof_select as usize != asked.len() || implemented != asked) {",
            )
        ],
    ),
    Mutation(
        name="R4 any endpoint that exists reports as hardware",
        why="the substitution this distinction exists to keep out",
        path=TARGET,
        suite="default",
        edits=[
            (
                "    pub fn is_hardware(&self) -> bool {\n"
                "        matches!(self, Self::CharacterDevice(_))\n"
                "    }",
                "    pub fn is_hardware(&self) -> bool {\n"
                "        !matches!(self, Self::Absent)\n"
                "    }",
            )
        ],
    ),
    Mutation(
        name="R5 seal fabricates a sealed blob instead of refusing",
        why="what the placeholder did for the whole life of M12",
        path=TARGET,
        suite="default",
        # The refusal message has been rewritten twice since this row was
        # written — each time the row's anchor went stale and the campaign
        # refused to run at all, which is the guard working. It is anchored to
        # the whole function so the next rewrite breaks it loudly.
        edits=[
            (
                "    fn seal(&self, _kek: &[u8; 32], _pcr_policy: &PcrPolicy)"
                " -> Result<TpmSealed, TpmError> {\n"
                "        Err(TpmError::TpmRefused(\n"
                "            \"this tpm2 device does not seal yet: CreateLoaded and Unseal work, but \\\n"
                "             CreateLoaded has no creationPCR, and a policy-bound unseal needs a \\\n"
                "             policy session and AES-CFB decryption of its response\"\n"
                "                .to_string(),\n"
                "        ))\n"
                "    }",
                "    fn seal(&self, kek: &[u8; 32], pcr_policy: &PcrPolicy)"
                " -> Result<TpmSealed, TpmError> {\n"
                "        let _ = kek;\n"
                "        Ok(TpmSealed {\n"
                "            blob: vec![0u8; 32],\n"
                "            pcr_policy: pcr_policy.clone(),\n"
                "            policy_version: 1,\n"
                "        })\n"
                "    }",
            )
        ],
    ),
    Mutation(
        name="R6 the session area moves ahead of the command's handles",
        why="the layout six matrices of session fields never tried, because all "
            "six put the area at one end and varied what was inside it",
        path=TARGET,
        suite="device",
        must_fail="a_password_session_writes_a_pcr_and_the_device_folds_it",
        edits=[
            (
                "        request.extend_from_slice(&code.to_be_bytes());\n"
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(&(area.len() as u32).to_be_bytes());\n"
                "        request.extend_from_slice(&area);\n"
                "        request.extend_from_slice(parameters);",
                "        request.extend_from_slice(&code.to_be_bytes());\n"
                "        request.extend_from_slice(&(area.len() as u32).to_be_bytes());\n"
                "        request.extend_from_slice(&area);\n"
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(parameters);",
            )
        ],
    ),
    Mutation(
        name="R7 authorizationSize stops being sent",
        why="the field whose presence was one axis of the dead-end matrix",
        path=TARGET,
        suite="device",
        must_fail="a_password_session_writes_a_pcr_and_the_device_folds_it",
        edits=[
            (
                # The `handles` line is in the anchor because the byte-layout
                # test rebuilds the same three lines from its own transcription.
                # That duplication is deliberate — a test that built its
                # expectation with the helper it is testing would agree with any
                # layout — so the anchor needs the line that differs to be
                # unique.
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(&(area.len() as u32).to_be_bytes());\n"
                "        request.extend_from_slice(&area);",
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(&area);",
            )
        ],
    ),
    Mutation(
        name="R8 the session area moves behind the command's parameters",
        why="the other end, which is where the area does not go either",
        path=TARGET,
        suite="device",
        must_fail="a_password_session_writes_a_pcr_and_the_device_folds_it",
        edits=[
            (
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(&(area.len() as u32).to_be_bytes());\n"
                "        request.extend_from_slice(&area);\n"
                "        request.extend_from_slice(parameters);",
                "        request.extend_from_slice(handles);\n"
                "        request.extend_from_slice(parameters);\n"
                "        request.extend_from_slice(&(area.len() as u32).to_be_bytes());\n"
                "        request.extend_from_slice(&area);",
            )
        ],
    ),
    Mutation(
        name="R9 Clear stops sending its authHandle",
        why="the missing first handle, which is what 0x184 was naming all along",
        path=TARGET,
        suite="device",
        must_fail="clear_is_accepted_and_the_missing_handle_was_the_whole_bug",
        edits=[
            (
                "        self.authorized_command(TPM2_CLEAR, &TPM_RH_LOCKOUT.to_be_bytes(), &[])?",
                "        self.authorized_command(TPM2_CLEAR, &[], &[])?",
            )
        ],
    ),
    Mutation(
        name="R10 pcr_extend reports success without writing",
        why="a write that appears to have worked and changed nothing is the "
            "failure this milestone exists to remove",
        path=TARGET,
        suite="device",
        must_fail="a_password_session_writes_a_pcr_and_the_device_folds_it",
        # The first formulation of this row discarded the command's *response*
        # and still sent the command, so the PCR was written and the test
        # correctly stayed green: the row was measuring nothing. A claim about
        # "reports success without writing" has to stop writing.
        edits=[
            (
                "        self.authorized_command(TPM2_PCR_EXTEND, &handles, &parameters)?\n"
                "            .into_body()\n"
                "            .map(|_| ())",
                "        let _ = (handles, parameters, self.channel.is_none());\n"
                "        Ok(())",
            )
        ],
    ),
    Mutation(
        name="R11 PolicyPCR goes out carrying the password session area",
        why="a policy command that authorises nothing must send no area, and the "
            "area this module uses for PCR_Extend is the one thing that looks "
            "right and is refused with 0x184",
        path=TARGET,
        suite="device",
        must_fail="a_policy_pcr_is_accepted_for_the_pcrs_it_names",
        edits=[
            (
                "        self.command(TPM2_POLICY_PCR, &body)?\n"
                "            .into_body()\n"
                "            .map(|_| pcr_digest)",
                "        self.authorized_command(TPM2_POLICY_PCR, &body, &[])?\n"
                "            .into_body()\n"
                "            .map(|_| pcr_digest)",
            )
        ],
    ),
    Mutation(
        name="R12 the pcrDigest stops being the hash of the PCR values",
        why="a well-formed digest that says nothing true is refused by the device, "
            "and a client that sent one would be sealing to a policy no PCR meets",
        path=TARGET,
        suite="device",
        must_fail="a_policy_pcr_is_accepted_for_the_pcrs_it_names",
        edits=[
            (
                "        let pcr_digest = pcr_value_digest(&self.pcr_read(slots)?);",
                "        let pcr_digest = [0u8; 32];\n"
                "        let _ = pcr_value_digest;",
            )
        ],
    ),
    Mutation(
        name="R13 the pcr digest stops sorting by PCR index",
        why="the device concatenates the values the selection covers in index "
            "order, so a digest over the caller's ordering names a set nobody asked for",
        path=TARGET,
        suite="default",
        must_fail="the_pcr_digest_hashes_the_values_in_index_order_not_in_the_order_asked",
        edits=[
            (
                "    ordered.sort_by_key(|(index, _)| *index);",
                "    // mutation: the order the caller listed them in is the order they hash in",
            )
        ],
    ),
    Mutation(
        name="R14 the policy chain stops folding in the pcrDigest",
        why="the chain is H(policy ‖ CC ‖ pcrs ‖ pcrDigest); drop the last term "
            "and the chain still advances, still looks like a digest, and no longer "
            "names the PCRs the policy is about",
        path=TARGET,
        suite="default",
        must_fail="the_policy_chain_reproduces_the_digests_the_device_reported",
        edits=[
            (
                "    hasher.update(pcr_digest);\n"
                "    hasher.finalize().into()",
                "    let _ = pcr_digest;\n"
                "    hasher.finalize().into()",
            )
        ],
    ),
    Mutation(
        name="R15 the policy session's unnamed byte stops being zero",
        why="a field the device admits exactly one value for, and this client "
            "cannot name; a client that guessed wrong is answered 0x2DA or 0x2D5",
        path=TARGET,
        suite="default",
        must_fail="a_policy_session_is_the_request_the_reference_client_sends",
        edits=[
            (
                "const POLICY_SESSION_UNNAMED_FIELD: u8 = 0x00;",
                "const POLICY_SESSION_UNNAMED_FIELD: u8 = 0x01;",
            )
        ],
    ),
]


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    bad = 0
    for m in MUTATIONS:
        text = m.path.read_text()
        for i, (before, _after) in enumerate(m.edits):
            n = text.count(before)
            if n != 1:
                say(f"BAD  {m.name[:48]:48} edit{i}: {n} matches in {m.path.name}")
                bad += 1
    return bad == 0


def run(suite: str) -> tuple[int, str]:
    if suite == "device":
        cmd = ["cargo", "test", "-p", "asv-vault", "--lib", "--features", "tpm-device", "tpm2"]
    else:
        cmd = ["cargo", "test", "-p", "asv-vault", "--lib", "tpm2"]
    try:
        done = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env={**os.environ, "TMPDIR": "/var/home/rubentxu/agent-secretless-tmp"},
        )
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    return done.returncode, done.stdout + done.stderr


def residue() -> list[str]:
    return [p.name for p in ALL if p.read_text() != ORIGINAL[p]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("rows", nargs="*", help="row name fragments, e.g. R1 R4")
    args = ap.parse_args()

    if args.list:
        for m in MUTATIONS:
            say(f"{m.name}  [{m.path.name} -> {m.suite}]")
        return 0

    ORIGINAL.update({p: p.read_text() for p in ALL})

    if not verify_anchors():
        return 1

    wanted = MUTATIONS
    if args.rows:
        picked: list[Mutation] = []
        for arg in args.rows:
            hits = [m for m in MUTATIONS if arg.upper() in m.name.upper()]
            if not hits:
                say(f"no row matches {arg!r}")
                return 1
            picked.extend(hits)
        seen: set[str] = set()
        wanted = [m for m in picked if not (m.name in seen or seen.add(m.name))]
        if not wanted:
            say("no rows selected")
            return 1

    say(f"falsifying {len(wanted)} rows of the tpm2 client")
    say("")
    red = 0
    for m in wanted:
        applied = True
        for before, after in m.edits:
            text = m.path.read_text()
            if text.count(before) != 1:
                say(f"SKIP {m.name}: the anchor is stale")
                applied = False
                break
            m.path.write_text(text.replace(before, after, 1))
        if not applied:
            continue
        try:
            code, out = run(m.suite)
        finally:
            for p in ALL:
                p.write_text(ORIGINAL[p])

        if "error[" in out or "error: could not compile" in out:
            say(f"SKIP {m.name}: the mutation does not compile")
            continue
        if code == 124:
            say(f"KILL {m.name}: the suite did not finish")
            continue
        if code == 0:
            say(f"ESCAPE {m.name}: the suite stayed green")
            continue
        # A red suite is not the same as the named assertion going red. Another
        # test in the file can fail for an unrelated reason and satisfy a
        # campaign that only looks at the exit code, which is how a mutation
        # gets reported as falsified when nothing tested it.
        if m.must_fail and f"{m.must_fail} ... FAILED" not in out:
            say(f"ESCAPE {m.name}: the suite went red but {m.must_fail} did not")
            say("      the mutation was not exercised by the assertion that names it")
            continue
        say(f"RED   {m.name}")
        say(f"      {m.why}")
        for line in out.splitlines():
            if line.startswith("test ") and "FAILED" in line:
                say(f"      {line.strip()}")
        for line in out.splitlines():
            if "panicked at" in line:
                say(f"      {line.strip()}")
        red += 1

    left = residue()
    if left:
        say("")
        say(f"RESIDUE: {', '.join(left)} are not back to their original contents")
        return 1
    say("no mutation residue in the tree")
    say(f"{red}/{len(wanted)} mutations went red")
    return 0 if red == len(wanted) else 1


if __name__ == "__main__":
    sys.exit(main())
