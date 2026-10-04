#!/usr/bin/env python3
"""C4 / M12 — falsifying the TPM 2.0 client.

The property being claimed is narrow, and it is the whole direction of the
increment: this module **refuses** where a placeholder used to answer, and it
speaks to a real device rather than to a mock.

    crates/vault/src/tpm2.rs   R1, R2, R3, R4, R5

## Why these five rows and not others

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

## What this campaign cannot falsify, and says so

**That the device is silicon.** Every device row runs against `swtpm`, a
software TPM 2.0 implementation. It speaks the real protocol, which is what the
rows exercise; it is not hardware, and `is_hardware` is false throughout. A host
with a real TPM would be a different run on a different machine.

**That the authorization for a real sealed object works.** `TPM2_CreatePrimary`,
`TPM2_Create` and `TPM2_Load` are not implemented. R5 measures that the refusal
is real, not that sealing works.

**That a PCR can be written.** `TPM2_PCR_Extend` is absent, which is why the
device tests assert the frame and not that a digest is non-zero: on a device
that has just been started every PCR *is* zero, and that is the correct answer.

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
    edits: list[tuple[str, str]] = field(default_factory=list)


MUTATIONS = [
    Mutation(
        name="R1 pcrUpdateCounter goes back into the PCR_Read request",
        why="the exact bug the encoding work found, against a real device",
        path=TARGET,
        suite="device",
        edits=[
            (
                "        body.extend_from_slice(&bitmap);\n"
                "        // **And nothing else.**",
                "        body.extend_from_slice(&bitmap);\n"
                "        body.extend_from_slice(&0u32.to_be_bytes());\n"
                "        // **And nothing else.**",
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
        edits=[
            (
                "    fn seal(&self, _kek: &[u8; 32], _pcr_policy: &PcrPolicy)"
                " -> Result<TpmSealed, TpmError> {\n"
                "        Err(TpmError::TpmRefused(\n"
                "            \"this tpm2 device does not seal yet:"
                " object creation is not implemented\".to_string(),\n"
                "        ))\n"
                "    }",
                "    fn seal(&self, kek: &[u8; 32], pcr_policy: &PcrPolicy)"
                " -> Result<TpmSealed, TpmError> {\n"
                "        Ok(TpmSealed {\n"
                "            blob: vec![0u8; 32],\n"
                "            pcr_policy: pcr_policy.clone(),\n"
                "            policy_version: 1,\n"
                "        })\n"
                "    }",
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
