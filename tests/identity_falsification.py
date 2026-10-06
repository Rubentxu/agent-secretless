#!/usr/bin/env python3
"""C1-R — falsifying the broker's identity gate.

M7's first scope item, a dedicated broker UID, was a footnote in a gate row
because nothing could *see* it: the broker's protections are all real and all
of them live inside the invoking user's own boundary. The launch contract now
declares the uid the installation expects and the binary refuses to start when
it is not the one in force.

    crates/broker/src/main.rs      I1, I4, I5
    crates/broker/src/identity.rs  I2, I3

    crates/broker/tests/broker_identity.rs   the witnesses

## What each row would break if the property were not real

*   **I1** deletes the check entirely. Every refusal stops being a refusal and
    becomes a broker that starts holding a credential under an identity the
    operator did not choose — the exact shape the flag exists to make visible.
*   **I2** treats a declaration that is not honoured as if it were. This is the
    subtle one: the verdict is still *computed* correctly, so a test that
    asserted on the verdict would stay green while the binary started anyway.
    The witnesses are therefore the binary's, not the function's.
*   **I3** drops the demand's effect on an undeclared identity. The guarantee
    becomes unfalsifiable in the only direction a deployment can take by
    accident, which is omitting the flag.
*   **I4** moves the check to after the vault is opened. Every refusal still
    refuses and every test that only watched the exit status still passes; what
    changes is that the broker has already read the passphrase. **A refusal
    that arrives after the secret has been read is a refusal that already had
    it**, and nothing about the process shows that.
*   **I5** makes an unparsable uid fall through to a default. The broker still
    refuses, so a test that only watched "did it exit non-zero" would pass —
    while a deployment that typos its own account name gets a *policy* refusal
    that names a uid nobody chose, which is the reading that sends an operator
    looking in the wrong place.

## What this campaign cannot falsify, and says so

**That the packaged unit is correct on the host it lands on.** The unit in
`packaging/asv-brokerd.dedicated.service` is a template with `REPLACE_ME` in
three places, and nothing here proves a given machine's `getent passwd` answer,
its `StateDirectory` mode, or that systemd actually started the unit with the
uid the installer wrote. That needs a host with an account, which this one does
not have. What is falsifiable here is the part the broker owns: that a
declaration is a contract it checks against a syscall rather than takes on
trust.

**The setuid branch.** `check` refuses a setuid broker under
`--require-dedicated-identity`, and the unit tests cover it, but no campaign
row mutates it: producing a setuid binary takes a second build step and the
mutation would not be a one-line edit of the source. The unit test is the
evidence for that branch and the campaign does not claim otherwise.

Run from the repository root:

    python3 tests/identity_falsification.py
    python3 tests/identity_falsification.py I2 I5
    python3 tests/identity_falsification.py --list
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "crates" / "broker" / "src" / "main.rs"
IDENTITY = ROOT / "crates" / "broker" / "src" / "identity.rs"
TARGET = ROOT / "crates" / "broker" / "tests" / "broker_identity.rs"
ALL = (MAIN, IDENTITY, TARGET)

SUITE = "broker_identity"
TIMEOUT = 2400

# The check, verbatim, at the position that matters.
CHECK_BLOCK = """    if let Err(error) = asv_broker::identity::check(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        declared_uid,
        require_dedicated_identity,
    ) {
        eprintln!("asv: {error}");
        std::process::exit(1);
    }
"""


@dataclasses.dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    edits: tuple[tuple[str, str], ...]
    expect: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="I1 the identity check is deleted",
        path=MAIN,
        edits=((CHECK_BLOCK, ""),),
        # Every refusal test fires on the same named phrase, because what
        # actually happens when the gate is absent is the alarming thing rather
        # than a timeout: the broker starts, opens the vault and keeps serving.
        expect="kept serving instead of refusing",
    ),
    Mutation(
        name="I2 a declaration that is not honoured is treated as honoured",
        path=IDENTITY,
        edits=(
            (
                "        Some(declared) => IdentityVerdict::Mismatch { declared, actual },",
                "        Some(declared) => {\n"
                "            let _ = declared;\n"
                "            IdentityVerdict::Dedicated { uid: actual }\n"
                "        }",
            ),
        ),
        # The verdict is still *computed* right in the sibling test, so the
        # witnesses here are the binary's. This row is the argument for them.
        expect="kept serving instead of refusing",
    ),
    Mutation(
        name="I3 a demanded identity with nothing declared is allowed",
        path=IDENTITY,
        edits=(
            (
                "        if let IdentityVerdict::Undeclared { .. } = verdict {\n"
                "            return Err(BrokerIdentityError::MissingDedicatedIdentity(\n"
                "                MissingDedicatedIdentity::Undeclared,\n"
                "            ));\n"
                "        }",
                "        if false {\n"
                "            return Err(BrokerIdentityError::MissingDedicatedIdentity(\n"
                "                MissingDedicatedIdentity::Undeclared,\n"
                "            ));\n"
                "        }",
            ),
        ),
        # The undeclared case, which is the one a deployment reaches by omitting
        # a flag rather than by getting a number wrong.
        expect="kept serving instead of refusing",
    ),
    Mutation(
        name="I4 the identity check runs after the vault is opened",
        path=MAIN,
        # Two edits: remove it from the position that matters, put it back
        # after the passphrase has been read. The whole difference between this
        # row and no row at all is a move, which is why a test that only watched
        # the exit status could not tell them apart.
        edits=(
            (CHECK_BLOCK, ""),
            (
                """        let store = VaultStore::open(&vault_path, &passphrase).unwrap_or_else(|err| {
            eprintln!("asv: cannot open vault {}: {err:?}", vault_path.display());
            std::process::exit(1);
        });""",
                """        let store = VaultStore::open(&vault_path, &passphrase).unwrap_or_else(|err| {
            eprintln!("asv: cannot open vault {}: {err:?}", vault_path.display());
            std::process::exit(1);
        });
""" + CHECK_BLOCK,
            ),
        ),
        # **This row did not go red the way the row above expected, and the
        # way it went red is the finding.** The broker still refuses, still
        # exits non-zero and still names its declared and actual uid — every
        # message assertion passes. What it does not do is refuse *first*:
        # `main` binds the socket at line 555 and opens the vault at 627, so a
        # check placed after the vault has been listening the whole time. The
        # witness is therefore the filesystem and not the prose, which is why
        # `a_refused_broker_leaves_no_socket_and_no_listener` exists as a test
        # of its own rather than as a side assertion.
        expect="a refused broker that bound a listener",
    ),
    Mutation(
        name="I5 an unparsable uid falls through to a default",
        path=MAIN,
        edits=(
            (
                """                    Err(_) => {
                        eprintln!("asv: --identity-uid requires a numeric uid, got {raw:?}");
                        std::process::exit(2);
                    }""",
                """                    Err(_) => {
                        declared_uid = Some(0);
                    }""",
            ),
        ),
        # The broker still refuses and still exits non-zero, so only the exit
        # code separates a typo from a policy decision. `Some(0)` is chosen
        # because root is the one uid no developer runs as, so the fallback
        # lands in the mismatch branch rather than accidentally matching.
        expect="a usage error is exit 2",
    ),
)


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    """Every `before` must be present exactly once.

    A row whose anchor is stale is a row that silently tests nothing. A skip is
    reported, never counted as a pass.
    """
    bad = 0
    for m in MUTATIONS:
        text = m.path.read_text()
        for i, (before, _after) in enumerate(m.edits):
            n = text.count(before)
            if n != 1:
                say(f"BAD  {m.name[:48]:48} edit{i}: {n} matches in {m.path.name}")
                bad += 1
    return bad == 0


def run_suite() -> tuple[int, str]:
    cmd = [
        "cargo", "test", "-p", "asv-broker", "--release",
        "--test", SUITE, "--", "--test-threads=1",
    ]
    try:
        done = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT,
            env={**os.environ, "TMPDIR": "/var/home/rubentxu/agent-secretless-tmp"},
        )
    except subprocess.TimeoutExpired:
        # Never reported as ESCAPED. A suite that could not finish has not been
        # shown to pass, and calling that a result is the one thing a
        # falsification campaign must not do.
        return 124, "TIMEOUT"
    return done.returncode, done.stdout + done.stderr


def residue() -> list[str]:
    return [p.name for p in ALL if p.read_text() != ORIGINAL[p]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print the rows and exit")
    # Declared, not read off `sys.argv` directly: `parse_args` rejects unknown
    # positionals, so a runner that selects rows by indexing `sys.argv[1:]`
    # while never declaring them cannot be asked for a subset at all.
    ap.add_argument("rows", nargs="*", help="row name fragments to run, e.g. I1 I4")
    args = ap.parse_args()

    if args.list:
        for i, m in enumerate(MUTATIONS, 1):
            say(f"{i:2}. {m.name}  [{m.path.name}]")
        return 0

    global ORIGINAL
    ORIGINAL = {p: p.read_text() for p in ALL}

    if not verify_anchors():
        return 1

    wanted = MUTATIONS
    if args.rows:
        picked: list[Mutation] = []
        for arg in args.rows:
            # A fragment that matches nothing is an error rather than an empty
            # selection: "two rows" silently running zero is how a campaign
            # reports a pass over rows it never touched.
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

    say(f"falsifying {len(wanted)} rows of the broker's identity gate")
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
            code, out = run_suite()
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
        if m.expect in out:
            say(f"RED   {m.name}")
            say(f"      the named assertion caught it: {m.expect!r}")
            red += 1
        else:
            say(f"WRONG {m.name}")
            say("      it went red for a reason this row did not name; the failing")
            say("      tests were:")
            for line in out.splitlines():
                if line.startswith("test ") and ("FAILED" in line or "failed" in line):
                    say(f"        {line.strip()}")
            for line in out.splitlines():
                if "panicked at" in line:
                    say(f"        {line.strip()}")
                    break

    left = residue()
    if left:
        say("")
        say(f"RESIDUE: {', '.join(left)} are not back to their original contents")
        return 1
    say("no mutation residue in the tree")
    say(f"{red}/{len(wanted)} mutations went red for the right reason")
    return 0 if red == len(wanted) else 1


if __name__ == "__main__":
    ORIGINAL: dict[Path, str] = {}
    sys.exit(main())
