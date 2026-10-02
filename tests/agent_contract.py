#!/usr/bin/env python3
"""Contract tests for the `asv.agent/v1` document DX2 promises.

07-ROADMAP.md lists "contract/golden tests" as part of DX2, and this is
where they live. The shape is the repository's: a Python suite beside the
others, driving the *real binary*, comparing against goldens under
`tests/golden/`.

# Why goldens and not assertions

Every other test in the DX1/DX2 work asserts a property: that the status is
`blocked`, that a code is `SETUP_REQUIRED`, that a link is runnable. Those
tests are what catch a wrong value. None of them notices a key that *moved*,
one that was renamed, or a field that quietly acquired a second meaning — and
an agent contract is precisely the kind of thing that is consumed by name.

So the goldens fix the document's shape, and the property tests fix its
meaning. A rename fails both, and the golden is the one that says "the key is
gone" rather than "the value is wrong".

# What is normalised, and why

`product_version` is the only field that changes every release. It is replaced
with a sentinel before comparison rather than excluded from the golden,
because a golden that is allowed to drift in one place is a golden that will
be allowed to drift in the next.

Every other field — every key name, every null, every link, every argv — is
compared exactly. A null in a golden is a claim: that the field is present and
known to be unknowable, which is a different thing from the field being
absent.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GOLDEN_DIR = REPO / "tests" / "golden"
def _default_binary() -> Path:
    """Where the build left `asv`, asked of the build itself.

    The obvious answer — `CARGO_TARGET_DIR` or `<repo>/target` — is wrong on
    any machine whose `~/.cargo/config.toml` sets `build.target-dir`, and this
    repository is developed on one. Cargo honours that config; this script
    would not, so it looked in `<repo>/target`, found nothing, and exited 2 in
    the `agent-contract` stage while the `build` stage right before it
    reported success. The failure looked like a missing binary and was really
    two components disagreeing about where binaries live.

    So the question is put to cargo, which is the only component that has the
    full answer: environment variable, then config file, then default. The
    environment variable is still honoured first, because that is the
    documented override, and `<repo>/target` remains the last resort for a
    checkout with no cargo available to ask.
    """
    override = os.environ.get("ASV_BIN")
    if override:
        return Path(override)

    from_env = os.environ.get("CARGO_TARGET_DIR")
    if from_env:
        return Path(from_env) / "debug" / "asv"

    try:
        meta = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps",
             "--manifest-path", str(REPO / "Cargo.toml")],
            capture_output=True, text=True, check=True, timeout=120)
        target_dir = json.loads(meta.stdout)["target_directory"]
        candidate = Path(target_dir) / "debug" / "asv"
        if candidate.exists():
            return candidate
    except (OSError, subprocess.SubprocessError, KeyError, ValueError, json.JSONDecodeError):
        # Cargo missing, offline, or answering something unexpected. The
        # fallback below is the honest guess, and a wrong guess ends in a
        # message that names the path it tried.
        pass

    return REPO / "target" / "debug" / "asv"


BINARY = Path(os.environ.get("ASV_BIN", "")) if os.environ.get("ASV_BIN") else _default_binary()

SENTINEL = "<product_version>"

_failures: list[str] = []
_passes = 0


def check(condition: bool, message: str) -> None:
    global _passes
    if condition:
        _passes += 1
    else:
        _failures.append(message)


def run(args: list[str], home: Path) -> tuple[int, str, str]:
    """Runs the real binary against a throwaway installation."""
    env = dict(os.environ)
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_RUNTIME_DIR=str(home / "run"),
        # The test must not start a service on the host. Same seam `asv setup`
        # exposes, for the same reason.
        ASV_SETUP_NO_SERVICE="1",
    )
    env.pop("ASV_SOCKET", None)
    env.pop("ASV_LIBEXEC_DIR", None)
    proc = subprocess.run(
        [str(BINARY), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def normalise(document: dict) -> dict:
    document = json.loads(json.dumps(document))
    document["product_version"] = SENTINEL
    return document


def compare_to_golden(name: str, document: dict) -> None:
    global _passes
    path = GOLDEN_DIR / f"{name}.json"
    if not path.exists():
        _failures.append(f"{name}: no golden at {path}")
        return
    expected = json.loads(path.read_text(encoding="utf-8"))
    actual = normalise(document)

    if actual == expected:
        _passes += 1
        return

    # Report the difference as keys rather than as two blobs, because a
    # 200-line diff of two JSON documents tells a reader nothing.
    for key in sorted(set(expected) | set(actual)):
        if expected.get(key) != actual.get(key):
            _failures.append(
                f"{name}: top-level key `{key}`\n"
                f"    golden: {json.dumps(expected.get(key))[:300]}\n"
                f"    actual: {json.dumps(actual.get(key))[:300]}"
            )


# --- the goldens ---------------------------------------------------------


def test_discover_with_no_broker_matches_the_golden() -> None:
    """The state a new user is in, and the one AAT-002 describes."""
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        code, out, _ = run(["agent", "discover", "--json"], home)
        check(code == 1, f"exit was {code}, expected 1 for a blocked install")
        document = json.loads(out)
        compare_to_golden("discover_blocked", document)


def test_capabilities_with_no_broker_matches_the_golden() -> None:
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        code, out, _ = run(["capabilities", "--json"], home)
        check(code == 1, f"exit was {code}, expected 1")
        document = json.loads(out)
        compare_to_golden("capabilities_unknown", document)


def test_doctor_matches_the_golden() -> None:
    """DX1's document, re-pinned now that the schema is shared.

    A change to `doctor --json` that DX2 did not intend would otherwise only
    be caught by DX1's property tests, which say nothing about keys moving.
    """
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        _, out, _ = run(["doctor", "--json"], home)
        document = json.loads(out)
        # `doctor` reports what it found on this machine, so the values in
        # `data` are host-dependent. The contract is the *shape*.
        compare_shape(
            "doctor",
            document,
            fixed={"schema", "status", "warnings", "links"},
            fixed_data={"cli_version", "checks", "blocking"},
        )


def compare_shape(name: str, document: dict, fixed: set[str], fixed_data: set[str]) -> None:
    """Compares key sets rather than values, for a host-dependent document."""
    for key in fixed:
        check(key in document, f"{name}: top-level key `{key}` is missing")

    data = document.get("data", {})
    for key in fixed_data:
        check(key in data, f"{name}: data key `{key}` is missing")

    for key in fixed:
        if key in ("status", "schema"):
            continue
        check(isinstance(document[key], list), f"{name}: `{key}` should be an array")

    # Every check carries the same four fields. A check that grows or loses
    # one changes what a consumer can rely on, and this is where that shows.
    for entry in data.get("checks", []):
        for field in ("id", "label", "state", "detail", "remedy"):
            check(
                field in entry,
                f"{name}: a check is missing `{field}`: {json.dumps(entry)[:200]}",
            )


# --- the properties a golden cannot express ------------------------------


def test_installed_via_comes_with_its_provenance() -> None:
    """DX4: `installed_via` is only useful if it can be weighed.

    The golden pins the shape — that `installed_via` and
    `installed_via_source` are present at all. This pins the meaning, which is
    the part a shape check cannot: a value read from a file the installer
    wrote and a value guessed from a path containing a mise directory are
    different claims, and an agent told "mise" has to be able to tell which one
    it is looking at. Without `installed_via_source` the two are
    indistinguishable, and the ADR's "inform the correct mechanism" has
    nothing to inform.
    """
    sources = {"record", "no-record", "unreadable"}
    values = {"installer", "mise", "package-manager", "source"}

    for argv in (["agent", "discover", "--json"], ["doctor", "--json"]):
        with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
            home = Path(tmp)
            (home / "run").mkdir()
            _, out, _ = run(argv, home)
            label = argv[-2]
            document = json.loads(out)
            installation = document.get("data", {}).get("installation", {})

            via = installation.get("installed_via")
            source = installation.get("installed_via_source")
            check(via in values, f"{label}: installed_via={via!r} is a known channel")
            check(source in sources, f"{label}: installed_via_source={source!r} says where it came from")
            check(
                "update_via" in installation,
                f"{label}: the update mechanism is stated, or explicitly null",
            )
            # A source tree is the one channel that owns nothing, so there is
            # no mechanism to name. Anything else must name one.
            if via == "source" and source == "no-record":
                check(
                    installation.get("update_via") is None,
                    f"{label}: a source tree claims no update mechanism",
                )
            else:
                check(
                    installation.get("update_via") is not None,
                    f"{label}: {via!r} names the mechanism that owns the update",
                )


def test_every_link_carries_the_contract_fields() -> None:
    """`06-CLI-CONTRACT.md` §4, on every document this build emits."""
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        for argv in (["agent", "discover", "--json"], ["capabilities", "--json"]):
            _, out, _ = run(argv, home)
            document = json.loads(out)
            for link in document["links"]:
                for field in ("rel", "operation", "invoke", "safety", "requires_human"):
                    check(
                        field in link,
                        f"{argv[0]}: link `{link.get('rel')}` is missing `{field}`",
                    )
                check(
                    link["invoke"]["program"] == "asv",
                    f"{argv[0]}: a link names a program other than `asv`: {link['invoke']}",
                )
                check(
                    isinstance(link["invoke"]["argv"], list),
                    f"{argv[0]}: argv is not an array: {link['invoke']}",
                )
                check(
                    link["safety"]
                    in ("read-only", "local-configuration", "bounded-execution"),
                    f"{argv[0]}: unknown safety `{link['safety']}`",
                )


def test_no_document_offers_the_private_broker_as_a_command() -> None:
    """AAT-002: "no sugerir iniciar `asv-brokerd` directamente".

    The precise property, and the first version of this test said it wrong.
    It asserted that no output mentions `asv-brokerd` at all — which would
    forbid `doctor` from naming the path, and naming the path is exactly what
    `doctor` is for. A user whose broker will not start needs to be told where
    the binary was looked for.

    What AAT-002 forbids is *offering it as something to run*. So that is what
    is asserted: no link anywhere names it as a program, and the agent-facing
    documents do not mention it at all. `doctor` is exempt from the second
    clause and not from the first.
    """
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()

        for argv in (
            ["agent", "discover", "--json"],
            ["capabilities", "--json"],
            ["doctor", "--json"],
        ):
            _, out, _ = run(argv, home)
            document = json.loads(out)
            for link in document.get("links", []):
                program = link["invoke"]["program"]
                check(
                    program == "asv",
                    f"`{argv[0]}` offers a link whose program is `{program}`",
                )
                check(
                    "asv-brokerd" not in link["invoke"]["argv"],
                    f"`{argv[0]}` tells the agent to run asv-brokerd: {link['invoke']}",
                )

        # The two documents an agent reads first never name it at all.
        for argv in (["agent", "discover", "--json"], ["capabilities", "--json"]):
            _, out, _ = run(argv, home)
            check(
                "asv-brokerd" not in out,
                f"`{argv[0]}` names the private broker; an agent should reach it "
                "through `setup`, never by name",
            )


def test_the_human_and_json_forms_agree_on_the_status() -> None:
    """UAT-DX-005 applied to `discover` as well as `doctor`."""
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        _, human, _ = run(["agent", "discover"], home)
        _, machine, _ = run(["agent", "discover", "--json"], home)
        status = json.loads(machine)["status"]
        check(
            f"— {status}" in human,
            f"the human rendering does not carry the status `{status}`:\n{human}",
        )


def test_every_exit_status_is_one_of_three() -> None:
    """Blocked and Error both exit 1; anything else would be a surprise a
    script cannot branch on."""
    with tempfile.TemporaryDirectory(prefix="asv-contract-") as tmp:
        home = Path(tmp)
        (home / "run").mkdir()
        for argv in (["agent", "discover"], ["capabilities"], ["doctor"]):
            code, _, _ = run(argv, home)
            check(code in (0, 1), f"`asv {argv[0]}` exited {code}")


def main() -> int:
    if not BINARY.exists():
        print(f"the asv binary is not at {BINARY}; build it first", file=sys.stderr)
        return 2

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        try:
            test()
        except Exception as error:  # noqa: BLE001 - reported, not swallowed
            _failures.append(f"{test.__name__} raised {error!r}")

    print(f"\n{_passes} checks passed, {len(_failures)} failed\n")
    for failure in _failures:
        print(f"FAIL  {failure}")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
