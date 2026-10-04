#!/usr/bin/env python3
"""Is the skill telling the truth about the CLI?

DX3's exit is "the skill activates on secretless tasks and does not activate on
tasks that manipulate secrets directly". Neither half of that is checkable by
reading the skill. Both are checkable by comparing the skill to the thing the
skill talks about.

# Why a guard and not a review

A skill is prose. Prose drifts: the CLI grows a relation, or renames one, or a
reference is edited to mention a command that never existed, and nothing in
either repository notices until an agent follows the stale sentence into a
subcommand the parser rejects. `tests/agent_contract.py` checks that the
*document* is well formed. This checks that the *instructions about* the
document are still accurate.

So every navigable name in the skill is extracted mechanically and compared
against the source of truth, which is the Rust that defines them. Nothing here
restates a rel list: `relations.rs` is parsed, and if it cannot be parsed the
suite fails rather than skipping, because a guard that quietly has no truth to
compare against is indistinguishable from a guard that passes.

# The two halves

**Fidelity** (C1-C9, C14): the skill names only rels, operations, argv arrays,
codes and envelope fields the product actually has, and names all of the ones
it must. A skill that invents `asv://rels/vault/read` fails; a skill that drops
`asv://rels/capabilities` fails too, because the omission is what an agent
cannot recover from.

**Conduct** (C10-C11): the prescriptive half of the skill contains no shell
construction and no un-negated instruction to retrieve a secret. The
anti-pattern reference is allowed to name both, because naming them is its job;
the rest of the skill is not allowed to contain them at all, which is a
mechanically decidable line rather than a matter of tone.

# Where the skill lives

It is a separate repository (`Rubentxu/agent-skill`, ADR-05), so this is a
cross-repository guard and the path is an input. Override with `ASV_SKILL_DIR`;
the default is a sibling checkout.

**When it is absent, this suite fails.** It used to exit 77 and say "skipped",
on the reasoning that a machine without a checkout cannot run a cross-repo
check. That reasoning was sound and the consequence was not: a release pipeline
read 77 as "nothing to do here", so the one thing R0.3 exists to establish — the
official skill is published and matches the product — was decided by whether the
build machine happened to have a sibling directory. A gate that goes green by
not having the thing it gates is not a gate.

**It also refuses to check the proposal in this repository.**
`docs/asv-agent-first-evolution/proposed-skill/agent-secretless/` is a copy kept
here for history, and pointing `ASV_SKILL_DIR` at it produces an entirely green
run that means nothing: the copy an agent installs is the one in the other
repository, and that is the copy that drifts. ADR-05 puts it there on purpose —
"no se mete en el repo de ASV como fuente canónica" — so the guard enforces the
separation instead of describing it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RELATIONS_RS = REPO / "crates" / "cli" / "src" / "agent" / "relations.rs"
DISCOVER_RS = REPO / "crates" / "cli" / "src" / "agent" / "discover" / "mod.rs"
SCHEMA_RS = REPO / "crates" / "cli" / "src" / "agent" / "schema.rs"

# The prescriptive half. Everything an agent reads on the happy path, plus the
# routing documents. `05`, `06` and `07` are excluded only for C11: they are
# the documents whose subject *is* the failure mode, and a guard that forbade
# them from naming it would be forbidding the answer.
#
# The `references/` prefix matters and is not cosmetic. These names are looked
# up as keys of the file map, and a list written without the prefix silently
# resolves to nothing: every check then passes because it examined no file at
# all. That is why `_documents_exist` fails loudly instead of skipping.
PRESCRIPTIVE = ("SKILL.md",
                "references/00-decision-tree.md",
                "references/01-discovery-hypermedia.md",
                "references/02-install-setup.md",
                "references/03-execution.md",
                "references/04-integrations.md")
ANTI_PATTERN = ("references/05-approvals-audit.md",
                "references/07-security-anti-patterns.md")

SKILL_BUDGET = 6000

_failures: list[str] = []
_passes = 0
_skips: list[str] = []


def check(condition: bool, message: str) -> None:
    global _passes
    if condition:
        _passes += 1
        print(f"  ok   {message}")
    else:
        _failures.append(message)
        print(f"  FAIL {message}")


def skill_dir() -> Path:
    override = os.environ.get("ASV_SKILL_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return (REPO.parent / "agent-skill" / "skills" / "agent-secretless").resolve()


# ---------------------------------------------------------------- truth side

def parse_truth() -> dict:
    """Read the contract out of the source, or fail trying.

    A parse that returns an empty set is the dangerous case: every comparison
    would then pass vacuously. So an empty or implausibly small result is
    itself a failure, not a shrug.
    """
    rel_src = RELATIONS_RS.read_text(encoding="utf-8")
    disc_src = DISCOVER_RS.read_text(encoding="utf-8")
    schema_src = SCHEMA_RS.read_text(encoding="utf-8")

    # rel uri, keyed by variant, from `AgentRel::X => "asv://rels/..."`
    rels = dict(re.findall(r'AgentRel::(\w+)\s*=>\s*"(asv://[^"]+)"', rel_src))
    # operation dotted name, keyed by the same variant
    operations = dict(re.findall(r'AgentRel::(\w+)\s*=>\s*"([a-z]+\.[a-z.]+)"', rel_src))
    # argv per variant, from the descriptor arm
    argvs = dict(re.findall(
        r'AgentRel::(\w+) =>\s*AgentLink::new\(\s*self\.uri\(\),\s*self\.operation\(\),\s*&\[([^\]]*)\]',
        rel_src, re.S))
    argv_list = {k: re.findall(r'"([^"]*)"', v) for k, v in argvs.items()}

    # the published subset, from `operational()`
    m = re.search(r'pub fn operational\(\)[^{]*\{.*?&\[\s*(.*?)\s*\]', rel_src, re.S)
    operational = re.findall(r'AgentRel::(\w+)', m.group(1)) if m else []

    codes = set(re.findall(r'pub const (\w+): &str = "([A-Z_]+)"',
                           disc_src.replace('&str = "', '&str = "', 1)))
    # simpler and less clever: every SCREAMING_SNAKE literal assigned in the file
    codes = set(re.findall(r'"([A-Z][A-Z_]{3,})"', disc_src))
    warn_codes = set(re.findall(r'code:\s*"([A-Z][A-Z_]{3,})"', disc_src))

    fields = set(re.findall(r'pub (\w+):\s*', schema_src))

    return {
        "rels": rels,
        "operations": operations,
        "argv": argv_list,
        "operational": operational,
        "codes": codes,
        "warn_codes": warn_codes,
        "fields": fields,
    }


# ----------------------------------------------------------------- skill side

def read_skill(d: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(d.rglob("*.md")):
        out[str(p.relative_to(d))] = p.read_text(encoding="utf-8")
    return out


def all_text(files: dict[str, str]) -> str:
    return "\n".join(files.values())


def blocks(text: str) -> list[str]:
    """Blank-line-delimited paragraphs, the unit a negation is written in."""
    return [b for b in re.split(r"\n\s*\n", text) if b.strip()]


NEGATION = re.compile(
    r"\b(no|nunca|jamás|sin|never|not|without|nor|prohibid|vetad|"
    r"rechaz|refus|don't|do not|can't|cannot|should not|shouldn't)\b",
    re.I)
SHELL = re.compile(r"\b(sh|bash|zsh)\s+-c\b|\beval\s+[\"'$]")
CJK = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")
GLUED = re.compile(r"\b[a-z]{2,}[A-Z][a-z]{2,}\b")
RETRIEVAL = re.compile(
    r"/proc/|environ|cmdline|\bdesencript|\bdescript|\bdescifra|"
    r"\bvolca\b|\bdumpe?a\b|strings\s+", re.I)
ALLOWED_GLUED = {"GitHub", "PostgreSQL", "Redis", "Landlock", "Seccomp", "OpenAI"}


def has_negation(block: str) -> bool:
    return bool(NEGATION.search(block))


def cjk_and_glued(files: dict[str, str]) -> None:
    """Two of the ways this repository's own documents get corrupted.

    A stray CJK fragment or a camelCase collision is invisible to a reviewer
    reading for meaning — the sentence still parses. It is not invisible to a
    byte scan, and it is the kind of defect that ships because every reader
    silently normalises it.
    """
    for name, text in files.items():
        hit = CJK.search(text)
        check(hit is None,
              f"{name} has no CJK characters"
              + ("" if hit is None else f" (found {hit.group()!r})"))
        glued = [w for w in GLUED.findall(text) if w not in ALLOWED_GLUED]
        check(not glued,
              f"{name} has no glued camelCase word"
              + ("" if not glued else f" (found {glued})"))


# ------------------------------------------------------------------- fidelity

def c1_structure(files: dict[str, str]) -> None:
    required = ["SKILL.md", "README.md", "tests/skill-evals.md"] + [
        f"references/{n}" for n in
        ("00-decision-tree.md", "01-discovery-hypermedia.md", "02-install-setup.md",
         "03-execution.md", "04-integrations.md", "05-approvals-audit.md",
         "06-diagnostics.md", "07-security-anti-patterns.md")]
    for rel in required:
        check(rel in files, f"{rel} exists")


def c2_frontmatter(files: dict[str, str], truth: dict) -> None:
    text = files.get("SKILL.md", "")
    m = re.search(r"^---\n(.*?)\n---", text, re.S)
    check(m is not None, "SKILL.md has frontmatter")
    if not m:
        return
    fm = m.group(1)
    name = re.search(r"^name:\s*(\S+)", fm, re.M)
    check(name is not None and name.group(1) == "agent-secretless",
          "frontmatter name is the directory name")
    desc = re.search(r'^description:\s*"?(.+?)"?$', fm, re.M)
    check(desc is not None and len(desc.group(1).strip()) > 40,
          "frontmatter description is a real sentence, not a stub")
    schema = re.search(r'asv-agent-schema:\s*"?([^"\n]+)"?', fm)
    check(schema is not None and schema.group(1) == "asv.agent/v1",
          "frontmatter declares the schema the product actually serves")


def c3_no_invented_rel(files: dict[str, str], truth: dict) -> None:
    declared = set(truth["rels"].values())
    mentioned = set(re.findall(r"asv://rels/[a-z/]+", all_text(files)))
    invented = mentioned - declared
    check(not invented,
          "the skill invents no relation the product does not declare"
          + ("" if not invented else f" (invented: {sorted(invented)})"))


def c4_withheld_rels_are_marked(files: dict[str, str], truth: dict) -> None:
    """A declared-but-unpublished rel may be named only as a non-option.

    `relations.rs` holds fourteen relations and publishes nine as of R2.A,
    which raised the three GitHub ones against a real command. A skill that
    lists the remaining five as things to follow is worse than one that omits
    them: an agent trusts a list far more than it trusts a missing entry. So
    naming one is allowed, in a block that says out loud that it is not
    published.
    """
    withheld = {u for v, u in truth["rels"].items() if v not in truth["operational"]}
    for name, text in files.items():
        for block in blocks(text):
            named = {r for r in re.findall(r"asv://rels/[a-z/]+", block)} & withheld
            if not named:
                continue
            flat = re.sub(r"\s+", " ", block).lower()
            ok = "withheld" in flat or "no publica" in flat
            check(ok,
                  f"{name} marks {sorted(named)[0]} as not published"
                  if ok else
                  f"{name} presents unpublished {sorted(named)} without saying so")


def c5_every_published_rel_is_reachable(files: dict[str, str], truth: dict) -> None:
    text = all_text(files)
    for variant in truth["operational"]:
        uri = truth["rels"].get(variant)
        if not uri:
            continue
        check(uri in text, f"the skill documents the published relation {uri}")


def c6_operations_are_real(files: dict[str, str], truth: dict) -> None:
    real = set(truth["operations"].values())
    for name, text in files.items():
        for op in set(re.findall(r'"operation":\s*"([a-z]+\.[a-z.]+)"', text)):
            check(op in real,
                  f"{name} operation {op} exists"
                  if op in real else
                  f"{name} invents operation {op}, which the CLI does not define")


def c7_argv_arrays_are_real(files: dict[str, str], truth: dict) -> None:
    """The strongest check in the file.

    Every argv array quoted in the skill must be byte-for-byte an argv the
    product publishes. This is what catches a reference that "helpfully"
    documents a hand-written command: the array is the contract, and an array
    that is not in `operational()` is a command no agent should ever assemble.
    """
    published = {tuple(truth["argv"].get(v, [])) for v in truth["operational"]}
    for name, text in files.items():
        for arr in re.findall(r'"argv":\s*\[([^\]]*)\]', text):
            items = tuple(re.findall(r'"([^"]*)"', arr))
            check(items in published,
                  f"{name} quotes a published argv"
                  if items in published else
                  f"{name} quotes argv {list(items)}, which is not a published link")


def c8_codes(files: dict[str, str], truth: dict) -> None:
    """Two directions, and the second one needs scoping to be worth anything.

    Every code the product can emit must be documented: an agent that meets an
    undocumented code has no move.

    The other direction is "the skill must not invent a code". Scoped naively —
    every backticked SCREAMING_SNAKE token anywhere — that check is wrong,
    because `` `GITHUB_TOKEN` `` and `` `$PATH` `` are legitimately not codes,
    and a guard that reports them trains the reader to ignore it. So a token
    only counts as a *code claim* when the block it sits in is actually talking
    about codes, or when it is in the document whose subject is codes.
    """
    real = set(truth["codes"]) | set(truth["warn_codes"])
    text = all_text(files)
    for code in sorted(real):
        check(code in text, f"the skill documents the {code} outcome")

    claims: set[str] = set()
    for name, body in files.items():
        for block in blocks(body):
            talking_about_codes = re.search(r"\bc[oó]digo\b|\bcodes?\b", block, re.I)
            if talking_about_codes or name == "references/06-diagnostics.md":
                claims |= set(re.findall(r"`([A-Z][A-Z_]{3,})`", block))
    unknown = claims - real
    check(not unknown,
          "the skill invents no error code the product does not emit"
          + ("" if not unknown else f" (invented: {sorted(unknown)})"))


def c9_envelope_fields(files: dict[str, str], truth: dict) -> None:
    text = all_text(files)
    real = {"schema", "product_version", "protocol_version", "status", "data",
            "error", "links", "warnings"}
    # fields the skill names in backticks that look like envelope keys
    for key in sorted(real):
        check(f"`{key}`" in text, f"the skill names the envelope field {key}")
    phantom = {"capabilities", "installation", "broker", "result", "entries"}
    for key in sorted(phantom):
        # Matched as a backticked or dotted key, not as a whole literal: the
        # skill legitimately writes `` `entries: []` `` and `data.result`.
        named = re.search(r"[`.]" + re.escape(key) + r"\b", text)
        check(named is not None,
              f"the skill accounts for data.{key}"
              if named else f"the skill never mentions {key}, which the CLI returns")


# -------------------------------------------------------------------- conduct

def _documents_exist(files: dict[str, str]) -> None:
    """A document a check names but that is absent is a failure, not a skip.

    The alternative — `if name not in files: continue` — produces a guard that
    reports green while examining nothing, which is indistinguishable from a
    working guard until the day it is needed. This is the check that makes
    every other scoped check trustworthy.
    """
    for name in PRESCRIPTIVE + ANTI_PATTERN:
        check(name in files, f"{name} is present for the scoped checks")


def _scoped(files: dict[str, str], names: tuple[str, ...]):
    for name in names:
        text = files.get(name)
        if text is None:
            continue  # already reported by _documents_exist
        yield name, text


def c10_no_retrieval_instruction(files: dict[str, str]) -> None:
    """AAT-006. Retrieval is allowed to be *named*, never *instructed*.

    The anti-pattern reference names `/proc` and `environ` in order to forbid
    them, so a bare mention proves nothing. What must not exist anywhere in the
    skill is a sentence that tells a reader to go and do it. The test is
    therefore: a retrieval term is acceptable only inside a block that also
    carries a negation.
    """
    for name, text in _scoped(files, PRESCRIPTIVE + ANTI_PATTERN):
        for block in blocks(text):
            if not RETRIEVAL.search(block):
                continue
            check(has_negation(block),
                  f"{name} names a retrieval source only to forbid it"
                  if has_negation(block) else
                  f"{name} contains an un-negated retrieval instruction: "
                  f"{RETRIEVAL.search(block).group()!r}")


def c11_no_shell_in_the_prescriptive_path(files: dict[str, str]) -> None:
    """AAT-007. A shell construction may be named in the prescriptive path,
    but only in order to be refused.

    The rule is positional and negational, not tonal. `03-execution.md` exists
    to be followed while building a command, so a `sh -c` there has to be an
    explicit prohibition — that is how the agent learns the property is not
    optional. What must not exist is a shell construction in a block with no
    refusal in it, because that is a sentence the agent can copy.

    `07-security-anti-patterns.md` shows the anti-pattern as its content, so
    it is out of scope for the prohibition; it is not out of scope for C10.
    """
    for name, text in _scoped(files, PRESCRIPTIVE):
        for block in blocks(text):
            hit = SHELL.search(block)
            if not hit:
                continue
            check(has_negation(block),
                  f"{name} names {hit.group()!r} only to forbid it"
                  if has_negation(block) else
                  f"{name} presents {hit.group()!r} without refusing it; an "
                  f"agent following this document can copy it")


# ------------------------------------------------------- progressive disclosure

def c12_progressive_disclosure(files: dict[str, str]) -> None:
    """UAT-DX-007, as a reachability question rather than a size question.

    The requirement is that a plain "run this command through ASV" task does
    not need the recovery, approvals or installation documents unless the
    runtime redirects there. Naming a document in the mode table is not
    loading it, so a byte budget cannot decide this: what decides it is the set
    of documents an agent reaches by following links *out of* the execution
    document. That set is computed here as a closure.

    The heavy set is the four documents an execution task has no reason to
    open. `06-diagnostics` belongs to it despite not being a recovery
    document: an agent that cannot reach it has nowhere to go when the runtime
    does redirect.
    """
    skill = files.get("SKILL.md", "")
    check(len(skill.encode("utf-8")) <= SKILL_BUDGET,
          f"SKILL.md is within the {SKILL_BUDGET}-byte budget "
          f"({len(skill.encode('utf-8'))} bytes)")

    def links_of(name: str) -> set[str]:
        body = files.get(name, "")
        out = set()
        for target in re.findall(r"\]\(([^)#]+\.md)\)", body):
            cand = str(Path(name).parent / target) if name != "SKILL.md" else target
            cand = str(Path(cand))
            if cand.startswith("./"):
                cand = cand[2:]
            if cand in files:
                out.add(cand)
        return out

    start = "references/03-execution.md"
    seen: set[str] = set()
    frontier = [start]
    while frontier:
        cur = frontier.pop()
        if cur in seen:
            continue
        seen.add(cur)
        frontier.extend(links_of(cur) - seen)

    heavy = {"references/02-install-setup.md", "references/05-approvals-audit.md",
             "references/06-diagnostics.md", "references/07-security-anti-patterns.md"}
    reached = seen & heavy
    check(not reached,
          f"the execution path reaches {len(seen)} document(s) and none of the "
          f"heavy ones"
          if not reached else
          f"a successful execution loads {sorted(reached)}; it should not")

    # Every declared mode must resolve. Iterating the *expected* modes rather
    # than the pairs found in the table is the point: scanning the table means
    # a row that lost its reference produces no pair, and a check that never
    # fires is indistinguishable from a check that passed.
    for mode in ("discover", "setup", "execute", "diagnose", "operator"):
        m = re.search(r"`" + mode + r"`\s*\|[^|]*\|\s*\[`references/([^`]+)`\]", skill)
        check(m is not None, f"mode {mode} points at a reference")
        if m:
            check(f"references/{m.group(1)}" in files,
                  f"mode {mode} points at an existing reference"
                  if f"references/{m.group(1)}" in files else
                  f"mode {mode} points at references/{m.group(1)}, which does "
                  f"not exist")


# --------------------------------------------------------------- binary parity

def run_cli(args: list[str], home: Path) -> tuple[int, str]:
    env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(home / "run"))
    (home / "run").mkdir(parents=True, exist_ok=True)
    p = subprocess.run([str(_binary()), *args], env=env, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _binary() -> Path:
    """Where the build left `asv`, asked of the build itself.

    Same reasoning as `tests/agent_contract.py`, and the same bug this fixed
    there: `<repo>/target` is wrong on a machine whose cargo config redirects
    the target directory, so this suite would have skipped its binary-parity
    checks on exactly the machines where they are worth running — and a
    skipped check prints as a pass.
    """
    if os.environ.get("ASV_BIN"):
        return Path(os.environ["ASV_BIN"])
    target = os.environ.get("CARGO_TARGET_DIR")
    if target:
        return Path(target) / "debug" / "asv"
    try:
        meta = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps",
             "--manifest-path", str(REPO / "Cargo.toml")],
            capture_output=True, text=True, check=True, timeout=120)
        candidate = Path(json.loads(meta.stdout)["target_directory"]) / "debug" / "asv"
        if candidate.exists():
            return candidate
    except (OSError, subprocess.SubprocessError, KeyError, ValueError):
        pass
    return REPO / "target" / "debug" / "asv"


def c14_argv_runs_on_the_real_parser(files: dict[str, str], truth: dict) -> None:
    """The argv arrays the skill teaches must be commands the parser accepts.

    Source-parity proves the array matches `relations.rs`. This proves
    `relations.rs` matches the binary: each published argv is executed in a
    throwaway HOME with no broker, and the only thing asserted is that the
    failure, if any, is a *runtime* failure and never a *parse* failure. A
    renamed subcommand surfaces as `error: unrecognized subcommand`, and a
    skill teaching it fails here even while matching the source perfectly.
    """
    if not _binary().exists():
        _skips.append("c14: no compiled asv at "
                      f"{_binary()}; set ASV_BIN or build the workspace")
        print(f"  SKIP c14: no compiled asv at {_binary()}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        for variant in truth["operational"]:
            argv = truth["argv"].get(variant, [])
            if not argv:
                check(False, f"{variant} has an argv in the source")
                continue
            probe = list(argv) + _completion_for(variant, argv)
            _, out = run_cli(probe, home)
            parse_error = re.search(
                r"unrecognized subcommand|unexpected argument|invalid value|"
                r"error: unexpected|Usage:", out)
            check(parse_error is None,
                  f"`asv {' '.join(probe)}` is a command the parser accepts"
                  if parse_error is None else
                  f"`asv {' '.join(probe)}` does not parse: {out.strip()[:160]}")


#: A vault id, for the same reason `relations.rs` uses one: the argv under test
#: must carry a *reference*, and a placeholder is how that is shown without a
#: real credential existing anywhere near a test.
_PLACEHOLDER_ID = "00000000-0000-4000-8000-000000000000"


def _completion_for(variant: str, argv: list[str]) -> list[str]:
    """What a consumer appends to a published argv before running it.

    The old version of this guard appended `["--", "true"]` to anything that
    was not already a `run` link, which was correct for exactly one shape: a
    template whose payload is free-form positional text. R2.A's GitHub links
    are not that shape — they are complete commands whose every input is a
    named flag — so the blanket completion appended a stray `true` to
    `asv github issue view` and the guard reported a parse failure for a
    command that parses fine. It would equally have appended `true` to
    `asv status --json`, which is not a template at all.

    That is the failure this whole file exists to prevent, in the mirror image:
    not a link that works but is undocumented, but a real command reported as
    broken because the *checker* was wrong. A guard that cries wolf gets
    disabled, and a disabled guard is worth less than the bug it was hiding.

    The shape is read off the argv itself rather than hardcoded per relation,
    so a descriptor that changes shape is completed correctly without this
    function being told.
    """
    if argv and argv[-1] == "--":
        # A template: the payload is the consumer's own words.
        return ["true"]
    if variant.startswith("Github"):
        # A complete command whose every input is a named flag. The credential
        # is a vault *id*, which is the whole claim `asv github` makes.
        common = ["--credential", _PLACEHOLDER_ID]
        if variant == "GithubIssueRead":
            return ["--repo", "owner/repo", "--number", "1", *common]
        if variant == "GithubIssueCreate":
            return ["--repo", "owner/repo", "--title", "a title",
                    "--body", "/dev/null", *common]
        return ["--repo", "owner/repo", "--tag", "v1", "--name", "a name",
                "--body", "/dev/null", *common]
    # Already the whole command.
    return []


def check_truth_is_not_vacuous(truth: dict) -> None:
    """A parse that yields nothing makes every comparison below pass.

    That is the failure mode this whole file exists to avoid, so it gets its
    own function rather than four assertions buried in `main`: a guard about
    vacuity that cannot itself be called is a guard about nothing. It is
    extracted so the falsification harness can call it against a stub source
    and require it to go red.
    """
    rels = truth["rels"]
    operational = truth["operational"]
    argv = truth["argv"]
    codes = set(truth["codes"]) | set(truth["warn_codes"])
    check(len(rels) >= 14, f"parsed {len(rels)} relations from relations.rs")
    # An exact count, not a floor. The number went 6 -> 9 in R2.A when the three
    # GitHub relations were republished against a real command, and a `>=` here
    # would have let the published set grow by any amount without this noticing.
    # The tripwire is also the thing that makes the skill update mandatory: a
    # release cannot pass with a skill that has not caught up.
    check(len(operational) == 9,
          f"parsed {len(operational)} published relations, expected 9")
    check(len(argv) == len(rels) and len(argv) >= 14,
          f"parsed an argv for every relation ({len(argv)} of {len(rels)})")
    check(len(codes) >= 5, f"parsed {len(codes)} error and warning codes")


# ---------------------------------------------------------------------- runner

def main() -> int:
    d = skill_dir()
    print(f"skill: {d}")
    if not (d / "SKILL.md").exists():
        # Not a skip. A release that cannot see the published skill has not
        # published one, and returning 77 made that indistinguishable from a
        # run that passed. The old behaviour meant a machine without a sibling
        # checkout reported "skipped" while the release pipeline read it as
        # "nothing to do here" — which is the exact shape of a gate that can be
        # made green by not having the thing it gates.
        print(f"\nFAIL: no skill at {d}", file=sys.stderr)
        print("  The published skill lives at Rubentxu/agent-skill/skills/agent-secretless.", file=sys.stderr)
        print("  Clone it as a sibling checkout, or set ASV_SKILL_DIR to it.", file=sys.stderr)
        print("  Absence is a failure, not a skip: a release cannot verify a", file=sys.stderr)
        print("  skill it cannot see.", file=sys.stderr)
        return 1

    # The proposal that lives inside this repository is not the product. It is
    # convenient to point this suite at it, and every run would be green, and
    # the green would mean nothing: the thing an agent installs is the copy in
    # the other repository, and that is the copy that can drift.
    try:
        inside_repo = d.is_relative_to(REPO)
    except AttributeError:  # pragma: no cover - Python < 3.9
        inside_repo = str(d).startswith(str(REPO) + os.sep)
    if inside_repo:
        print(f"\nFAIL: {d} is inside this repository", file=sys.stderr)
        print("  That is the proposal, not the published skill. The contract", file=sys.stderr)
        print("  guards the copy an agent installs, which lives at", file=sys.stderr)
        print("  Rubentxu/agent-skill/skills/agent-secretless.", file=sys.stderr)
        return 1

    truth = parse_truth()
    print(f"truth: {len(truth['rels'])} relations declared, "
          f"{len(truth['operational'])} published, "
          f"{len(truth['codes'] | truth['warn_codes'])} codes\n")

    # A vacuous truth would make every comparison below pass.
    check_truth_is_not_vacuous(truth)

    files = read_skill(d)

    print("\n-- scope")
    _documents_exist(files)

    print("\n-- fidelity")
    c1_structure(files)
    c2_frontmatter(files, truth)
    c3_no_invented_rel(files, truth)
    c4_withheld_rels_are_marked(files, truth)
    c5_every_published_rel_is_reachable(files, truth)
    c6_operations_are_real(files, truth)
    c7_argv_arrays_are_real(files, truth)
    c8_codes(files, truth)
    c9_envelope_fields(files, truth)

    print("\n-- conduct")
    c10_no_retrieval_instruction(files)
    c11_no_shell_in_the_prescriptive_path(files)

    print("\n-- progressive disclosure")
    c12_progressive_disclosure(files)

    print("\n-- text hygiene")
    cjk_and_glued(files)

    print("\n-- binary parity")
    c14_argv_runs_on_the_real_parser(files, truth)

    print(f"\n{_passes} checks passed, {len(_failures)} failed, "
          f"{len(_skips)} skipped")
    for f in _failures:
        print(f"  FAILED: {f}")
    for s in _skips:
        print(f"  SKIPPED: {s}")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
