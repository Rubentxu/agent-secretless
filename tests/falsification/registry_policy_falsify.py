#!/usr/bin/env python3
"""Falsification for R2.F.3a: the OCI registry as a policy resource.

Two files, because that is where the increment actually lives. `asv-domain`
supplies the two actions and the `Registry` resource; `asv-policy` maps them onto
Cedar, declares the entity type, supplies its attributes, and decides that the
default policy permits neither. Each mutation is applied on its own, the one row
that is supposed to catch it is run, and the file is restored.

Same five-bucket accounting as the other campaigns in this directory -- red,
compiler-refused, green survivor, measured nothing, and a snippet this harness
could not find, which is a defect in the harness rather than a result about the
code.

**Six mutations, six red, and one row that was written, failed, and was
replaced rather than debugged.** That row is the finding, and it is the fifth
time this repository has paid for it.

`una_autoridad_de_registro_no_puede_escribirse_como_una_mirla` asserted that
`Authority::canonicalize("registry-1.docker.io.evil.example")` fails, on the
reasoning that a suffix mirla is a forgery. It does not fail: that string is a
perfectly valid host and a *different* one, and the row went red the moment it
was run against a real `canonicalize`. The type provides canonical **spelling**
-- one value per host, lowercased, refusing anything that is not a bare host --
and it does **not** provide approval. Treating a different host as a forgery is
the wrong model and would have been the wrong thing to write down next to the
D6 allowlist, which is what actually does the approving.

The row was replaced by
`una_autoridad_de_registro_tiene_una_sola_ortografia_y_es_un_host`, which
asserts the two things that are true: one spelling per host, and nothing that is
not a bare host gets in. The false claim is recorded here rather than deleted,
because the next person to write it will be the next person to have written it
before.

**The mutation to read first is the one that maps a push onto a pull.**
`action_name` is an exhaustive match over `Action`, so a copy-paste there
compiles, validates, and silently makes `registry_push` evaluate as
`registry_pull` -- which, under any policy an operator wrote for reading, turns
a permitted read into a permitted write. Nothing else in the tree would notice:
the schema still declares both actions, the entity is still a `Registry`, and
the audit trail would record the push under a name that says otherwise.
`un_pull_permitido_no_arrastra_al_push` is the row that exists for it, and it is
the only place in this increment where a copy-paste in a one-line match turns
into a privilege.

**The second is dropping the `repository` attribute.** Supplying
`resource.repository` is the whole reason `Registry` is not an `Api`, and the
failure is invisible in the way this file's own history says it is: an operator
whose rule reads `resource.repository == "library/alpine"` would get a permanent
unexplained denial, and the row that catches it is the one that loads the exact
text `POLICY_TEXT` prints.

Run:  python3 registry_policy_falsify.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

POLICY = f.REPO / "crates/policy/src/lib.rs"
DOMAIN = f.REPO / "crates/domain/src/lib.rs"

# The rows added here live at the crate root next to the four that were already
# there, so they carry no module path. `--lib` on `asv-policy` is the target that
# holds them; an integration test file would make every mutation report
# `measured nothing`, which is the bucket for "this harness pointed at the wrong
# place" rather than for "the row did not catch it".
TEST_PREFIX = ""
CARGO_TARGET = "--lib"
PACKAGE = "asv-policy"

ENV = dict(os.environ)

# (label, old, new, test that must go red)
POLICY_MUTATIONS = [
    (
        # The one that is easiest to get wrong by accident. A new provider reads
        # as harmless, and `registry_pull` is the *read* half, so it is the
        # variant most likely to be added to the default policy "to make the
        # thing work". The effect is that every deployment upgrading starts
        # letting every session pull every image its credential reaches, with no
        # operator having decided that. The house rule is the other way round
        # and this row is what holds it: AWS STS, OAuth2 and connect_route all
        # took the same decision.
        "permit a registry pull in the default policy text",
        "// trusting it here.\n//\"#;",
        "// trusting it here.\n//\n"
        'permit (principal, action == Action::"registry_pull", resource is Registry);\n'
        "//\"#;",
        "la_policy_por_defecto_no_permite_nada_sobre_un_registro",
    ),
    (
        # A copy-paste in a one-line exhaustive match: it compiles, the schema
        # still declares both actions, and under any policy written for reading
        # it turns a permitted pull into a permitted push. Nothing in the tree
        # would say so.
        "evaluate a push as if it were a pull",
        '        Action::RegistryPush => "registry_push",',
        '        Action::RegistryPush => "registry_pull",',
        "un_pull_permitido_no_arrastra_al_push",
    ),
    (
        # The attribute is the increment. Drop it and an operator's rule can
        # never match, which is the failure that already shipped once in
        # `Api::audience`: declared in the schema, validated, never supplied.
        "supply the authority under the repository's attribute name",
        '            ("repository", ResourceAttribute::Text(repository.clone())),',
        '            ("repository", ResourceAttribute::Text(authority.to_string())),',
        "la_regla_documentada_de_un_registro_casa_y_solo_con_el_suyo",
    ),
    (
        # The D6 defect the comment on `entity_type` describes, in a different
        # costume: every `resource is Registry` rule becomes vacuously false.
        "type a registry entity as an Api",
        '        Resource::Registry { .. } => "Registry",',
        '        Resource::Registry { .. } => "Api",',
        "la_regla_documentada_de_un_registro_casa_y_solo_con_el_suyo",
    ),
    (
        # Two namespaces, one namespace. A `Registry` holding `acme/app` would
        # render the same uid as a `Repository { owner: acme, name: app }`, and
        # a rule naming one would match whichever the store held.
        "drop the namespace prefix from a registry uid",
        '            format!("registry:{authority}/{repository}")',
        '            format!("{authority}/{repository}")',
        "una_entidad_de_registro_no_se_puede_confundir_con_una_de_repositorio",
    ),
]

DOMAIN_MUTATIONS = [
    (
        # The guarantee the row really is about. Without case folding, an
        # operator who writes `registry-1.docker.io` and a broker that built
        # `REGISTRY-1.DOCKER.IO` get two values, and the allowlist comparison
        # becomes a spelling lottery rather than an allowlist.
        "stop lowercasing an authority",
        "            labels.push(label.to_ascii_lowercase());",
        "            labels.push(label.to_string());",
        "una_autoridad_de_registro_tiene_una_sola_ortografia_y_es_un_host",
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> dict:
    """Apply each mutation to one file and tally the five buckets.

    A snippet this harness cannot find exactly once is a defect in the harness,
    not a result about the code, and it has its own bucket for that reason.
    """
    original = path.read_text()
    buckets = {
        "red": 0,
        "compiler-refused": 0,
        "green (SURVIVOR)": 0,
        "measured nothing": 0,
        "harness error": 0,
    }
    problems: list = []
    for label, old, new, test in mutations:
        if original.count(old) != 1:
            buckets["harness error"] += 1
            problems.append(
                (label, test, f"snippet counts {original.count(old)}, want 1 -- harness defect")
            )
            print(f"SKIP  {label!r}: snippet is not unique ({original.count(old)})", flush=True)
            continue
        path.write_text(original.replace(old, new, 1))
        try:
            verdict, out = f.run_test(test)
        finally:
            path.write_text(original)
        if verdict == "red":
            buckets["red"] += 1
            print(f"ok    [{title}] {label}\n      -> {test} went red", flush=True)
        elif verdict == "green":
            buckets["green (SURVIVOR)"] += 1
            problems.append((label, test, "the row stayed green"))
            print(
                f"SURVIVOR  [{title}] {label}\n      -> {test} stayed GREEN  <-- the finding",
                flush=True,
            )
        elif verdict == "refused":
            buckets["compiler-refused"] += 1
            first = next(
                (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
            )
            print(
                f"ok*   [{title}] {label}\n      -> {test}: refused by the compiler\n         {first}",
                flush=True,
            )
        else:
            buckets["measured nothing"] += 1
            problems.append((label, test, verdict))
            print(f"BAD   [{title}] {label}\n      -> {test}: {verdict}", flush=True)
    assert path.read_text() == original, f"{path} was not restored"
    assert sum(buckets.values()) == len(mutations), (buckets, len(mutations))
    return buckets


def main() -> int:
    f.CARGO_TARGET = CARGO_TARGET
    f.PACKAGE = PACKAGE
    f.TEST_PREFIX = TEST_PREFIX
    f.MUTATIONS[:] = POLICY_MUTATIONS + DOMAIN_MUTATIONS

    total = len(POLICY_MUTATIONS) + len(DOMAIN_MUTATIONS)
    print(f"# falsifying R2.F.3a with {total} mutations across 2 files\n")

    tally = {}
    problems = []
    for index, (path, mutations, title) in enumerate(
        [
            (POLICY, POLICY_MUTATIONS, "R2.F.3a the policy layer"),
            (DOMAIN, DOMAIN_MUTATIONS, "R2.F.3a the authority spelling"),
        ],
        start=1,
    ):
        print(f"## phase {index} -- {title} ({path.relative_to(f.REPO)})")
        tally[title] = run_phase(path, mutations, title)
        problems += [
            p
            for p in []
        ]
        print()

    merged = {}
    for buckets in tally.values():
        for key, value in buckets.items():
            merged[key] = merged.get(key, 0) + value
    assert sum(merged.values()) == total, (merged, total)

    print(f"mutations: {total}  (the five buckets partition the run)")
    for name, count in merged.items():
        print(f"  {name:<22}: {count}")
    print()
    for title, buckets in tally.items():
        line = ", ".join(f"{k}={v}" for k, v in buckets.items() if v)
        print(f"  {title}: {line or 'none'}")

    for label, test, why in problems:
        print(f"\nFINDING: {label}\n  test: {test}\n  {why}")
    return 1 if merged["green (SURVIVOR)"] or merged["harness error"] or merged["measured nothing"] else 0


if __name__ == "__main__":
    sys.exit(main())
