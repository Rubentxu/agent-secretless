#!/usr/bin/env python3
"""Falsification for R2.F.3b's registry declaration (the allowlist itself).

One file. Every row here asserts something about *which registries a deployment
can reach*, which is the property the policy layer deliberately does **not**
enforce: `POLICY_TEXT` in `asv-policy` says out loud that `Resource::Registry`
is outside `ALLOWED_AUDIENCES` and that the reachable set comes from operator
configuration. That sentence is only true because of this module, so a row that
did not falsify it would be testing a comment.

Same five-bucket accounting as the other campaigns here -- red,
compiler-refused, green survivor, measured nothing, and a snippet this harness
could not find, which is a defect in the harness rather than a result about the
code.

**Six mutations, six red, and one row that was written wrong and had to be
replaced rather than debugged.** It is the third time in this repository that a
row asserted a property the type under it does not have, and the first two are
both about `Authority`, which is why this one is recorded at length below.

The row `una_declaracion_que_no_es_un_host_puro_se_rechaza` originally listed
`registry-1.docker.io.evil.example` among the strings that must be refused. It
is not refused, and it must not be: **the registry in this file is operator
text.** A self-hosted Artifactory at `registry.internal.example` is precisely
the case the file exists for, because enumerating registries is the list nobody
maintains. A suffix rule aimed at the operator would make a large fraction of
real deployments undeployable, and it would have been me deciding that a
deployment someone else runs is a forgery.

The property that actually matters is the opposite direction and lives in the
lookup: a *request* naming the mirla must not be served the credential declared
for the real registry. That is `ni_una_mirla_ni_un_sufijo_de_un_registry_declarado_lo_alcanza`,
and it is the row that carries the D6 property. The replacement row,
`un_registry_autohospedado_se_declara_y_solo_responde_por_el_mismo`, pins the
positive half: a self-hosted registry is declared, and answers only for itself.

**The mutation to read first is `ends_with`.** It is the shape the whole D6
allowlist exists to refuse, it compiles, it is one character, and every row that
asks "did this registry answer?" still passes when only the real registry is
declared. It becomes exploitable the moment a deployment declares two
registries whose names share a suffix, which is the ordinary case for anyone
running both `registry-1.docker.io` and `registry.internal.example`, and it is
a credential handed to the wrong host.

**The second is keeping both entries of a duplicate.** `dos_credenciales_para_
un_registry_se_rechusan_al_cargar` refuses a file that declares one registry
twice, because a registry with two credentials is not a deployment, it is a
coin toss whose outcome is the order of a JSON array. Letting the lookup take
the first compiles, passes every other row in this file, and means which secret
a pull spends is invisible to the operator who wrote the file.

Run:  python3 registry_declaration_falsify.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

MODULE = f.REPO / "crates/broker/src/registry_declaration.rs"

# The rows are at the crate root of the module's own `mod tests`, so they carry
# a module path -- unlike the four top-level rows `sts_falsify.py` was written
# against.
TEST_PREFIX = "registry_declaration::tests::"
CARGO_TARGET = "--lib"
PACKAGE = "asv-broker"

ENV = dict(os.environ)

# (label, old, new, test that must go red)
MUTATIONS = [
    (
        # The D6 defect, one character. Every other row asks "did this registry
        # answer?", and with one declaration declared they all still pass.
        "match a registry by suffix rather than by equality",
        "            .find(|entry| &entry.authority == registry)",
        "            .find(|entry| entry.authority.as_str().ends_with(registry.as_str()))",
        "ni_una_mirla_ni_un_sufijo_de_un_registry_declarado_lo_alcanza",
    ),
    (
        # The coin toss. Loads cleanly, passes every row that asks what a
        # declared registry answers, and spends whichever secret the file
        # happened to list first.
        "keep both credentials for a duplicated registry and take the first",
        "        if entries\n"
        "            .iter()\n"
        "            .any(|existing| existing.authority == authority)\n"
        "        {\n"
        "            return Err(DeclarationError::Duplicate {\n"
        "                registry: authority.to_string(),\n"
        "            });\n"
        "        }",
        "        let _ = &authority;",
        "dos_credenciales_para_un_registry_se_rechusan_al_cargar",
    ),
    (
        # The plausible-looking one: a validator that accepts something the
        # comparer would treat as a different host is a declaration that loads
        # and is then unreachable, or worse, reachable under the wrong name.
        "accept a registry spelled as a URL",
        "        let authority = Authority::canonicalize(&entry.registry).map_err(|error| {",
        "        let authority = Authority::canonicalize(\n"
        "            entry.registry.trim_start_matches(\"https://\").trim_end_matches('/'),\n"
        "        ).map_err(|error| {",
        "una_declaracion_que_no_es_un_host_puro_se_rechaza",
    ),
    (
        # The invariant every other row is vacuous without: a lookup over an
        # always-empty set would answer `None` to everything and the
        # "declares and answers" row would pass.
        "load no declarations at all",
        "    Ok(RegistryDeclarations { entries })",
        "    entries.clear();\n    Ok(RegistryDeclarations { entries })",
        "un_registry_autohospedado_se_declara_y_solo_responde_por_el_mismo",
    ),
    (
        # The control itself. `credential_for` returning `Some` unconditionally
        # would make every reachability row pass and the allowlist decorative.
        "answer for whatever registry is asked, declared or not",
        "    pub fn credential_for(&self, registry: &Authority) -> Option<&CredentialId> {\n"
        "        self.entries\n"
        "            .iter()\n"
        "            .find(|entry| &entry.authority == registry)\n"
        "            .map(|entry| &entry.credential)\n"
        "    }",
        "    pub fn credential_for(&self, _registry: &Authority) -> Option<&CredentialId> {\n"
        "        self.entries.first().map(|entry| &entry.credential)\n"
        "    }",
        "un_registry_declarado_responde_y_uno_sin_declarar_no",
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> dict:
    """Apply each mutation and tally the five buckets.

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
    f.MUTATIONS[:] = MUTATIONS

    total = len(MUTATIONS)
    print(f"# falsifying the registry declaration with {total} mutations\n")
    print(f"## phase 1 -- the allowlist ({MODULE.relative_to(f.REPO)})")
    buckets = run_phase(MODULE, MUTATIONS, "R2.F.3b the declaration")
    print()

    print(f"mutations: {total}  (the five buckets partition the run)")
    for name, count in buckets.items():
        print(f"  {name:<22}: {count}")
    print()
    print(
        "  R2.F.3b the declaration: "
        + (", ".join(f"{k}={v}" for k, v in buckets.items() if v) or "none")
    )
    return (
        1
        if buckets["green (SURVIVOR)"] or buckets["harness error"] or buckets["measured nothing"]
        else 0
    )


if __name__ == "__main__":
    sys.exit(main())