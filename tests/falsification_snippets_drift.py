#!/usr/bin/env python3
"""Every falsification mutation must still name code the repository has.

Six mutations across three harnesses under `tests/falsification/` were found
and repaired by hand, and each was caused by an ordinary refactor -- a private
test seam, a closure replacing a comma expression, a tuple spreading onto its
own lines -- with each one naming a snippet of production source that no longer
existed in that shape.

A falsification harness is not a gate. It runs when somebody remembers to run
it, which is exactly what did not happen, and its exit code had no reader. The
harnesses themselves were never wrong about the failure: a snippet that does not
match lands in its own bucket rather than being reported as a survivor, and
`registry_falsify.py`'s docstring records that an earlier version got that
wrong. The detection was right; nothing was reading it.

This is the instrument that would have caught them at the time. It reads every
harness, pulls out the code each mutation intends to replace, and checks that
it still exists somewhere in the repository's Rust sources. It runs in
milliseconds and launches no cargo, which is the only reason it would ever be
run by anything.

**It is red, and that is the finding.** On the tree this was written against it
reports 28 further mutations across 11 harnesses that measure nothing, none of
which the hand sweep that found the first six had seen. The hand sweep matched
multi-line string literals and therefore skipped every mutation whose `old` is
a single line -- which, as `OLD_INDEX` records, is most of them. A check written
by reading the harnesses missed two thirds of what it was looking for.

What counts as a defect
-----------------------

A snippet that appears **nowhere** is a defect: the mutation cannot be applied,
so the row it guards is unmeasured. That is the case that is invisible until
someone spends minutes running the harness.

A snippet that appears **more than once** is deliberately not reported. It may
be ambiguous for one particular target file, but the harness resolves that
itself, by counting occurrences in the file it declared, and it already buckets
the result. Reporting it here would be a false positive: the search here is over
the whole tree rather than over the declared target, and a real run of
`identity_falsify.py` measures all three of its modes with nothing unmeasured
while this check sees one of its snippets twice.

Why `ast` and not a pattern
---------------------------

A mutation's snippet is routinely split across several string literals, and
Python concatenates adjacent ones. `&[(SESSION_TOKEN_HEADER, ...` in
`identity_falsify.py` is three literals whose value is one snippet; matching the
literals individually would invent a fragment that never existed in the source
and report it as stale. Parsing gives the constant as written.

Run: python3 tests/falsification_snippets_drift.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HARNESSES = REPO / "tests" / "falsification"
CRATES = REPO / "crates"

#: Below this, a multi-line constant is far more likely to be an argument to a
#: command than a span of source to be mutated.
MIN_SNIPPET = 25


#: Where the code-to-be-replaced sits in each tuple shape these harnesses use.
#: Position, not content: `old` is frequently a single line while `new` is a
#: multi-line rewrite, so "the first multi-line element" picks the replacement
#: and reports every one of them as stale.
OLD_INDEX = {2: 0, 3: 1, 4: 1}


def snippets_in(harness: str) -> list[str]:
    """The `old` side of every mutation in `harness` -- the code it must find.

    Only the text a mutation *replaces* can be stale in the sense that matters.
    The text it writes is absent from the source by definition, so checking it
    would report every mutation in the tree as broken. These harnesses use
    `(old, new)` for multi-snippet mutations and `(label, old, new, test)`
    otherwise, 430 of the latter; `OLD_INDEX` names the position in each.

    Adjacent literals are concatenated by the parser before this sees them,
    which is the whole reason this walks the AST rather than matching text: the
    `SESSION_TOKEN_HEADER` snippet is three literals whose value is one snippet,
    and matching the literals individually would invent a fragment that never
    existed in the source.

    Docstrings are excluded, and excluding them is not a detail. A harness
    opens with a long prose description of what it falsifies, and every module,
    class and function in these files carries one. Counting those put 235
    phantom stale snippets across 31 harnesses -- a sweep reporting almost
    everything broken on a tree where three harnesses had just been run end to
    end with nothing unmeasured. Prose is not code to be mutated.

    A short `old` is skipped rather than guessed at. That is a false negative,
    which is the right way for this check to be wrong.
    """
    try:
        tree = ast.parse(harness)
    except SyntaxError:
        return []

    docs: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    docs.add(id(body[0].value))

    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Tuple, ast.List)) or len(node.elts) < 2:
            continue
        strings = [
            e.value
            for e in node.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str) and id(e) not in docs
        ]
        if len(strings) != len(node.elts):
            continue
        index = OLD_INDEX.get(len(strings))
        if index is None:
            continue
        value = strings[index]
        if len(value) >= MIN_SNIPPET:
            out.append(value)
    return out


def stale_snippets(harness_text: str, sources: dict[str, str]) -> list[str]:
    """Snippets the harness names that no source file in `sources` contains."""
    missing: list[str] = []
    for snippet in snippets_in(harness_text):
        if not any(snippet in text for text in sources.values()):
            missing.append(snippet)
    return missing


def read_sources(root: Path = CRATES) -> dict[str, str]:
    return {str(p): p.read_text(encoding="utf-8") for p in root.rglob("*.rs")}


def read_harnesses(root: Path = HARNESSES) -> dict[str, str]:
    return {str(p): p.read_text(encoding="utf-8") for p in sorted(root.glob("*_falsify.py"))}


def scan(harness_text: str, sources: dict[str, str]) -> tuple[bool, str]:
    missing = stale_snippets(harness_text, sources)
    if not missing:
        return True, "no snippet is stale"
    shown = ", ".join(repr(m.splitlines()[0][:60]) for m in missing[:3])
    return False, f"{len(missing)} snippet(s) measure nothing: {shown}"


# ------------------------------------------------------------------ cases
#
# A guard written after the fact and never shown able to fail establishes
# nothing about its own green result, so each case below is a synthetic harness
# with exactly one thing wrong.


def _harness(snippet: str, replacement: str) -> str:
    return (
        'MUTATIONS = [\n'
        '    (\n'
        '        "a label",\n'
        f'        {snippet!r},\n'
        f'        {replacement!r},\n'
        '        "a_row_that_must_go_red",\n'
        '    ),\n'
        ']\n'
    )


def main() -> int:
    if not HARNESSES.is_dir():
        print(f"FAIL harness directory not found: {HARNESSES}")
        return 1

    sources = read_sources()
    harnesses = read_harnesses()

    # A realistic snippet, and the source that contains it.
    live = "        let resolved = resolve_and_pin(&audience, port, policy)?;"
    source_with_it = {"src.rs": "fn vet() {\n" + live + "\n}\n"}

    results: list[tuple[str, bool, str]] = []

    # 1. The clean case: every snippet resolves.
    ok, out = scan(_harness(live + "\n", "        let resolved = hardcoded;"), source_with_it)
    results.append(("a harness whose snippets all resolve passes", ok, out))

    # 2. The defect: a refactor renamed the binding the snippet named.
    ok, out = scan(
        _harness("        let resolved = resolve_and_pin(&authority, TOKEN_PORT, policy)?;\n",
                 "        let resolved = ResolvedAudience { authority: authority.clone(), port: TOKEN_PORT, addresses: vec![] };\n"),
        source_with_it,
    )
    results.append(("a snippet naming a refactored binding is a defect", not ok, out))

    # 3. A snippet split across adjacent literals is one snippet, not three.
    #    This is the case a text pattern gets wrong in both directions.
    concatenated = (
        'MUTATIONS = [\n'
        '    (\n'
        '        "a label",\n'
        '        "        if let Some(named) = url.port() {\\n"\n'
        '        "            if named != port {\\n",\n'
        '        "        if let Some(named) = url.port() {\\n"\n'
        '        "            if false {\\n",\n'
        '        "a_row",\n'
        '    ),\n'
        ']\n'
    )
    ok, out = scan(
        concatenated,
        {"src.rs": "fn vet() {\n        if let Some(named) = url.port() {\n            if named != port {\n                return Err(());\n            }\n        }\n}\n"},
    )
    results.append(("adjacent literals are one snippet, not three fragments", ok, out))

    # 4. Ambiguity is not staleness. The snippet exists in two files; the
    #    harness counts in its declared target and this guard does not know
    #    which that is, so reporting it would be inventing a defect.
    ok, out = scan(
        _harness(live + "\n", "        let resolved = hardcoded;"),
        {"a.rs": live + "\n", "b.rs": live + "\n"},
    )
    results.append(("a snippet present in two files is not reported here", ok, out))

    # 5. A short multi-line constant is an argument, not source to mutate.
    ok, out = scan(_harness("  --locked\n", "  --offline\n"), {})
    results.append(("a short command argument is not treated as a snippet", ok, out))

    # 6. The real repository, which is the only case that says anything about it.
    total_missing = 0
    detail: list[str] = []
    for path, text in harnesses.items():
        missing = stale_snippets(text, sources)
        total_missing += len(missing)
        for snippet in missing:
            detail.append(f"{Path(path).name}: {snippet.splitlines()[0][:70]!r}")
    results.append((
        f"every harness in {HARNESSES.relative_to(REPO)} names code that exists",
        total_missing == 0,
        f"{len(harnesses)} harnesses, {total_missing} stale" + (f" -- {'; '.join(detail[:5])}" if detail else ""),
    ))

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail_text in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"          {detail_text}")

    print(f"\n{passed}/{len(results)} behaviours confirmed")
    if not sources:
        print("FAIL no Rust sources found; the sweep would pass on an empty tree")
        return 1
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())