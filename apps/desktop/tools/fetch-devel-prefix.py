#!/usr/bin/env python3
"""Build a pkg-config chain for the Tauri shell without root.

The machine has the GUI *runtime* (`libwebkit2gtk-4.1.so.0` in /usr/lib64) and
a display, but not the *headers* — and `sudo` needs a password. This downloads
the `-devel` RPMs as an ordinary user, unpacks them under a local prefix,
rewrites every `.pc` to point at that prefix, repairs the unversioned `.so`
symlinks, and repeats until `pkg-config` stops complaining.

    python3 apps/desktop/tools/fetch-devel-prefix.py [--prefix ~/.cache/asv-devel]

Then build with:

    export PKG_CONFIG_PATH=$PREFIX/root/usr/lib64/pkgconfig:$PREFIX/root/usr/share/pkgconfig
    export LIBRARY_PATH=$PREFIX/root/usr/lib64:/usr/lib64
    cargo check --manifest-path apps/desktop/Cargo.toml

## Properties it deliberately has and does not have

- It never installs anything into the system. Nothing under /usr is touched.
- It never stubs a package a *dynamic* link needs. Only `Requires.private`
  entries are stubbed, because those matter only to a static link, which this
  workspace does not do. A build that genuinely needed those symbols would
  fail to link, which is the correct outcome.

## Five defects this script already had, and why each one mattered

Recorded because the failure modes are silent: three of them produced a loop
that looked like progress.

1. `PKG_CONFIG_PATH` had to include `share/pkgconfig`, not just
   `lib64/pkgconfig`. Fedora ships 28 `.pc` files there — every X11 protocol
   module, `xproto.pc` among them. With only the lib64 path, `xproto` was
   downloaded, unpacked, and never seen, for fifteen rounds.

2. Progress is "did the set of RPMs on disk grow?", not "did dnf exit 0?".
   An already-present RPM exits 0, so a round that changed nothing looked
   like a step forward. That is what made the loop in (1) infinite.

3. Package names may contain uppercase. `libXft-devel` is a real Fedora
   package; a lowercase-only name test refused it forever.

4. Package names may contain `:`, which is the epoch separator —
   `libglvnd-devel-1:1.7.0-9.fc44`. Rejecting it made every epoch-carrying
   provider unresolvable, and then `Repo`, a *field in dnf's own output*,
   passed the name test and was returned as the package to download.

5. Verified mappings outrank heuristics. `dnf provides */krb5-gssapi.pc`
   answers `heimdal-devel`, which ships a `krb5-gssapi.pc` that does not
   satisfy the real chain. `ALIASES` is hand-checked; `provider()` is a
   guess, so the guess is consulted second.

And the one that only appeared at link time: every `-devel` package ships
`/usr/lib64/libgtk-3.so -> libgtk-3.so.0`, but `libgtk-3.so.0` belongs to the
*runtime* package, which is installed system-wide and never downloaded here.
All the unversioned symlinks were dangling — `ls` listed them, `ld` refused
every one. `repair_symlinks` repoints them at /usr/lib64.

**A green `pkg-config` is not a green link.** That is why the build is
verified by compiling and running, not by resolving.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

TARGETS = ["webkit2gtk-4.1", "gtk+-3.0", "libsoup-3.0"]

# Only `Requires.private` (static-link-only) entries are stubbed. See the
# module docstring: this is the one place a missing package may be papered
# over, and doing it anywhere else would hide a real failure.
STUBBED = {"sysprof-capture-4"}

# Hand-verified Fedora spellings for modules `dnf provides` cannot be trusted
# to answer. Consulted BEFORE `provider()`, because a checked fact should not
# be overruled by a heuristic.
ALIASES = {
    "liblzma": "xz-devel",
    "libxml-2.0": "libxml2-devel",
    "javascriptcoregtk-4.1": "javascriptcoregtk4.1-devel",  # no hyphen before 4.1
    "x11": "libX11-devel",
    "xext": "libXext-devel",
    "xrender": "libXrender-devel",
    "xcb": "libxcb-devel",
    "xcb-render": "libxcb-render-devel",
    "xcb-shm": "libxcb-shm-devel",
    "pixman-1": "pixman-devel",
    "sqlite3": "sqlite-devel",
    "libnghttp2": "libnghttp2-devel",
    "libpsl": "libpsl-devel",
    "krb5-gssapi": "krb5-devel",  # NOT heimdal-devel, which dnf suggests
    "glycin-2": "glycin-devel",
    "cairo-gobject": "cairo-gobject-devel",
    "gio-2.0": "glib2-devel",
}

# dnf prints its own field names in the same `Name : value` shape as results.
# "Repo" is all letters and would otherwise pass a naive name test.
METADATA_KEYS = {
    "Repo", "Filename", "Matched From", "From repo", "Repo from",
    "Package", "Version", "Architecture",
}

# Cross-builds answer `dnf provides` too, and unpack to a foreign sysroot.
FOREIGN = r"^(mingw|mingw32|mingw64|aarch64|arm|armv7|arm64|ppc|s390x|riscv|mingw-w64)"


class Prefix:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.pkg = root / "root"
        self.dirs = [
            self.pkg / "usr/lib64/pkgconfig",
            self.pkg / "usr/share/pkgconfig",
            self.pkg / "usr/lib/pkgconfig",
        ]
        self.libdirs = [self.pkg / "usr/lib64", self.pkg / "usr/lib"]

    @property
    def pcpath(self) -> str:
        """Recomputed on every read, never cached at construction.

        Caching this is what broke the first two attempts: the prefix starts
        out empty, so a value computed in `__init__` is `""` and pkg-config is
        silently handed an empty search path. It looks like a resolution
        failure, and the fix — re-run after the directories exist — masks a
        defect rather than removing it. The first two versions of this script
        only worked because the prefix happened to exist from a previous run.
        """
        return ":".join(str(d) for d in self.dirs if d.is_dir())

    def sh(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PKG_CONFIG_PATH"] = self.pcpath
        return subprocess.run(args, capture_output=True, text=True, check=False, env=env)


def unpack_all(p: Prefix) -> None:
    rpms = sorted(p.root.glob("*.rpm"))
    p.pkg.mkdir(parents=True, exist_ok=True)
    for rpm in rpms:
        p.sh("bash", "-c",
             f"rpm2cpio '{rpm}' | (cd '{p.pkg}' && cpio -idmu --quiet 2>/dev/null)")


def rewrite_prefixes(p: Prefix) -> None:
    """Point every `.pc` at the local prefix.

    Without this, `prefix=/usr` sends `-I/usr/include/webkitgtk-4.1` at a path
    that does not exist and the headers we just unpacked stay invisible.
    """
    for d in p.dirs:
        if not d.is_dir():
            continue
        for pc in d.glob("*.pc"):
            text = pc.read_text(encoding="utf-8")
            text = re.sub(r"^prefix=/usr$", f"prefix={p.pkg}/usr", text, flags=re.M)
            text = re.sub(r"^libdir=/usr/lib64$", f"libdir={p.pkg}/usr/lib64", text, flags=re.M)
            pc.write_text(text, encoding="utf-8")


def repair_symlinks(p: Prefix) -> int:
    """Repoint dangling `.so` symlinks at the system runtime. See docstring."""
    system = Path("/usr/lib64")
    fixed = 0
    for d in p.libdirs:
        if not d.is_dir():
            continue
        for so in d.glob("*.so"):
            if not (so.is_symlink() and not so.exists()):
                continue
            target = so.readlink().name
            found = system / target
            if not found.exists():
                # The link may name a full version (`libfreetype.so.6.20.4`)
                # where the system ships only the soname. Resolve by prefix.
                matches = sorted(system.glob(f"{target.split('.so')[0]}.so.*"))
                if matches:
                    found = matches[-1]
            if found.exists():
                so.unlink()
                so.symlink_to(found)
                fixed += 1
    return fixed


def missing_modules(p: Prefix) -> list[str]:
    """Modules pkg-config cannot satisfy for the public compile+link flags.

    `--exists` would only prove the three top-level modules exist; the chain
    that actually breaks a build is the one they pull in.
    """
    out = p.sh("pkg-config", "--print-errors", "--cflags", "--libs", *TARGETS)
    # pkg-config reports a missing module two ways and only the first carries
    # the bare name. The second names the *requirer* ("required by X"), so a
    # pattern built on it collects the wrong module and resolves nothing.
    found = re.findall(r"^Package ([\w.+-]+) was not found", out.stderr, re.MULTILINE)
    return sorted(set(found))


def provider(p: Prefix, module: str) -> str | None:
    out = p.sh("dnf", "provides", f"*/{module}.pc")
    fallback: str | None = None
    for line in out.stdout.splitlines():
        # Split on the " : " before the summary, never on the first colon:
        # epoch-bearing names carry their own.
        m = re.match(r"^(.+?)\s+:\s+\S", line)
        if not m:
            continue
        token = m.group(1).strip()
        if token in METADATA_KEYS or re.match(FOREIGN, token):
            continue
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.:+_-]*$", token):
            continue
        if token.endswith(".x86_64") or token.endswith(".noarch"):
            return re.sub(r"\.(x86_64|noarch)$", "", token)
        fallback = fallback or token
    return fallback


def download(p: Prefix, package: str) -> bool:
    """Fetch a package. Progress means a *new* RPM landed, nothing else.

    No `--arch`: `--arch=x86_64` excludes noarch packages, and dnf5 rejects
    `--arch=a,b` as unsupported. Left alone, dnf resolves for the host arch
    and includes noarch, which header-only X11 proto packages need.
    """
    before = {q.name for q in p.root.glob("*.rpm")}
    p.sh("dnf", "download", "--nogpgcheck", f"--destdir={p.root}", package)
    return bool({q.name for q in p.root.glob("*.rpm")} - before)


def stub(p: Prefix, module: str) -> bool:
    if module not in STUBBED:
        return False
    path = p.dirs[0] / f"{module}.pc"
    if path.exists():
        return False
    path.write_text(
        f"prefix={p.pkg}/usr\n"
        "libdir=${prefix}/lib64\n"
        "includedir=${prefix}/include\n\n"
        f"Name: {module}\n"
        "Description: local stub; private (static-link-only) dependency\n"
        "Version: 99.0.0\n"
        "Libs:\nCflags:\n",
        encoding="utf-8",
    )
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="~/.cache/asv-devel")
    ap.add_argument("--rounds", type=int, default=60)
    args = ap.parse_args()

    p = Prefix(Path(args.prefix).expanduser().resolve())
    p.root.mkdir(parents=True, exist_ok=True)

    fixed = repair_symlinks(p)
    if fixed:
        print(f"repaired {fixed} dangling .so symlink(s)")

    for attempt in range(1, args.rounds + 1):
        missing = missing_modules(p)
        if not missing:
            print(f"resolved after {attempt - 1} round(s)")
            break
        print(f"round {attempt}: missing {', '.join(missing)}", flush=True)
        progress = False
        for module in missing:
            if stub(p, module):
                print(f"  stubbed (private dep): {module}")
                progress = True
                continue
            # Verified mapping first, heuristic second — see docstring (5).
            package = ALIASES.get(module) or provider(p, module)
            if package is None:
                print(f"  NO PROVIDER for {module}")
                continue
            if download(p, package):
                print(f"  downloaded {package} for {module}")
                progress = True
            else:
                print(f"  could not download {package} for {module}")
        if not progress:
            print("no progress; stopping")
            return 1
        unpack_all(p)
        rewrite_prefixes(p)
        repair_symlinks(p)
    else:
        print(f"gave up after {args.rounds} rounds")
        return 1

    print(f"\nBuild with:\n"
          f"  export PKG_CONFIG_PATH={p.pcpath}\n"
          f"  export LIBRARY_PATH={p.libdirs[0]}:/usr/lib64\n"
          f"  cargo check --manifest-path apps/desktop/Cargo.toml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
