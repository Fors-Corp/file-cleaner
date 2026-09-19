"""Generator for tests/safety_cases.json.

The committed JSON is the source of truth that the tests (and any port) read;
this only saves typing ~370 rows by hand. After changing a deny-list in
``safety.py``, re-run it from the repository root and review the diff:

    PYTHONPATH=src python tools/gen_safety_cases.py

``tests/test_safety.py::test_table_covers_every_deny_entry`` fails if a deny
entry is added without regenerating.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, "src")
from filecleaner import safety  # noqa: E402

NFC = "é"  # é, precomposed
NFD = "é"  # e + combining acute

dirs: list[str] = []
symlinks: list[dict[str, str]] = []
cases: list[dict[str, object]] = []


def case(group: str, path: str, protected: bool, note: str = "", **extra: object) -> None:
    row: dict[str, object] = {"group": group, "path": path, "protected": protected}
    if note:
        row["note"] = note
    row.update(extra)
    cases.append(row)


def swap(s: str) -> str:
    return s.swapcase()


CI = {"requires": "case-insensitive-fs"}

# --- absolute deny paths ---------------------------------------------------
for i, deny in enumerate(safety.ABSOLUTE_DENY_PATHS):
    case("absolute/exact", deny, True)
    case("absolute/child", f"{deny}/some/child", True)
    case("absolute/case-variant", f"{deny.lower()}/child", True, "all-lowercase spelling")
    case("absolute/case-variant", f"{deny.upper()}/child", True, "all-uppercase spelling")
    case("absolute/case-variant", f"{swap(deny)}/child", True, "swapped-case spelling")
    case("absolute/boundary", f"{deny}x/child", False, "shares a string prefix but is a sibling")
    link = f"{{TMP}}/links/abs_{i}"
    symlinks.append({"link": link, "target": deny})
    case("absolute/symlink-into", f"{link}/child", True, f"symlink -> {deny}")

# --- relative deny subpaths under a (fake) mounted volume -------------------
dirs.append("{VOLUMES}/Ext")
for i, sub in enumerate(safety.RELATIVE_DENY_SUBPATHS):
    case("volume/exact", f"{{VOLUMES}}/Ext/{sub}", True)
    case("volume/child", f"{{VOLUMES}}/Ext/{sub}/child", True)
    case("volume/case-variant", f"{{VOLUMES}}/Ext/{sub.lower()}/child", True)
    case("volume/case-variant", f"{{VOLUMES}}/Ext/{sub.upper()}/child", True)
    case("volume/case-variant", f"{{VOLUMES}}/ext/{swap(sub)}/child", True, "volume name case-varied too")
    case("volume/boundary", f"{{VOLUMES}}/Ext/{sub}x/child", False)
    dirs.append(f"{{VOLUMES}}/Ext/{sub}")
    link = f"{{TMP}}/links/vol_{i}"
    symlinks.append({"link": link, "target": f"{{VOLUMES}}/Ext/{sub}"})
    case("volume/symlink-into", f"{link}/child", True, f"symlink -> Ext/{sub}")
case("volume/ordinary", "{VOLUMES}/Ext/Users/me/file.txt", False)
case("volume/ordinary", "{VOLUMES}/Ext/Library/Caches/x", False)
case("volume/root", "{VOLUMES}/Ext", False, "a volume root itself is not denied, only OS subpaths")
case(
    "volume/not-mounted",
    "{VOLUMES}/NotMounted/System/x",
    False,
    "volume roots are enumerated from the volumes dir; an absent one contributes no rules",
)
# a volume whose entry in the volumes dir is a symlink (like '/Volumes/Macintosh HD' -> '/')
dirs.append("{TMP}/fakeroot/System")
symlinks.append({"link": "{VOLUMES}/BootAlias", "target": "{TMP}/fakeroot"})
case("volume/symlinked-root", "{TMP}/fakeroot/System/x", True, "root resolved through the volume symlink")
case("volume/symlinked-root", "{TMP}/fakeroot/SYSTEM/x", True)
case("volume/symlinked-root", "{VOLUMES}/BootAlias/usr/x", True)
case("volume/symlinked-root", "{TMP}/fakeroot/Users/x", False)
# non-ASCII volume name, created NFC, addressed NFD
dirs.append(f"{{VOLUMES}}/Donn{NFC}es")
case("volume/unicode", f"{{VOLUMES}}/Donn{NFC}es/System/x", True, "NFC spelling")
case("volume/unicode", f"{{VOLUMES}}/Donn{NFD}es/System/x", True, "NFD spelling of the same volume")
case("volume/unicode", f"{{VOLUMES}}/DONN{NFD.upper()}ES/system/x", True, "NFD + case-varied")
case("volume/unicode", f"{{VOLUMES}}/Donn{NFD}es/Users/x", False)

# --- home deny subpaths ------------------------------------------------------
# {HOME} is a sandbox home whose own name is non-ASCII (created NFC).
for i, sub in enumerate(safety.HOME_DENY_SUBPATHS):
    dirs.append(f"{{HOME}}/{sub}")
    case("home/exact", f"{{HOME}}/{sub}", True)
    case("home/child", f"{{HOME}}/{sub}/child", True)
    case("home/case-variant", f"{{HOME}}/{sub.lower()}/child", True)
    case("home/case-variant", f"{{HOME}}/{sub.upper()}/child", True)
    case("home/case-variant", f"{{HOME_SWAPCASE}}/{swap(sub)}/child", True, "home dir case-varied too")
    case("home/nfd", f"{{HOME_NFD}}/{sub}/child", True, "home dir spelled NFD")
    case("home/nfd", f"{{HOME_NFD}}/{sub.upper()}/child", True, "NFD + case-varied")
    case("home/boundary", f"{{HOME}}/{sub}x/child", False)
    link = f"{{TMP}}/links/home_{i}"
    symlinks.append({"link": link, "target": f"{{HOME}}/{sub}"})
    case("home/symlink-into", f"{link}/child", True, f"symlink -> ~/{sub}")
    case("home/symlink-into", f"{{TMP}}/LINKS/HOME_{i}/child", True, "case-varied symlink name", **CI)
case("home/itself", "{HOME}", True, "the home directory itself is never a candidate")
case("home/itself", "{HOME}/", True, "trailing slash")
case("home/itself", "{HOME_SWAPCASE}", True)
case("home/itself", "{HOME_NFD}", True)
case("home/itself", "{HOME}/Documents/..", True, "'..' back up to home")
dirs.append("{HOME}/Documents")
dirs.append("{HOME}/Library/Caches")
case("home/ordinary", "{HOME}/Documents", False)
case("home/ordinary", "{HOME}/Documents/report.txt", False)
case("home/ordinary", "{HOME}/Library/Caches/com.example/blob", False)
case("home/ordinary", "{HOME_NFD}/Documents/report.txt", False)
case("home/ordinary", "{HOME}/Library", False, "parent of denied subpaths is not itself denied")
case("home/parent", "{TMP}", False, "parent of home is not denied")

# --- '..' segments -----------------------------------------------------------
case("dotdot", "/usr/local/../bin/x", True)
case("dotdot", "/System/../usr/x", True)
case("dotdot", "/System/../tmp/x", False, "'..' escapes the denied dir to /tmp")
case("dotdot", "{HOME}/Documents/../.ssh/id_rsa", True)
case("dotdot", "{HOME}/Documents/../.SSH/id_rsa", True)
case("dotdot", "{HOME}/.ssh/../Documents/x", False, "'..' escapes the denied dir")
case("dotdot", "{TMP}/links/home_0/../Documents/x", False, "'..' applies to the symlink TARGET (~/.ssh/.. = ~)")
case("dotdot", "{TMP}/links/home_0/../.gnupg/x", True, "'..' applies to the symlink target, landing in ~/.gnupg")

# --- non-existent tails --------------------------------------------------------
case("nonexistent", "/System/does/not/exist", True)
case("nonexistent", "/SYSTEM/does/not/exist", True)
case("nonexistent", "{HOME}/.SSH/nope/nope", True)
case("nonexistent", "{HOME}/library/mail/nope", True)
case("nonexistent", "{TMP}/nope/nope/nope", False)
case("nonexistent", "/no-such-top-level/System/x", False, "'System' only matters directly under a volume root")

# --- /etc, /tmp, /var: the /private symlink family -----------------------------
case("private", "/etc/hosts", True)
case("private", "/private/etc/hosts", True)
case("private", "/ETC/hosts", True)
case("private", "/PRIVATE/ETC/hosts", True)
case("private", "/Private/Etc/hosts", True)
case("private", "/var/db/x", True)
case("private", "/VAR/DB/x", True)
case("private", "/private/var/DB/x", True)
case("private", "/var/root/x", True)
case("private", "/var/vm/swapfile0", True)
case("private", "/tmp", False)
case("private", "/tmp/x", False)
case("private", "/private/tmp/x", False)
case("private", "/TMP/x", False)
case("private", "/var/folders/ab/x", False)
case("private", "/var/tmp/x", False)
case("private", "/private/var/log/x", False)
case("private", "/private", False)
case("private", "/", False)

# --- dangling symlinks and loops -------------------------------------------------
symlinks.append({"link": "{TMP}/links/dangling", "target": "{TMP}/gone"})
symlinks.append({"link": "{TMP}/links/dangling_system", "target": "/System/gone/nowhere"})
symlinks.append({"link": "{TMP}/links/dangling_ssh", "target": "{HOME}/.ssh/missing_key"})
symlinks.append({"link": "{TMP}/links/dangling_ssh_case", "target": "{HOME_SWAPCASE}/.SSH/missing_key"})
case("dangling", "{TMP}/links/dangling", False)
case("dangling", "{TMP}/links/dangling/child", False)
case("dangling", "{TMP}/links/dangling_system", True)
case("dangling", "{TMP}/links/dangling_system/child", True)
case("dangling", "{TMP}/links/dangling_ssh", True)
case("dangling", "{TMP}/links/dangling_ssh_case", True, "dangling target spelled with different case")
symlinks.append({"link": "{HOME}/.ssh/loop_a", "target": "{HOME}/.ssh/loop_b"})
symlinks.append({"link": "{HOME}/.ssh/loop_b", "target": "{HOME}/.ssh/loop_a"})
case("loop", "{HOME}/.ssh/loop_a", True, "a symlink loop inside a denied dir is still denied")

# --- chained symlinks ---------------------------------------------------------------
symlinks.append({"link": "{TMP}/links/chain_1", "target": "{TMP}/links/chain_2"})
symlinks.append({"link": "{TMP}/links/chain_2", "target": "{TMP}/links/home_3"})
case("chain", "{TMP}/links/chain_1/child", True, "link -> link -> link -> ~/Library/Mail")

# --- File Cleaner's own code ----------------------------------------------------------
case("self", "{SELF}", True)
case("self", "{SELF}/safety.py", True)
case("self", "{SELF_SWAPCASE}/safety.py", True)

# --- extra_protected (user config) -------------------------------------------------------
dirs.append("{TMP}/keep")
dirs.append(f"{{TMP}}/caf{NFC}")
symlinks.append({"link": "{TMP}/links/to_keep", "target": "{TMP}/keep"})
X = {"extra_protected": ["{TMP}/keep"]}
case("extra", "{TMP}/keep", True, **X)
case("extra", "{TMP}/keep/x", True, **X)
case("extra", "{TMP}/KEEP/x", True, **X)
case("extra", "{TMP}/keeper/x", False, "string-prefix sibling", **X)
case("extra", "{TMP}/links/to_keep/x", True, "candidate reaches it through a symlink", **X)
case("extra", "{TMP}/keep/x", False, "no extra_protected given")
case("extra", "{TMP}/keep/x", True, "extra_protected itself given as a symlink", extra_protected=["{TMP}/links/to_keep"])
case("extra", "{TMP}/keep/x", True, "extra_protected given case-varied", extra_protected=["{TMP}/KEEP"])
case("extra/unicode", f"{{TMP}}/caf{NFD}/x", True, "config NFC, candidate NFD", extra_protected=[f"{{TMP}}/caf{NFC}"])
case("extra/unicode", f"{{TMP}}/caf{NFC}/x", True, "config NFD, candidate NFC", extra_protected=[f"{{TMP}}/caf{NFD}"])
case("extra/unicode", f"{{TMP}}/CAF{NFD.upper()}/x", True, "NFD + case", extra_protected=[f"{{TMP}}/caf{NFC}"])

# --- relative paths (cwd is {HOME}) ---------------------------------------------------------
case("relative", ".ssh/id_rsa", True, "resolved against cwd = {HOME}")
case("relative", "Documents/../.SSH/id_rsa", True)
case("relative", "Documents/report.txt", False)
case("relative", ".", True, "cwd is the home directory itself")

# --- ordinary paths -----------------------------------------------------------------------------
dirs.append("{TMP}/ordinary/System")
case("ordinary", "{TMP}/ordinary/file.log", False)
case("ordinary", "{TMP}/ordinary/System/x", False, "'System' deep inside a tree is not a volume-root subpath")
case("ordinary", "/Library/Caches/x", False)
case("ordinary", "/Library/Application Support/x", False)
case("ordinary", "/Users/Shared/x", False)
case("ordinary", "/opt/homebrew/x", False)

doc = {
    "description": (
        "Language-neutral conformance table for safety.is_protected. Each case is a path and the "
        "expected verdict. A harness must (1) create setup.dirs, then setup.symlinks, (2) expand "
        "placeholders, (3) point the implementation's home at {HOME}, its volumes directory at "
        "{VOLUMES}, and the working directory at {HOME}, then (4) assert every case. Cases with "
        "'requires' may be skipped when the filesystem lacks that property."
    ),
    "placeholders": {
        "{TMP}": "fresh, fully resolved temporary directory",
        "{HOME}": "{TMP}/hôme-" + NFC + " (non-ASCII on purpose; created with this exact NFC spelling)",
        "{HOME_NFD}": "{HOME} with its final component NFD-normalised",
        "{HOME_SWAPCASE}": "{HOME} with the case of its final component swapped",
        "{VOLUMES}": "{TMP}/Volumes (stands in for /Volumes)",
        "{SELF}": "directory containing the implementation's own code",
        "{SELF_SWAPCASE}": "{SELF} with the case of its final component swapped",
    },
    "setup": {"dirs": dirs, "symlinks": symlinks},
    "cases": cases,
}
out = Path("tests/safety_cases.json")
out.write_text(json.dumps(doc, indent=1, ensure_ascii=True) + "\n")
print(f"{len(cases)} cases, {len(dirs)} dirs, {len(symlinks)} symlinks -> {out}")
