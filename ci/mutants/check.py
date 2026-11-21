#!/usr/bin/env python3
"""Fail on surviving mutants that this OS does not expect.

usage: check.py [--full] EXPECTED_LIST MUTANTS_OUT_DIR [MUTANTS_OUT_DIR ...]

cargo-mutants does not evaluate `cfg`, so a mutant in code that only builds
for another OS always "survives" here. Each OS keeps a list of the survivors
it accepts, each with a reason (ci/mutants/expected-<os>.txt). Anything that
survives and is not on that list fails the check.

- Names are compared without `:line:column`, so the lists survive code moving.
- Counts matter: if a function has two mutants with the same description and
  only one is listed, a second survivor still fails.
- Several mutants.out directories (one per shard) are merged first.
- With --full (a run over every mutant), a listed mutant that is now caught
  also fails, so the lists only ever shrink to what is really untestable.
- Mutants caught only because the tests hung are reported as warnings.
"""

import collections
import pathlib
import re
import sys


def key(name: str) -> str:
    """`src\\ffi\\mod.rs:59:24: replace | with &` -> `src/ffi/mod.rs: replace | with &`."""
    name = name.strip().replace("\\", "/")
    return re.sub(r"^([^:]+?):\d+(?::\d+)?:", r"\1:", name)


def read_names(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def main(argv: list[str]) -> int:
    full = "--full" in argv
    args = [a for a in argv if a != "--full"]
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    expected_file, out_dirs = pathlib.Path(args[0]), [pathlib.Path(d) for d in args[1:]]

    expected = collections.Counter(key(n) for n in read_names(expected_file))
    missed = collections.Counter()
    for out in out_dirs:
        missed.update(key(n) for n in read_names(out / "missed.txt"))

    timeouts = [n for out in out_dirs for n in read_names(out / "timeout.txt")]
    unexpected = missed - expected
    stale = expected - missed if full else collections.Counter()

    for name, count in sorted(unexpected.items()):
        print(f"::error::mutant survived (no test caught it): {name}" + (f" (x{count})" if count > 1 else ""))
    for name, count in sorted(stale.items()):
        print(f"::error::{expected_file}: listed survivor is now caught, remove it: {name}"
              + (f" (x{count})" if count > 1 else ""))

    # A mutant that made the tests hang counts as caught, but say so: a hang is
    # a weak way to catch it, and usually means a test is missing.
    for name in timeouts:
        print(f"::warning::mutant caught only by a timeout (tests hung): {key(name)}")

    total_missed = sum(missed.values())
    print(f"{total_missed} survived, {total_missed - sum(unexpected.values())} of them expected "
          f"({expected_file.name}); {sum(unexpected.values())} unexpected, {sum(stale.values())} stale, "
          f"{len(timeouts)} caught only by a timeout.")
    return 1 if unexpected or stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
