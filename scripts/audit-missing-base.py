#!/usr/bin/env python3
"""Report every subcommand group whose base is weaker than what the group can reach.

A group's classification answers for the bare invocation and for every child the group does not
model, so it has to be at least as severe as its children. Two ways it fails:

- **no classification at all** -- the base defaults to READONLY, and the unmodelled child is the
  one nobody thought about;
- **a classification that answers `risk: LOW`** while something below it does not -- `git remote`
  declared READONLY over an `add` that is EXTERNAL_EFFECTS says `git remote whatever` is
  read-only, and it is not.

`risk: LOW` is the question because it is the bundled hook's auto-approve condition. A base that
answers MEDIUM or HIGH over more severe children is not flagged: `gh issue` at UNKNOWN prompts
for the child it does not model, which is all the base has to do.

A group is allowed to answer LOW over LOW only, unless an unmodelled child would genuinely be
read-only too, the way `gh search` is; `docs/classification-guidance.md` has the decision.

    uv run python scripts/audit-missing-base.py [commands-dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "src" / "bash_classify" / "commands"

RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
DEFAULT_RISK = {
    "READONLY": "LOW",
    "LOCAL_EFFECTS": "MEDIUM",
    "EXTERNAL_EFFECTS": "MEDIUM",
    "UNKNOWN": "HIGH",
    "DANGEROUS": "HIGH",
}


def risk_of(node: dict) -> str:
    """The risk a node answers with, the way the matcher derives it."""
    if node.get("risk"):
        return node["risk"]
    return DEFAULT_RISK[node.get("classification") or "READONLY"]


def worst_descendant_risk(node: dict) -> tuple[str, str]:
    """The highest risk anywhere below this node, and the path that carries it."""
    worst, where = "LOW", ""
    for name, child in (node.get("subcommands") or {}).items():
        for candidate, source in ((risk_of(child), name), worst_descendant_risk(child)):
            if RISK[candidate] > RISK[worst]:
                worst, where = candidate, f"{name} {source}".strip()
    return worst, where


def walk(node: dict, path: list[str], rows: list, totals: list[int]) -> None:
    children = node.get("subcommands") or {}
    if children:
        totals[0] += 1
        # The question is the hook's: this group answers `risk: LOW` for its bare invocation and
        # for every child it does not model, while something under it is not LOW.
        base = risk_of(node)
        worst, where = worst_descendant_risk(node)
        if base == "LOW" and RISK[worst] > 0:
            declared = node.get("classification") or "no classification"
            rows.append((" ".join(path), declared, f"{worst} at `{where}`", sorted(children)))
    for name, child in children.items():
        walk(child, [*path, name], rows, totals)


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else DEFAULT_DIR
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    rows: list = []
    totals = [0]
    for file in sorted(root.glob("*.yaml")):
        data = yaml.safe_load(file.read_text())
        walk(data, [data["command"]], rows, totals)

    for path, declared, reaches, names in rows:
        shown = ", ".join(names[:5]) + (" ..." if len(names) > 5 else "")
        print(f"{path:<32} base {declared:<17} answers LOW, reaches {reaches:<28} {shown}")
    print(f"\n{len(rows)} groups answering LOW over something that is not, out of {totals[0]} with children")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
