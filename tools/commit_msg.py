#!/usr/bin/env python3
"""AGENTS.md §8 as a program: ``type(scope): what and why`` — one line, atomic, no trailers.

Run two ways:

    python tools/commit_msg.py .git/COMMIT_EDITMSG     the `commit-msg` hook, on the message
    python tools/commit_msg.py --range origin/dev..HEAD   CI, over a pull request's commits

Deliberately a plain script with no dependencies.  The convention is short enough to state in
thirty lines, and the project's own rule is that a tool says *why* it refuses something — so
each failure names the rule it broke and shows a message that would have passed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

TYPES = ("feat", "fix", "docs", "test", "refactor", "perf", "chore", "ci", "build", "revert")
MAX_HEADER = 100

# `type(scope)!: subject` — scope and the breaking-change `!` are optional.
HEADER = re.compile(rf"^(?P<type>{'|'.join(TYPES)})(?P<scope>\([^()]+\))?!?: (?P<subject>.+)$")

# Trailers the project does not want in its history (AGENTS.md §8: "no trailers").
TRAILER = re.compile(
    r"^(Co-authored-by|Signed-off-by|Claude-Session|Generated-with|Reviewed-by|Refs)\s*:",
    re.IGNORECASE | re.MULTILINE,
)

# `git commit -v` appends the diff after this marker; it is not part of the message.
SCISSORS = re.compile(r"^# -+ >8 -+$", re.MULTILINE)

EXAMPLE = "fix(loader): collapse duplicate rules so a corpus loaded twice counts once"


def clean(message: str) -> str:
    """The message as it will be recorded: comments and the ``git commit -v`` diff removed."""
    cut = SCISSORS.search(message)
    if cut:
        message = message[: cut.start()]
    kept = [line for line in message.splitlines() if not line.startswith("#")]
    return "\n".join(kept).strip()


def is_exempt(message: str) -> bool:
    """A merge or a revert: git writes those itself and there is nothing to gain from a fight."""
    first = message.splitlines()[0] if message.splitlines() else ""
    return first.startswith(("Merge ", "Revert ", "revert:", "fixup!", "squash!"))


def check(message: str) -> list[str]:
    """Every rule the message breaks, in the order a reader would notice them."""
    text = clean(message)
    if not text:
        return ["the message is empty"]
    if is_exempt(text):
        return []

    problems: list[str] = []
    lines = text.splitlines()
    header = lines[0]

    match = HEADER.match(header)
    if match is None:
        if re.match(r"^\w+(\([^()]+\))?!?:", header):
            kind = header.split(":", 1)[0].split("(", 1)[0].rstrip("!")
            problems.append(f"type {kind!r} is not one of: {', '.join(TYPES)}")
        else:
            problems.append("the header must read `type(scope): what and why`")
    else:
        subject = match.group("subject")
        if subject.endswith("."):
            problems.append("the subject does not end in a full stop")
        if subject[:1].isupper():
            problems.append("the subject starts lower case")

    if len(header) > MAX_HEADER:
        problems.append(f"the header is {len(header)} characters; the limit is {MAX_HEADER}")

    body = "\n".join(lines[1:]).strip()
    if body:
        problems.append("the message is one line — say what and why in the subject, or split the commit")
    if TRAILER.search(text):
        name = TRAILER.search(text).group(1)  # type: ignore[union-attr]
        problems.append(f"commits carry no trailers — drop the {name!r} line")
    return problems


def report(message: str, problems: list[str]) -> None:
    header = clean(message).splitlines()[0] if clean(message) else "(empty)"
    print(f"\n  {header}", file=sys.stderr)
    for p in problems:
        print(f"    ✗ {p}", file=sys.stderr)
    print(f"\n  the convention is AGENTS.md §8, for example:\n    {EXAMPLE}\n", file=sys.stderr)


def messages_in(rev_range: str) -> list[str]:
    out = subprocess.run(
        ["git", "log", "--format=%B%x00", "--no-merges", rev_range],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [m.strip() for m in out.split("\0") if m.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", nargs="?", help="a file holding one commit message (the hook's argument)")
    ap.add_argument("--range", dest="rev_range", help="check every commit in a range, e.g. origin/dev..HEAD")
    ns = ap.parse_args(argv)

    if ns.rev_range:
        texts = messages_in(ns.rev_range)
    elif ns.file:
        with open(ns.file, encoding="utf-8") as fh:
            texts = [fh.read()]
    else:
        texts = [sys.stdin.read()]

    bad = 0
    for text in texts:
        problems = check(text)
        if problems:
            bad += 1
            report(text, problems)
    if bad:
        print(f"{bad} of {len(texts)} commit message(s) need a rewrite", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
