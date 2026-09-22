#!/usr/bin/env python3
"""Verify that an installed decnique wheel contains its public runtime surface."""

from __future__ import annotations

import argparse
import pkgutil
from importlib.metadata import distribution, version

import decnique
from decnique.dsl.parser import parse_text
from decnique.env import Catalog
from decnique.regions import Numeric


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("expected_version")
    args = parser.parse_args(argv)

    installed_version = version("decnique")
    if installed_version != args.expected_version:
        parser.error(f"installed version is {installed_version}, expected {args.expected_version}")

    modules = {module.name for module in pkgutil.walk_packages(decnique.__path__, "decnique.")}
    if "decnique.regions" not in modules:
        parser.error("decnique.regions is missing from the installed package")

    scripts = {entry.name: entry.value for entry in distribution("decnique").entry_points}
    expected_scripts = {
        "decnique": "decnique.ui.repl:main",
        "decnique-tooling": "decnique.cli:main",
    }
    if {name: scripts.get(name) for name in expected_scripts} != expected_scripts:
        parser.error("installed console scripts do not match the public command surface")

    if not Numeric(0, 2).contains_point(1):
        parser.error("region engine failed its numeric-domain smoke check")
    parsed = parse_text('detection d { event method = "X" }', "d.decn")
    if parsed.detections[0].id != "d":
        parser.error("packaged DSL grammar failed its parse smoke check")
    permissions = Catalog.gcp().all_permissions()
    if not permissions:
        parser.error("packaged GCP catalog is empty")

    print(
        f"decnique {installed_version}: {len(modules)} modules, "
        f"{len(permissions)} catalog permissions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
