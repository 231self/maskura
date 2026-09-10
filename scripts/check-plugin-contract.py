#!/usr/bin/env python3
"""Validate the canonical plugin contract, manifests, and Maskura namespace."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORLD = "maskura:plugin/transformer@0.1.0"
LOADABLE_ROOTS = (
    ROOT / "plugins" / "filters",
    ROOT / "plugins" / "crypto",
    ROOT / "plugins" / "transforms",
)
ALLOWED_STATUS = {"official", "experimental"}
ALLOWED_CAPABILITIES = {
    "public_key_pem",
    "entropy_seed",
    "stable_key",
    "stable_fields",
}
SCAN_ROOTS = (
    ROOT / "crates",
    ROOT / "plugins",
    ROOT / "tests",
    ROOT / "scripts",
    ROOT / "sdks",
    ROOT / ".github",
    ROOT / "local",
    ROOT / "examples",
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "AGENTS.md",
)
OLD_NAMESPACE = re.compile(r"\bs4\b|(?<!aw)s4[-_:]|s4m_|S4Client", re.IGNORECASE)
TEXT_SUFFIXES = {
    "",
    ".cjs",
    ".html",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".wit",
    ".yml",
    ".yaml",
}


def fail(message: str) -> None:
    print(f"plugin contract check: {message}", file=sys.stderr)
    raise SystemExit(1)


def loadable_plugins() -> list[Path]:
    plugins: list[Path] = []
    for category in LOADABLE_ROOTS:
        plugins.extend(manifest.parent for manifest in sorted(category.glob("*/Cargo.toml")))
    return plugins


def check_manifests() -> None:
    identifiers: set[str] = set()
    for plugin in loadable_plugins():
        metadata_path = plugin / "plugin.toml"
        if not metadata_path.is_file():
            fail(f"{plugin.relative_to(ROOT)} is missing plugin.toml")
        metadata = tomllib.loads(metadata_path.read_text())
        category = plugin.parent.name
        if metadata.get("schema_version") != 1:
            fail(f"{metadata_path.relative_to(ROOT)} has an unsupported schema_version")
        if metadata.get("category") != category:
            fail(f"{metadata_path.relative_to(ROOT)} category must be {category!r}")
        if metadata.get("status") not in ALLOWED_STATUS:
            fail(f"{metadata_path.relative_to(ROOT)} has an invalid status")
        if metadata.get("world") != WORLD:
            fail(f"{metadata_path.relative_to(ROOT)} must use {WORLD}")
        identifier = metadata.get("id")
        if not isinstance(identifier, str) or not identifier.startswith(f"maskura.{category}."):
            fail(f"{metadata_path.relative_to(ROOT)} has an invalid id")
        if identifier in identifiers:
            fail(f"duplicate plugin id {identifier!r}")
        identifiers.add(identifier)
        capabilities = metadata.get("capabilities")
        if not isinstance(capabilities, list) or not set(capabilities) <= ALLOWED_CAPABILITIES:
            fail(f"{metadata_path.relative_to(ROOT)} requests an unknown capability")
        cargo = (plugin / "Cargo.toml").read_text()
        if "maskura-plugin-sdk" not in cargo:
            fail(f"{plugin.relative_to(ROOT)} does not depend on maskura-plugin-sdk")


def check_wit_ownership() -> None:
    wit = ROOT / "crates" / "plugin-sdk" / "wit" / "world.wit"
    if "package maskura:plugin@0.1.0;" not in wit.read_text():
        fail("canonical WIT package declaration is missing")
    host = (ROOT / "crates" / "wasm-runtime" / "src" / "lib.rs").read_text()
    if 'path: "../plugin-sdk/wit"' not in host:
        fail("host runtime is not bound to the plugin SDK WIT")
    stray = [path for path in ROOT.rglob("*.wit") if path != wit and "target" not in path.parts]
    if stray:
        fail(f"WIT contract exists outside plugin-sdk: {stray[0].relative_to(ROOT)}")


def scan_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file() or "target" in path.parts or path.suffix == ".pem":
            continue
        if path.suffix in TEXT_SUFFIXES:
            yield path


def check_namespace() -> None:
    for root in SCAN_ROOTS:
        for path in scan_files(root):
            if path == Path(__file__).resolve():
                continue
            match = OLD_NAMESPACE.search(path.read_text(errors="ignore"))
            if match:
                fail(
                    f"old namespace {match.group(0)!r} remains in "
                    f"{path.relative_to(ROOT)}"
                )
    for path in ROOT.rglob("*"):
        if "target" in path.parts or ".jj" in path.parts:
            continue
        if OLD_NAMESPACE.search(path.name):
            fail(f"old namespace remains in path {path.relative_to(ROOT)}")


def main() -> None:
    check_manifests()
    check_wit_ownership()
    check_namespace()
    print("Plugin contract and Maskura namespace are consistent")


if __name__ == "__main__":
    main()
