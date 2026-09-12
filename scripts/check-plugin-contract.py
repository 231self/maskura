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
FROZEN_PROTOCOL_LITERALS = {
    Path("crates/gateway/src/managed.rs"): (
        'b"s4-placement-policy\\0"',
        'b"s4-rendezvous\\0"',
    ),
}
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


def check_proof_component_source() -> None:
    proof = (ROOT / "examples" / "prove-maskura.sh").read_text()
    expected = (
        'docker cp "$CONTAINER:/app/components/email-detect.component.wasm" '
        '"$component"'
    )
    if expected not in proof:
        fail("proof harness must import the component shipped in the image under test")
    if '$ROOT/components/email-detect.component.wasm' in proof:
        fail("proof harness must not mix checkout components with a published image")


def check_bundled_component_context() -> None:
    required_fields = (
        b"content-type",
        b"operation",
        b"policy-version",
        b"config-json",
        b"public-key-pem",
        b"entropy-seed",
        b"stable-key",
        b"stable-fields",
    )
    components = sorted((ROOT / "components").glob("*.component.wasm"))
    if not components:
        fail("no bundled plugin components were found")
    for component in components:
        payload = component.read_bytes()
        missing = [field.decode() for field in required_fields if field not in payload]
        if missing:
            fail(
                f"{component.relative_to(ROOT)} has a stale context contract; "
                f"missing {', '.join(missing)}; run just build-plugins and refresh components"
            )


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
            relative_path = path.relative_to(ROOT)
            contents = path.read_text(errors="ignore")
            for literal in FROZEN_PROTOCOL_LITERALS.get(relative_path, ()):
                contents = contents.replace(literal, "")
            match = OLD_NAMESPACE.search(contents)
            if match:
                fail(
                    f"old namespace {match.group(0)!r} remains in "
                    f"{relative_path}"
                )
    for path in ROOT.rglob("*"):
        if "target" in path.parts or ".jj" in path.parts:
            continue
        if OLD_NAMESPACE.search(path.name):
            fail(f"old namespace remains in path {path.relative_to(ROOT)}")


def main() -> None:
    check_manifests()
    check_wit_ownership()
    check_proof_component_source()
    check_bundled_component_context()
    check_namespace()
    print("Plugin contract and Maskura namespace are consistent")


if __name__ == "__main__":
    main()
