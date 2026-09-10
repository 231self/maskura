#!/usr/bin/env python3
"""Fail when Maskura's release-facing versions disagree."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def workspace_package_versions(workspace_version: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    manifests = sorted((ROOT / "crates").glob("*/Cargo.toml"))
    manifests += sorted((ROOT / "plugins").glob("*/*/Cargo.toml"))
    manifests += sorted((ROOT / "tests" / "plugins").glob("*/Cargo.toml"))
    for path in manifests:
        package = load_toml(path)["package"]
        if package["name"] == "maskura-plugin-sdk":
            if package.get("version") != "0.1.0":
                raise SystemExit("maskura-plugin-sdk version must match its 0.1.0 WIT ABI")
            versions[package["name"]] = "0.1.0"
            continue
        if package.get("version") != {"workspace": True}:
            raise SystemExit(
                f"{path.relative_to(ROOT)} does not inherit the workspace version"
            )
        versions[package["name"]] = workspace_version
    return versions


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="release tag to compare, such as v0.7.0")
    args = parser.parse_args()

    version = load_toml(ROOT / "Cargo.toml")["workspace"]["package"]["version"]
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"workspace version is not a release SemVer: {version!r}")
    if args.tag is not None and args.tag != f"v{version}":
        raise SystemExit(f"tag {args.tag!r} does not match workspace version v{version}")

    lock_packages = load_toml(ROOT / "Cargo.lock")["package"]
    locked_versions = {
        package["name"]: package["version"]
        for package in lock_packages
        if "source" not in package
    }
    for name, expected_version in sorted(workspace_package_versions(version).items()):
        if locked_versions.get(name) != expected_version:
            raise SystemExit(
                f"Cargo.lock has {name} {locked_versions.get(name)!r}, "
                f"expected {expected_version}"
            )

    openapi_version = json.loads((ROOT / "sdks/openapi.json").read_text())["info"][
        "version"
    ]
    if openapi_version != version:
        raise SystemExit(
            f"sdks/openapi.json reports {openapi_version}, expected {version}; "
            "run just build-sdks"
        )

    python_package = load_toml(ROOT / "sdks/python/pyproject.toml")["project"]
    if python_package["version"] != version:
        raise SystemExit(
            "sdks/python/pyproject.toml reports package version "
            f"{python_package['version']}, expected {version}; run just build-sdks"
        )
    setup_version = re.search(
        r'^VERSION = "([^"]+)"$',
        (ROOT / "sdks/python/setup.py").read_text(),
        re.MULTILINE,
    )
    if setup_version is None or setup_version.group(1) != version:
        reported = setup_version.group(1) if setup_version is not None else None
        raise SystemExit(
            f"sdks/python/setup.py reports package version {reported!r}, "
            f"expected {version}; run just build-sdks"
        )
    typescript_package = json.loads(
        (ROOT / "sdks/typescript/package.json").read_text()
    )
    if typescript_package["version"] != version:
        raise SystemExit(
            "sdks/typescript/package.json reports package version "
            f"{typescript_package['version']}, expected {version}; run just build-sdks"
        )

    generated_versions: set[str] = set()
    patterns = (
        re.compile(
            r"The version of the OpenAPI document: ([0-9]+\.[0-9]+\.[0-9]+)"
        ),
        re.compile(r"OpenAPI spec version: ([0-9]+\.[0-9]+\.[0-9]+)"),
    )
    for directory in (ROOT / "sdks/python", ROOT / "sdks/typescript"):
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".ts", ".md"}:
                continue
            text = path.read_text(errors="replace")
            for pattern in patterns:
                generated_versions.update(pattern.findall(text))
    if generated_versions != {version}:
        raise SystemExit(
            f"generated SDK metadata has versions {sorted(generated_versions)}, "
            f"expected only {version}; run just build-sdks"
        )

    image = f"ghcr.io/231self/maskura/maskura:v{version}"
    required_references = {
        ROOT / "README.md": image,
        ROOT / "docs/proofs.md": image,
    }
    for path, expected in required_references.items():
        if expected not in path.read_text():
            raise SystemExit(f"{path.relative_to(ROOT)} does not reference {expected}")

    tag_workflow = (ROOT / ".github/workflows/tag-on-version-bump.yml").read_text()
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text()
    if "RELEASE_TOKEN" in tag_workflow:
        raise SystemExit("version-bump tagging must not depend on a maintainer PAT")
    for expected in (
        "contents: write",
        "uses: ./.github/workflows/release.yml",
        "release_tag: ${{ needs.tag-if-bumped.outputs.tag }}",
        "secrets: inherit",
    ):
        if expected not in tag_workflow:
            raise SystemExit(
                f"tag-on-version-bump.yml is missing reusable-release contract {expected!r}"
            )
    for expected in (
        "workflow_call:",
        "RELEASE_TAG: ${{ inputs.release_tag || github.ref_name }}",
    ):
        if expected not in release_workflow:
            raise SystemExit(
                f"release.yml is missing reusable-release contract {expected!r}"
            )
    if release_workflow.count("github.ref_name") != 1:
        raise SystemExit(
            "release.yml must use RELEASE_TAG everywhere except its push-trigger fallback"
        )

    print(f"release contract passed for v{version}")


if __name__ == "__main__":
    main()
