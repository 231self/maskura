"""Dagger pipeline for Maskura: build, test, publish.

Run locally (requires the Dagger CLI + engine):
    just build-local                    # fmt + clippy + filters + tests (cached)
    just image-local                    # assemble the deploy image
    just publish-local TAG=v0.2.0       # push canonical + legacy image tags

Sources are cloned in-engine via dag.git (no host filesystem dependency),
and cargo registry + target dirs live on persistent cache volumes, so
repeated runs reuse compiled dependencies instead of recompiling.
"""

import base64
import re

import dagger
from dagger import dag, function, object_type

REGISTRY = "ghcr.io/231self/maskura/maskura"
LEGACY_REGISTRY = "ghcr.io/231self/maskura/maskura"
REPO = "https://github.com/231self/maskura.git"
DEFAULT_REF = "main"


def validate_nonce(nonce: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("missing or malformed guard freshness nonce")


@object_type
class Maskura:
    """Build, test, and publish Maskura."""

    @function
    async def builder(self, guard_source_b64: str, ref: str = DEFAULT_REF) -> dagger.Container:
        """Rust builder: workspace + wasm32 target + wasm-tools, cargo-cached."""
        tree = dag.git(REPO).branch(ref).tree()
        source = base64.b64decode(guard_source_b64, validate=True).decode("utf-8")
        if not source or len(source) > 100_000:
            raise ValueError("missing or oversized trusted guard source")
        return (
            dag.container()
            .from_(
                "rust:1.97.0-trixie@sha256:b92b8c8574f8f3b207fcb0912fb3e2de4041580b5934d90312d53938c9a038a9"
            )
            .with_directory("/src", tree)
            .with_new_file("/src/scripts/sqlite-guard.py", contents=source)
            .with_workdir("/src")
            .with_env_variable("CARGO_HOME", "/cargo")
            .with_mounted_cache("/cargo", dag.cache_volume("maskura-cargo-registry"))
            .with_mounted_cache("/src/target", dag.cache_volume("maskura-cargo-target"))
            .with_exec(["apt-get", "update"])
            .with_exec(["apt-get", "install", "-y", "--no-install-recommends", "python3"])
            .with_exec(["rustup", "target", "add", "wasm32-wasip1"])
            .with_exec(
                ["cargo", "install", "--locked", "wasm-tools", "--version", "1.255.0"]
            )
        )

    @function
    async def ci(self, guard_nonce: str, guard_source_b64: str, ref: str = DEFAULT_REF) -> str:
        """Build filters + gateway, then fmt / clippy / test."""
        validate_nonce(guard_nonce)
        ctr = await self.builder(guard_source_b64, ref)
        ctr = ctr.with_exec(["bash", "scripts/build-plugins.sh"])
        ctr = ctr.with_exec(["cargo", "fmt", "--check"])
        ctr = ctr.with_exec(["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])
        ctr = ctr.with_exec(["cargo", "test", "--workspace"])
        ctr = ctr.with_exec(["python3", "scripts/sqlite-guard.py", "--nonce", guard_nonce])
        return await ctr.stdout()

    @function
    async def image(self, guard_nonce: str, guard_source_b64: str, ref: str = DEFAULT_REF) -> dagger.Container:
        """Assemble the deploy image: release binary + Wasm components + certs."""
        validate_nonce(guard_nonce)
        builder = await self.builder(guard_source_b64, ref)
        builder = builder.with_exec(["bash", "scripts/build-plugins.sh"])
        builder = builder.with_exec(["cargo", "build", "--release", "-p", "maskura-gateway"])
        builder = builder.with_exec(["python3", "scripts/sqlite-guard.py", "--nonce", guard_nonce])

        return (
            dag.container()
            .from_(
                "debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
            )
            .with_exec(["apt-get", "update"])
            .with_exec(
                ["apt-get", "install", "-y", "--no-install-recommends", "ca-certificates"]
            )
            .with_exec(["rm", "-rf", "/var/lib/apt/lists/*"])
            .with_file(
                "/usr/local/bin/maskura-gateway",
                builder.file("/src/target/release/maskura-gateway"),
            )
            .with_directory(
                "/app/components",
                builder.directory("/src/target/components"),
            )
            .with_env_variable(
                "MASKURA_DEFAULT_PLUGIN", "/app/components/pii-default.component.wasm"
            )
            .with_env_variable("MASKURA_PLUGINS_DIR", "/app/components")
            .with_env_variable("LISTEN_ADDR", "0.0.0.0:8080")
            .with_exposed_port(8080)
            .with_entrypoint(["maskura-gateway"])
        )

    @function
    async def publish(self, tag: str, guard_nonce: str, guard_source_b64: str, ref: str = DEFAULT_REF) -> str:
        """Publish identical canonical and legacy deploy image tags."""
        img = await self.image(guard_nonce, guard_source_b64, ref)
        canonical = await img.publish(f"{REGISTRY}:{tag}")
        await img.publish(f"{LEGACY_REGISTRY}:{tag}")
        return canonical
