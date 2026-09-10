#!/usr/bin/env python3
"""Reject internal positioning commentary from public entry-point copy."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ENTRY_POINTS = (ROOT / "README.md",)
FORBIDDEN = re.compile(
    r"not the product|what makes (?:us|maskura) different|we built|the moat|"
    r"commodity (?:feature|product)|strategic problem|under-marketed|"
    r"defensible product",
    re.IGNORECASE,
)


def main() -> None:
    failures: list[str] = []
    for path in PUBLIC_ENTRY_POINTS:
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if FORBIDDEN.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")

    if failures:
        raise SystemExit(
            "Internal positioning commentary found in public copy:\n"
            + "\n".join(failures)
        )

    print("Public copy check passed")


if __name__ == "__main__":
    main()
