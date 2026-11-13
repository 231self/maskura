#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit entry point; importing never launches a campaign."""
from managed_release_linux.controller import main


if __name__ == "__main__":
    raise SystemExit(main())
