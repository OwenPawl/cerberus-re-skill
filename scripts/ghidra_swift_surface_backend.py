#!/usr/bin/env python3
"""Compatibility entrypoint for the split Swift surface backend."""

from python_lib.ghidra_swift_surface_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
