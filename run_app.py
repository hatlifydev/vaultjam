"""Lanzador (también punto de entrada para PyInstaller)."""
import sys

from vaultjam.app import main

if __name__ == "__main__":
    sys.exit(main())
