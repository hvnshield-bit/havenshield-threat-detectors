#!/usr/bin/env python3
"""Entrypoint wrapper for HavenShield.

This keeps a simple executable at the repo root while the main implementation
lives under src/ for easier testing and packaging.
"""
from src.havenshield import main

if __name__ == "__main__":
    main()
