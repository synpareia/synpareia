"""Shared test fixtures."""

from __future__ import annotations

import pytest

import synpareia


@pytest.fixture
def profile() -> synpareia.Profile:
    """A fresh test profile with signing keys."""
    return synpareia.generate()


@pytest.fixture
def profile_b() -> synpareia.Profile:
    """A second test profile."""
    return synpareia.generate()
