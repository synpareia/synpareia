"""Shared test fixtures."""

from __future__ import annotations

import pytest

import synpareia
from synpareia.policy import Policy, templates


@pytest.fixture
def profile() -> synpareia.Profile:
    """A fresh test profile with signing keys."""
    return synpareia.generate()


@pytest.fixture
def profile_b() -> synpareia.Profile:
    """A second test profile."""
    return synpareia.generate()


@pytest.fixture
def cop_policy(profile: synpareia.Profile) -> Policy:
    """Permissive single-owner CoP policy keyed on the default profile fixture."""
    return templates.cop(profile)


@pytest.fixture
def sphere_policy(profile: synpareia.Profile, profile_b: synpareia.Profile) -> Policy:
    """Bilateral Sphere policy keyed on profile + profile_b, no witness."""
    return templates.sphere(profile, profile_b)
