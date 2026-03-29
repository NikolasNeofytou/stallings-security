"""
Test suite: test_basic.py
Chapter 1: Overview and Key Concepts

These should pass after TODO 1 and TODO 2.
Run with: pytest tests/test_basic.py -v
"""

import pytest
from src.types import (
    Asset,
    AssetCategory,
    AttackType,
    CIACategory,
    CIAImpact,
    ImpactLevel,
    Likelihood,
    Threat,
)
from src.core import assess_cia_impact, map_threats


# -- Fixtures ------------------------------------------------------------------

@pytest.fixture
def sample_asset():
    return Asset(
        name="User credentials",
        category=AssetCategory.DATA,
        description="Usernames and passwords",
    )


@pytest.fixture
def known_assets():
    return ["User credentials", "Product catalog", "Admin panel"]


# -- TestCIAAssessment (TODO 1) ------------------------------------------------

class TestCIAAssessment:
    """Tests for assess_cia_impact -- the CIA triad rating system."""

    def test_basic_rating(self, sample_asset):
        """All three CIA properties set correctly."""
        ratings = {
            "confidentiality": "HIGH",
            "integrity": "HIGH",
            "availability": "MEDIUM",
        }
        result = assess_cia_impact(sample_asset, ratings)

        assert result.cia_impact is not None
        assert result.cia_impact.confidentiality == ImpactLevel.HIGH
        assert result.cia_impact.integrity == ImpactLevel.HIGH
        assert result.cia_impact.availability == ImpactLevel.MEDIUM

    def test_returns_same_asset(self, sample_asset):
        """The returned asset should preserve name, category, description."""
        ratings = {"confidentiality": "LOW", "integrity": "LOW", "availability": "LOW"}
        result = assess_cia_impact(sample_asset, ratings)

        assert result.name == "User credentials"
        assert result.category == AssetCategory.DATA
        assert result.description == "Usernames and passwords"

    def test_missing_keys_default_to_none(self, sample_asset):
        """Missing CIA keys should default to ImpactLevel.NONE."""
        ratings = {"confidentiality": "CRITICAL"}
        result = assess_cia_impact(sample_asset, ratings)

        assert result.cia_impact.confidentiality == ImpactLevel.CRITICAL
        assert result.cia_impact.integrity == ImpactLevel.NONE
        assert result.cia_impact.availability == ImpactLevel.NONE

    def test_empty_ratings(self, sample_asset):
        """Empty dict -> all NONE."""
        result = assess_cia_impact(sample_asset, {})
        assert result.cia_impact.confidentiality == ImpactLevel.NONE
        assert result.cia_impact.integrity == ImpactLevel.NONE
        assert result.cia_impact.availability == ImpactLevel.NONE

    def test_all_impact_levels(self, sample_asset):
        """Verify every impact level string converts correctly."""
        for level_name in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            ratings = {"confidentiality": level_name}
            result = assess_cia_impact(sample_asset, ratings)
            assert result.cia_impact.confidentiality == ImpactLevel[level_name]

    def test_max_impact_property(self, sample_asset):
        """The max_impact property should return the highest of the three."""
        ratings = {
            "confidentiality": "LOW",
            "integrity": "CRITICAL",
            "availability": "MEDIUM",
        }
        result = assess_cia_impact(sample_asset, ratings)
        assert result.cia_impact.max_impact == ImpactLevel.CRITICAL


# -- TestThreatMapping (TODO 2) ------------------------------------------------

class TestThreatMapping:
    """Tests for map_threats -- turning raw data into validated Threats."""

    def test_basic_mapping(self, known_assets):
        """A valid threat maps correctly."""
        threat_data = [
            {
                "description": "Passwords intercepted over HTTP",
                "attack_type": "passive",
                "target_asset": "User credentials",
                "cia_category": "confidentiality",
                "likelihood": "LIKELY",
            }
        ]
        result = map_threats(threat_data, known_assets)

        assert len(result) == 1
        t = result[0]
        assert t.description == "Passwords intercepted over HTTP"
        assert t.attack_type == AttackType.PASSIVE
        assert t.target_asset == "User credentials"
        assert t.cia_category == CIACategory.CONFIDENTIALITY
        assert t.likelihood == Likelihood.LIKELY

    def test_unknown_asset_skipped(self, known_assets):
        """Threats targeting unknown assets are filtered out."""
        threat_data = [
            {
                "description": "Attack on nonexistent thing",
                "attack_type": "active",
                "target_asset": "Nonexistent Asset",
                "cia_category": "integrity",
            }
        ]
        result = map_threats(threat_data, known_assets)
        assert len(result) == 0

    def test_default_likelihood(self, known_assets):
        """Missing likelihood defaults to POSSIBLE."""
        threat_data = [
            {
                "description": "Some threat",
                "attack_type": "active",
                "target_asset": "Admin panel",
                "cia_category": "integrity",
            }
        ]
        result = map_threats(threat_data, known_assets)
        assert result[0].likelihood == Likelihood.POSSIBLE

    def test_multiple_threats(self, known_assets):
        """Multiple threats, mix of valid and invalid targets."""
        threat_data = [
            {
                "description": "Threat A",
                "attack_type": "passive",
                "target_asset": "User credentials",
                "cia_category": "confidentiality",
            },
            {
                "description": "Threat B",
                "attack_type": "active",
                "target_asset": "Ghost Asset",
                "cia_category": "availability",
            },
            {
                "description": "Threat C",
                "attack_type": "active",
                "target_asset": "Product catalog",
                "cia_category": "integrity",
            },
        ]
        result = map_threats(threat_data, known_assets)
        assert len(result) == 2
        assert result[0].description == "Threat A"
        assert result[1].description == "Threat C"

    def test_attack_surface_field(self, known_assets):
        """Optional attack_surface field is preserved."""
        threat_data = [
            {
                "description": "SQL injection via search",
                "attack_type": "active",
                "target_asset": "Product catalog",
                "cia_category": "integrity",
                "attack_surface": "Web application",
            }
        ]
        result = map_threats(threat_data, known_assets)
        assert result[0].attack_surface == "Web application"

    def test_empty_input(self, known_assets):
        """Empty threat list returns empty result."""
        assert map_threats([], known_assets) == []
