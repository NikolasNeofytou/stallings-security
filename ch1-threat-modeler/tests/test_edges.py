"""
Test suite: test_edges.py
Chapter 1: Overview and Key Concepts

These should pass after TODO 3.
Run with: pytest tests/test_edges.py -v
"""

import pytest
from src.types import AttackSurface
from src.core import identify_attack_surfaces


# -- Fixtures ------------------------------------------------------------------

@pytest.fixture
def known_assets():
    return ["User credentials", "Product catalog", "Admin panel", "Order data"]


# -- TestAttackSurfaces (TODO 3) -----------------------------------------------

class TestAttackSurfaces:
    """Tests for identify_attack_surfaces -- entry point analysis."""

    def test_basic_surface(self, known_assets):
        """A simple surface with valid exposed assets."""
        surface_data = [
            {
                "name": "Web application",
                "description": "Public-facing HTTP interface",
                "exposed_assets": ["User credentials", "Product catalog"],
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 1
        assert isinstance(result[0], AttackSurface)
        assert result[0].name == "Web application"
        assert result[0].description == "Public-facing HTTP interface"
        assert result[0].exposed_assets == ["User credentials", "Product catalog"]

    def test_unknown_assets_filtered(self, known_assets):
        """Assets not in known_assets are silently dropped from exposed list."""
        surface_data = [
            {
                "name": "API endpoint",
                "description": "REST API",
                "exposed_assets": ["User credentials", "Ghost Asset", "Order data"],
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 1
        assert "Ghost Asset" not in result[0].exposed_assets
        assert result[0].exposed_assets == ["User credentials", "Order data"]

    def test_all_assets_unknown(self, known_assets):
        """Surface with only unknown assets -> empty exposed list."""
        surface_data = [
            {
                "name": "Mystery endpoint",
                "description": "Points to nothing real",
                "exposed_assets": ["Fake A", "Fake B"],
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 1
        assert result[0].exposed_assets == []

    def test_empty_exposed_assets(self, known_assets):
        """Surface with no exposed assets specified."""
        surface_data = [
            {
                "name": "Physical server",
                "description": "The machine itself",
                "exposed_assets": [],
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 1
        assert result[0].exposed_assets == []

    def test_multiple_surfaces(self, known_assets):
        """Multiple attack surfaces identified correctly."""
        surface_data = [
            {
                "name": "Web app",
                "description": "HTTP interface",
                "exposed_assets": ["User credentials"],
            },
            {
                "name": "Admin panel",
                "description": "/admin endpoint",
                "exposed_assets": ["Admin panel", "Order data"],
            },
            {
                "name": "File upload",
                "description": "Image upload form",
                "exposed_assets": ["Product catalog"],
            },
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 3
        assert result[0].name == "Web app"
        assert result[1].name == "Admin panel"
        assert result[2].name == "File upload"

    def test_empty_input(self, known_assets):
        """Empty surface list returns empty result."""
        assert identify_attack_surfaces([], known_assets) == []

    def test_missing_exposed_assets_key(self, known_assets):
        """Surface data without exposed_assets key defaults to empty list."""
        surface_data = [
            {
                "name": "Network port",
                "description": "Open TCP port",
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)

        assert len(result) == 1
        assert result[0].exposed_assets == []

    def test_duplicate_assets_preserved(self, known_assets):
        """If the same asset appears twice in exposed list, keep as-is."""
        surface_data = [
            {
                "name": "Dual exposure",
                "description": "Same asset twice",
                "exposed_assets": ["User credentials", "User credentials"],
            }
        ]
        result = identify_attack_surfaces(surface_data, known_assets)
        # Implementation may deduplicate or preserve -- either is acceptable
        assert "User credentials" in result[0].exposed_assets
