"""
Test suite: test_properties.py
Chapter 1: Overview and Key Concepts

The final test: does your threat modeler produce a complete, consistent,
and useful report? This tests the full pipeline -- all TODOs must work.

These should pass after TODO 5.
Run with: pytest tests/test_properties.py -v
"""

import pytest
from src.types import (
    AssetCategory,
    ImpactLevel,
    Likelihood,
    ThreatReport,
)
from src.core import generate_threat_report


# -- Test Data: a complete system to model -------------------------------------

SYSTEM_NAME = "MiniShop"
SYSTEM_DESC = "Small e-commerce application with admin panel and file uploads."

ASSET_DATA = [
    {
        "name": "User credentials",
        "category": "data",
        "description": "Emails and passwords",
        "cia": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
    },
    {
        "name": "Product catalog",
        "category": "data",
        "description": "Product names, prices, stock counts",
        "cia": {"confidentiality": "LOW", "integrity": "HIGH", "availability": "HIGH"},
    },
    {
        "name": "Admin panel",
        "category": "service",
        "description": "Administrative interface at /admin",
        "cia": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
    },
]

THREAT_DATA = [
    {
        "description": "Passwords intercepted over HTTP",
        "attack_type": "passive",
        "target_asset": "User credentials",
        "cia_category": "confidentiality",
        "likelihood": "ALMOST_CERTAIN",
    },
    {
        "description": "SHA-1 cracking via rainbow tables",
        "attack_type": "active",
        "target_asset": "User credentials",
        "cia_category": "confidentiality",
        "likelihood": "LIKELY",
    },
    {
        "description": "Price tampering",
        "attack_type": "active",
        "target_asset": "Product catalog",
        "cia_category": "integrity",
        "likelihood": "POSSIBLE",
    },
    {
        "description": "Brute force on admin login",
        "attack_type": "active",
        "target_asset": "Admin panel",
        "cia_category": "confidentiality",
        "likelihood": "LIKELY",
    },
    {
        "description": "Threat against fake asset",
        "attack_type": "active",
        "target_asset": "Nonexistent",
        "cia_category": "integrity",
        "likelihood": "LIKELY",
    },
]

SURFACE_DATA = [
    {
        "name": "Web application",
        "description": "Public-facing HTTP endpoints",
        "exposed_assets": ["User credentials", "Product catalog"],
    },
    {
        "name": "Admin endpoint",
        "description": "/admin path",
        "exposed_assets": ["Admin panel", "Ghost Asset"],
    },
]


# -- TestReportGeneration (TODO 5) ---------------------------------------------

class TestReportGeneration:
    """Tests for the full pipeline: generate_threat_report."""

    @pytest.fixture
    def report(self):
        return generate_threat_report(
            SYSTEM_NAME, SYSTEM_DESC, ASSET_DATA, THREAT_DATA, SURFACE_DATA
        )

    def test_returns_threat_report(self, report):
        """Output is a ThreatReport instance."""
        assert isinstance(report, ThreatReport)

    def test_system_info(self, report):
        """System name and description are preserved."""
        assert report.system_name == SYSTEM_NAME
        assert report.system_description == SYSTEM_DESC

    def test_assets_created(self, report):
        """All assets from input are created with CIA impact."""
        assert len(report.assets) == 3
        names = {a.name for a in report.assets}
        assert names == {"User credentials", "Product catalog", "Admin panel"}

        for asset in report.assets:
            assert asset.cia_impact is not None

    def test_threats_filtered(self, report):
        """Threats against unknown assets are filtered out."""
        # 5 input threats, but "Nonexistent" target -> 4 valid
        assert len(report.threats) == 4
        targets = {t.target_asset for t in report.threats}
        assert "Nonexistent" not in targets

    def test_surfaces_created(self, report):
        """Attack surfaces created with filtered exposed assets."""
        assert len(report.attack_surfaces) == 2

        admin_surface = next(
            s for s in report.attack_surfaces if s.name == "Admin endpoint"
        )
        # "Ghost Asset" should be filtered from exposed_assets
        assert "Ghost Asset" not in admin_surface.exposed_assets
        assert "Admin panel" in admin_surface.exposed_assets

    def test_risk_scores_computed(self, report):
        """Risk scores exist for all valid threats."""
        assert len(report.risk_scores) == 4

        for rs in report.risk_scores:
            assert rs.score >= 0
            assert rs.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_summary_complete(self, report):
        """Summary dict has all required keys."""
        required_keys = {
            "total_assets",
            "total_surfaces",
            "total_threats",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "top_cia_concern",
            "most_exposed_asset",
        }
        assert required_keys.issubset(report.summary.keys())

    def test_summary_counts_correct(self, report):
        """Summary counts match the actual data."""
        s = report.summary
        assert s["total_assets"] == 3
        assert s["total_surfaces"] == 2
        assert s["total_threats"] == 4

        severity_total = (
            s["critical_count"] + s["high_count"]
            + s["medium_count"] + s["low_count"]
        )
        assert severity_total == 4

    def test_top_cia_concern_is_string(self, report):
        """top_cia_concern should be a CIA category name string."""
        valid_concerns = {"confidentiality", "integrity", "availability", "N/A"}
        assert report.summary["top_cia_concern"] in valid_concerns

    def test_most_exposed_asset_exists(self, report):
        """most_exposed_asset should be one of the defined assets."""
        asset_names = {a.name for a in report.assets} | {"N/A"}
        assert report.summary["most_exposed_asset"] in asset_names


class TestReportEdgeCases:
    """Edge cases for the full pipeline."""

    def test_no_threats(self):
        """System with assets but no threats."""
        report = generate_threat_report(
            "Safe System", "Nothing to worry about",
            ASSET_DATA, [], SURFACE_DATA,
        )
        assert len(report.threats) == 0
        assert len(report.risk_scores) == 0
        assert report.summary["total_threats"] == 0

    def test_no_surfaces(self):
        """System with assets and threats but no defined surfaces."""
        report = generate_threat_report(
            "Surfaceless", "No entry points defined",
            ASSET_DATA, THREAT_DATA, [],
        )
        assert len(report.attack_surfaces) == 0
        assert report.summary["total_surfaces"] == 0
        # Threats still work without surfaces
        assert len(report.threats) == 4

    def test_minimal_system(self):
        """Minimal valid input: one asset, one threat, one surface."""
        report = generate_threat_report(
            "Tiny",
            "Minimal system",
            [{"name": "DB", "category": "data", "description": "A database",
              "cia": {"confidentiality": "HIGH"}}],
            [{"description": "Data leak", "attack_type": "passive",
              "target_asset": "DB", "cia_category": "confidentiality",
              "likelihood": "LIKELY"}],
            [{"name": "Network", "description": "Open port",
              "exposed_assets": ["DB"]}],
        )
        assert report.summary["total_assets"] == 1
        assert report.summary["total_threats"] == 1
        assert report.summary["total_surfaces"] == 1
        assert report.risk_scores[0].score == 4 * 3  # LIKELY x HIGH = 12
