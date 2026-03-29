"""
Test suite: test_hard.py
Chapter 1: Overview and Key Concepts

Remember feel_the_problem.py? That ad-hoc analysis missed threats and
had no way to prioritize them. These tests verify that your threat
modeler does it RIGHT -- systematically, with risk scores.

These should pass after TODO 4.
Run with: pytest tests/test_hard.py -v
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
    RiskScore,
    Threat,
)
from src.core import assess_cia_impact, map_threats, compute_risk_scores


# -- Fixtures: the MiniShop scenario from Phase 1 ------------------------------

@pytest.fixture
def minishop_assets():
    """The same assets from feel_the_problem.py, now properly modeled."""
    raw = [
        ("User credentials", AssetCategory.DATA, "Emails and passwords",
         {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"}),
        ("Customer PII", AssetCategory.DATA, "Personal data: email, address",
         {"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"}),
        ("Product catalog", AssetCategory.DATA, "Product names, prices, stock",
         {"confidentiality": "LOW", "integrity": "HIGH", "availability": "HIGH"}),
        ("Admin panel", AssetCategory.SERVICE, "Administrative interface",
         {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"}),
        ("Web server", AssetCategory.INFRASTRUCTURE, "Single Flask server",
         {"confidentiality": "LOW", "integrity": "MEDIUM", "availability": "HIGH"}),
    ]
    assets = []
    for name, cat, desc, cia in raw:
        a = Asset(name=name, category=cat, description=desc)
        a = assess_cia_impact(a, cia)
        assets.append(a)
    return assets


@pytest.fixture
def minishop_threats(minishop_assets):
    """Threats from the Phase 1 analysis."""
    known = [a.name for a in minishop_assets]
    threat_data = [
        {
            "description": "Passwords intercepted over HTTP",
            "attack_type": "passive",
            "target_asset": "User credentials",
            "cia_category": "confidentiality",
            "likelihood": "ALMOST_CERTAIN",
        },
        {
            "description": "SHA-1 hashes cracked via rainbow tables",
            "attack_type": "active",
            "target_asset": "User credentials",
            "cia_category": "confidentiality",
            "likelihood": "LIKELY",
        },
        {
            "description": "SQL injection exposes customer records",
            "attack_type": "active",
            "target_asset": "Customer PII",
            "cia_category": "confidentiality",
            "likelihood": "POSSIBLE",
        },
        {
            "description": "Price tampering via request manipulation",
            "attack_type": "active",
            "target_asset": "Product catalog",
            "cia_category": "integrity",
            "likelihood": "POSSIBLE",
        },
        {
            "description": "Brute force on /admin endpoint",
            "attack_type": "active",
            "target_asset": "Admin panel",
            "cia_category": "confidentiality",
            "likelihood": "LIKELY",
        },
        {
            "description": "Single point of failure -- server crash",
            "attack_type": "active",
            "target_asset": "Web server",
            "cia_category": "availability",
            "likelihood": "POSSIBLE",
        },
    ]
    return map_threats(threat_data, known)


# -- TestRiskScoring (TODO 4) --------------------------------------------------

class TestRiskScoring:
    """The Phase 1 scenario -- now with proper risk quantification."""

    def test_scores_computed_for_all_threats(self, minishop_threats, minishop_assets):
        """Every threat gets a risk score."""
        scores = compute_risk_scores(minishop_threats, minishop_assets)
        assert len(scores) == len(minishop_threats)

    def test_score_is_likelihood_times_impact(self, minishop_threats, minishop_assets):
        """Risk = likelihood x impact for the relevant CIA category."""
        scores = compute_risk_scores(minishop_threats, minishop_assets)

        # First threat: "Passwords intercepted over HTTP"
        # target: User credentials, cia: confidentiality -> HIGH (3)
        # likelihood: ALMOST_CERTAIN (5)
        # expected score: 5 x 3 = 15
        http_score = scores[0]
        assert http_score.score == 5 * 3  # 15

    def test_severity_labels_correct(self, minishop_threats, minishop_assets):
        """Severity labels match the score thresholds."""
        scores = compute_risk_scores(minishop_threats, minishop_assets)

        for rs in scores:
            if rs.score >= 12:
                assert rs.severity == "CRITICAL"
            elif rs.score >= 8:
                assert rs.severity == "HIGH"
            elif rs.score >= 4:
                assert rs.severity == "MEDIUM"
            else:
                assert rs.severity == "LOW"

    def test_http_interception_is_critical(self, minishop_threats, minishop_assets):
        """The no-HTTPS threat should be CRITICAL -- highest risk."""
        scores = compute_risk_scores(minishop_threats, minishop_assets)
        http_score = next(
            s for s in scores
            if "HTTP" in s.threat.description
        )
        assert http_score.severity == "CRITICAL"

    def test_different_cia_categories_use_correct_impact(self, minishop_assets):
        """Threats to different CIA categories pull the right impact level."""
        known = [a.name for a in minishop_assets]

        # Product catalog: C=LOW(1), I=HIGH(3), A=HIGH(3)
        threats = map_threats([
            {
                "description": "Steal product data",
                "attack_type": "passive",
                "target_asset": "Product catalog",
                "cia_category": "confidentiality",
                "likelihood": "POSSIBLE",
            },
            {
                "description": "Tamper with prices",
                "attack_type": "active",
                "target_asset": "Product catalog",
                "cia_category": "integrity",
                "likelihood": "POSSIBLE",
            },
        ], known)

        scores = compute_risk_scores(threats, minishop_assets)

        # Confidentiality = LOW (1) x POSSIBLE (3) = 3
        assert scores[0].score == 3
        # Integrity = HIGH (3) x POSSIBLE (3) = 9
        assert scores[1].score == 9

    def test_risk_score_fields_populated(self, minishop_threats, minishop_assets):
        """Every RiskScore has all fields set."""
        scores = compute_risk_scores(minishop_threats, minishop_assets)

        for rs in scores:
            assert isinstance(rs, RiskScore)
            assert rs.threat is not None
            assert isinstance(rs.impact_level, ImpactLevel)
            assert isinstance(rs.likelihood, Likelihood)
            assert isinstance(rs.score, int)
            assert rs.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_empty_threats(self, minishop_assets):
        """No threats -> no scores."""
        assert compute_risk_scores([], minishop_assets) == []

    def test_asset_without_cia_defaults_to_none(self):
        """If asset has no cia_impact, impact should be NONE (0)."""
        bare_asset = Asset(
            name="Bare",
            category=AssetCategory.DATA,
            description="No CIA assessed",
        )
        threat = Threat(
            description="Some threat",
            attack_type=AttackType.ACTIVE,
            target_asset="Bare",
            cia_category=CIACategory.CONFIDENTIALITY,
            likelihood=Likelihood.LIKELY,
        )
        scores = compute_risk_scores([threat], [bare_asset])
        assert scores[0].score == 0  # LIKELY (4) x NONE (0) = 0
        assert scores[0].severity == "LOW"
