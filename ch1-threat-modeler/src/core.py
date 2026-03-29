"""
Module: core
Purpose: The threat modeling engine -- this is where YOU build the logic.
Chapter Reference: Stallings Ch 1 (Sections 1.1, 1.2, 1.5)

This module contains 5 TODOs that progressively build a complete
threat modeler. Work through them in order, running tests after each.

Concepts you'll implement:
  - CIA impact assessment (Section 1.1)
  - Threat-to-asset mapping (Section 1.2)
  - Attack surface identification (Section 1.5)
  - Attack path construction (Section 1.5)
  - Risk scoring and report generation
"""

from src.types import (
    Asset,
    AssetCategory,
    AttackSurface,
    AttackType,
    CIACategory,
    CIAImpact,
    ImpactLevel,
    Likelihood,
    RiskScore,
    Threat,
    ThreatReport,
)
from src.utils import (
    classify_severity,
    count_by_severity,
    find_most_exposed_asset,
    find_top_cia_concern,
)


# -- TODO 1: CIA Impact Assessment ---------------------------------------------
#
# Implement a function that takes an asset and a dictionary of
# CIA ratings and returns the asset with its cia_impact field populated.
#
# The CIA triad (Section 1.1) rates each property independently:
#   - Confidentiality: what's the damage if this asset is disclosed?
#   - Integrity: what's the damage if this asset is modified?
#   - Availability: what's the damage if this asset becomes unavailable?
#
# Input: an Asset and a dict like:
#   {"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"}
#
# Output: the same Asset with cia_impact set to a CIAImpact instance.
#
# Hint: Convert string levels to ImpactLevel enum members.
#       Handle missing keys by defaulting to ImpactLevel.NONE.
#
# After this works, tests in test_basic.py::TestCIAAssessment should pass.

def assess_cia_impact(asset: Asset, ratings: dict[str, str]) -> Asset:
    """Assess CIA impact for an asset given string ratings."""
    # TODO 1: your implementation here
    raise NotImplementedError("TODO 1: implement CIA impact assessment")


# -- TODO 2: Threat Mapping ----------------------------------------------------
#
# Implement a function that creates Threat objects from a structured
# description and validates that each threat references a known asset.
#
# Section 1.2 distinguishes passive attacks (eavesdropping, monitoring)
# from active attacks (modification, DoS, masquerade, replay).
#
# Input:
#   - threat_data: a list of dicts, each with keys:
#       "description", "attack_type" ("passive"/"active"),
#       "target_asset" (asset name), "cia_category" ("confidentiality"/
#       "integrity"/"availability"), and optionally "likelihood" and
#       "attack_surface"
#   - known_assets: list of asset names that exist in the model
#
# Output: list of Threat objects (only for threats whose target_asset
#         is in known_assets -- skip threats targeting unknown assets)
#
# Hint: Use AttackType and CIACategory enums. Default likelihood to
#       Likelihood.POSSIBLE if not specified.
#
# After this works, tests in test_basic.py::TestThreatMapping should pass.

def map_threats(
    threat_data: list[dict],
    known_assets: list[str],
) -> list[Threat]:
    """Map raw threat descriptions to validated Threat objects."""
    # TODO 2: your implementation here
    raise NotImplementedError("TODO 2: implement threat mapping")


# -- TODO 3: Attack Surface Identification -------------------------------------
#
# Implement a function that analyzes a system description and produces
# a list of AttackSurface objects.
#
# Section 1.5 defines attack surface as the set of reachable and
# exploitable entry points. Each surface should list which assets
# it exposes.
#
# Input: a list of dicts, each with keys:
#   "name", "description", "exposed_assets" (list of asset names)
#
# Output: list of AttackSurface objects
#
# Validation: only include asset names that exist in known_assets.
#   If an exposed_asset isn't in known_assets, silently drop it.
#
# Hint: This is simpler than it looks -- the main job is structured
#       construction with validation. The hard thinking is in deciding
#       WHAT the surfaces are (which you do when using the tool, not
#       when building it).
#
# After this works, tests in test_edges.py should pass.

def identify_attack_surfaces(
    surface_data: list[dict],
    known_assets: list[str],
) -> list[AttackSurface]:
    """Identify and validate attack surfaces."""
    # TODO 3: your implementation here
    raise NotImplementedError("TODO 3: implement attack surface identification")


# -- TODO 4: Risk Scoring ------------------------------------------------------
#
# Implement a function that computes a RiskScore for each threat.
#
# Risk = Likelihood x Impact
#   - Likelihood comes from the Threat object
#   - Impact comes from the target asset's CIA rating for the
#     specific CIA category the threat targets
#
# Example: A threat targeting "User credentials" with cia_category
# CONFIDENTIALITY and likelihood LIKELY -> look up the confidentiality
# impact of "User credentials" (say HIGH=3), multiply by LIKELY=4,
# score = 12.
#
# Use classify_severity() from utils to get the severity label.
#
# Input:
#   - threats: list of Threat objects
#   - assets: list of Asset objects (with cia_impact populated)
#
# Output: list of RiskScore objects, one per threat
#
# Hint: You need to look up the asset by name, then get the right
#       CIA impact level based on the threat's cia_category.
#       If the asset has no cia_impact, default to ImpactLevel.NONE.
#
# After this works, tests in test_hard.py should pass.

def compute_risk_scores(
    threats: list[Threat],
    assets: list[Asset],
) -> list[RiskScore]:
    """Compute risk scores for all threats."""
    # TODO 4: your implementation here
    raise NotImplementedError("TODO 4: implement risk scoring")


# -- TODO 5: Generate Report ---------------------------------------------------
#
# Implement a function that ties everything together: given a system
# name, description, and raw input data, produce a complete
# ThreatReport.
#
# This orchestrates TODOs 1-4 in sequence:
#   1. Create Asset objects and assess CIA impact for each
#   2. Map threats to validated assets
#   3. Identify attack surfaces
#   4. Compute risk scores
#   5. Build summary statistics
#
# Input:
#   - system_name: str
#   - system_description: str
#   - asset_data: list of dicts with keys:
#       "name", "category" (str matching AssetCategory),
#       "description", "cia" (dict of CIA ratings)
#   - threat_data: list of dicts (same format as TODO 2)
#   - surface_data: list of dicts (same format as TODO 3)
#
# Output: a ThreatReport with all fields populated, including summary:
#   {
#       "total_assets": int,
#       "total_surfaces": int,
#       "total_threats": int,
#       "critical_count": int,
#       "high_count": int,
#       "medium_count": int,
#       "low_count": int,
#       "top_cia_concern": str,
#       "most_exposed_asset": str,
#   }
#
# Hint: Use AssetCategory[category_string.upper()] to convert strings.
#       Use count_by_severity(), find_top_cia_concern(), and
#       find_most_exposed_asset() from utils for the summary.
#
# After this works, tests in test_properties.py should pass.

def generate_threat_report(
    system_name: str,
    system_description: str,
    asset_data: list[dict],
    threat_data: list[dict],
    surface_data: list[dict],
) -> ThreatReport:
    """Generate a complete threat model report."""
    # TODO 5: your implementation here
    raise NotImplementedError("TODO 5: implement report generation")
