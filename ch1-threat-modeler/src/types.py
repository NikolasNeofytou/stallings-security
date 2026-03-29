"""
Module: types
Purpose: Data structures for the threat modeling system.
Chapter Reference: Section 1.1 (CIA), 1.2 (Threats/Assets), 1.5 (Attack Surfaces)

All types are defined here. You won't need to modify this file --
just import and use these structures in core.py.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CIACategory(Enum):
    """The three pillars of information security (Section 1.1)."""
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"


class ImpactLevel(Enum):
    """How severely a breach would affect the asset."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Likelihood(Enum):
    """How probable the threat is, given the system's exposure."""
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class AttackType(Enum):
    """Stallings Section 1.2: passive vs active attacks."""
    PASSIVE = "passive"    # Eavesdropping, traffic analysis
    ACTIVE = "active"      # Modification, DoS, replay, masquerade


class AssetCategory(Enum):
    """Classification of what needs protection."""
    DATA = "data"
    SERVICE = "service"
    INFRASTRUCTURE = "infrastructure"
    PERSONNEL = "personnel"


@dataclass
class CIAImpact:
    """
    CIA impact rating for a single asset.
    Each property is rated independently -- an asset can have
    HIGH confidentiality impact but LOW availability impact.
    """
    confidentiality: ImpactLevel = ImpactLevel.NONE
    integrity: ImpactLevel = ImpactLevel.NONE
    availability: ImpactLevel = ImpactLevel.NONE

    @property
    def max_impact(self) -> ImpactLevel:
        """Return the highest impact across all three categories."""
        return max(
            self.confidentiality,
            self.integrity,
            self.availability,
            key=lambda x: x.value,
        )


@dataclass
class Asset:
    """Something of value that needs protection."""
    name: str
    category: AssetCategory
    description: str
    cia_impact: Optional[CIAImpact] = None


@dataclass
class AttackSurface:
    """
    An entry point through which the system can be attacked (Section 1.5).
    Examples: network interface, web form, file upload, API endpoint.
    """
    name: str
    description: str
    exposed_assets: list[str] = field(default_factory=list)  # Asset names


@dataclass
class Threat:
    """
    A potential attack against an asset (Section 1.2).
    Combines what could happen, how bad it would be, and how likely it is.
    """
    description: str
    attack_type: AttackType
    target_asset: str               # Asset name
    cia_category: CIACategory       # Which CIA property is threatened
    likelihood: Likelihood = Likelihood.POSSIBLE
    attack_surface: Optional[str] = None  # AttackSurface name (entry point)


@dataclass
class RiskScore:
    """
    Computed risk for a single threat.
    Risk = likelihood x impact (standard risk matrix approach).
    """
    threat: Threat
    impact_level: ImpactLevel
    likelihood: Likelihood
    score: int                      # Computed: likelihood.value x impact.value
    severity: str                   # "LOW", "MEDIUM", "HIGH", "CRITICAL"


@dataclass
class ThreatReport:
    """The final output: a complete threat model for a system."""
    system_name: str
    system_description: str
    assets: list[Asset]
    attack_surfaces: list[AttackSurface]
    threats: list[Threat]
    risk_scores: list[RiskScore]
    summary: dict                   # Aggregated stats
