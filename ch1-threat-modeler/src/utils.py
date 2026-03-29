"""
Module: utils
Purpose: Helper functions for formatting, I/O, and report generation.
These are provided for you -- no TODOs here.
"""

from src.types import (
    ImpactLevel,
    Likelihood,
    RiskScore,
    ThreatReport,
    CIACategory,
    AttackType,
)


# -- Severity classification ---------------------------------------------------

RISK_THRESHOLDS = {
    "CRITICAL": 12,  # score >= 12
    "HIGH": 8,       # score >= 8
    "MEDIUM": 4,     # score >= 4
    "LOW": 0,        # score >= 0
}


def classify_severity(score: int) -> str:
    """Map a numeric risk score to a severity label."""
    for label, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            return label
    return "LOW"


# -- Report formatting ---------------------------------------------------------

def format_impact(level: ImpactLevel) -> str:
    """Format an impact level with a visual indicator."""
    indicators = {
        ImpactLevel.NONE: "[ ]",
        ImpactLevel.LOW: "[.]",
        ImpactLevel.MEDIUM: "[..]",
        ImpactLevel.HIGH: "[...]",
        ImpactLevel.CRITICAL: "[!!!!]",
    }
    return f"{indicators.get(level, '?')} {level.name}"


def format_risk_table(risk_scores: list[RiskScore]) -> str:
    """Format risk scores as a readable text table."""
    if not risk_scores:
        return "  No risks identified.\n"

    # Sort by score descending
    sorted_risks = sorted(risk_scores, key=lambda r: r.score, reverse=True)

    lines = []
    lines.append(f"  {'Threat':<45} {'Impact':<10} {'Likely':<15} {'Score':<6} {'Severity'}")
    lines.append(f"  {'-'*45} {'-'*10} {'-'*15} {'-'*6} {'-'*10}")

    for rs in sorted_risks:
        desc = rs.threat.description[:44]
        lines.append(
            f"  {desc:<45} {rs.impact_level.name:<10} "
            f"{rs.likelihood.name:<15} {rs.score:<6} {rs.severity}"
        )

    return "\n".join(lines)


def format_summary(report: ThreatReport) -> str:
    """Format the report summary section."""
    s = report.summary
    lines = [
        f"\n  System: {report.system_name}",
        f"  {report.system_description}\n",
        f"  Assets identified:          {s.get('total_assets', 0)}",
        f"  Attack surfaces identified:  {s.get('total_surfaces', 0)}",
        f"  Threats identified:          {s.get('total_threats', 0)}",
        "",
        f"  Risk breakdown:",
        f"    CRITICAL: {s.get('critical_count', 0)}",
        f"    HIGH:     {s.get('high_count', 0)}",
        f"    MEDIUM:   {s.get('medium_count', 0)}",
        f"    LOW:      {s.get('low_count', 0)}",
        "",
        f"  Top CIA concern:    {s.get('top_cia_concern', 'N/A')}",
        f"  Most exposed asset: {s.get('most_exposed_asset', 'N/A')}",
    ]
    return "\n".join(lines)


def print_full_report(report: ThreatReport) -> str:
    """Format the complete threat model report as a string."""
    sections = []

    sections.append("=" * 60)
    sections.append(f"  THREAT MODEL REPORT: {report.system_name}")
    sections.append("=" * 60)

    # Summary
    sections.append("\n-- SUMMARY " + "-" * 49)
    sections.append(format_summary(report))

    # Assets
    sections.append("\n-- ASSETS " + "-" * 50)
    for asset in report.assets:
        cia = asset.cia_impact
        sections.append(f"\n  {asset.name} ({asset.category.name})")
        sections.append(f"    {asset.description}")
        if cia:
            sections.append(f"    C={format_impact(cia.confidentiality)}")
            sections.append(f"    I={format_impact(cia.integrity)}")
            sections.append(f"    A={format_impact(cia.availability)}")

    # Attack Surfaces
    sections.append("\n-- ATTACK SURFACES " + "-" * 41)
    for surface in report.attack_surfaces:
        sections.append(f"\n  {surface.name}")
        sections.append(f"    {surface.description}")
        if surface.exposed_assets:
            sections.append(f"    Exposes: {', '.join(surface.exposed_assets)}")

    # Risk Table
    sections.append("\n-- RISK ASSESSMENT " + "-" * 41)
    sections.append(format_risk_table(report.risk_scores))

    sections.append("\n" + "=" * 60)

    return "\n".join(sections)


# -- Aggregation helpers -------------------------------------------------------

def count_by_severity(risk_scores: list[RiskScore]) -> dict[str, int]:
    """Count risks by severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for rs in risk_scores:
        counts[rs.severity] = counts.get(rs.severity, 0) + 1
    return counts


def find_top_cia_concern(risk_scores: list[RiskScore]) -> str:
    """Find which CIA category has the most high-severity threats."""
    cia_severity_total: dict[str, int] = {}
    for rs in risk_scores:
        cat = rs.threat.cia_category.value
        cia_severity_total[cat] = cia_severity_total.get(cat, 0) + rs.score
    if not cia_severity_total:
        return "N/A"
    return max(cia_severity_total, key=cia_severity_total.get)


def find_most_exposed_asset(risk_scores: list[RiskScore]) -> str:
    """Find which asset has the highest total risk score."""
    asset_totals: dict[str, int] = {}
    for rs in risk_scores:
        name = rs.threat.target_asset
        asset_totals[name] = asset_totals.get(name, 0) + rs.score
    if not asset_totals:
        return "N/A"
    return max(asset_totals, key=asset_totals.get)
