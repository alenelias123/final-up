"""
Enterprise-mode scan tailoring.

Takes a company profile and a list of raw findings, then:
  1. Filters findings by the requested minimum severity.
  2. Enriches recommendations with compliance-framework context
     (PCI-DSS, HIPAA, SOC 2, ISO 27001, GDPR).
  3. Boosts severity of findings that are especially relevant to the
     company's tech stack or industry.
  4. Appends a company-context note to every finding so analysts can
     see why it matters to *this* organisation.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compliance framework mappings
# ---------------------------------------------------------------------------

# category -> list of (framework, control_id, description)
COMPLIANCE_REFS: dict[str, list[tuple[str, str, str]]] = {
    "transport_security": [
        ("PCI-DSS", "4.2.1", "Strong cryptography required for data in transit."),
        ("HIPAA", "164.312(e)(1)", "Transmission security for ePHI."),
        ("SOC2", "CC6.7", "Logical and physical access controls over data in transit."),
        ("ISO27001", "A.10.1", "Cryptographic controls for data in transit."),
        ("GDPR", "Art.32", "Appropriate technical measures including encryption."),
    ],
    "content_security": [
        ("PCI-DSS", "6.4.3", "Manage all scripts on payment pages."),
        ("SOC2", "CC6.1", "Logical access security software."),
    ],
    "cookie_security": [
        ("PCI-DSS", "6.5.10", "Broken authentication and session management."),
        ("HIPAA", "164.312(a)(2)(iii)", "Automatic log-off to prevent unauthorised access."),
    ],
    "cors": [
        ("OWASP Top-10", "A01", "Broken Access Control."),
    ],
    "information_disclosure": [
        ("PCI-DSS", "6.5.5", "Improper error handling."),
        ("HIPAA", "164.308(a)(1)", "Risk analysis and management."),
        ("GDPR", "Art.25", "Data protection by design and by default."),
    ],
    "git_exposure": [
        ("OWASP Top-10", "A05", "Security Misconfiguration."),
        ("PCI-DSS", "6.5.5", "Improper error handling / info disclosure."),
    ],
    "env_exposure": [
        ("OWASP Top-10", "A05", "Security Misconfiguration."),
        ("PCI-DSS", "8.3.2", "Individual non-consumer credentials must be protected."),
    ],
    "backup_exposure": [
        ("OWASP Top-10", "A05", "Security Misconfiguration."),
    ],
    "server_info": [
        ("OWASP Top-10", "A05", "Security Misconfiguration."),
    ],
    "tls": [
        ("PCI-DSS", "4.2.1", "Strong cryptography required for data in transit."),
        ("HIPAA", "164.312(e)(2)(ii)", "Encryption of ePHI in transit."),
    ],
    "auth": [
        ("PCI-DSS", "8.3", "Identify and authenticate access to system components."),
        ("HIPAA", "164.312(d)", "Person or entity authentication."),
    ],
    "subdomain_takeover": [
        ("OWASP Top-10", "A05", "Security Misconfiguration."),
    ],
    "clickjacking": [
        ("PCI-DSS", "6.4.6", "Content Security Policy."),
    ],
}

# Industries where particular categories are considered higher risk
INDUSTRY_SEVERITY_BOOSTS: dict[str, dict[str, str]] = {
    "healthcare": {
        "information_disclosure": "critical",
        "env_exposure": "critical",
        "transport_security": "high",
        "auth": "critical",
    },
    "finance": {
        "transport_security": "critical",
        "cookie_security": "high",
        "cors": "high",
        "env_exposure": "critical",
        "auth": "critical",
    },
    "ecommerce": {
        "transport_security": "high",
        "cookie_security": "high",
        "cors": "high",
        "git_exposure": "critical",
    },
    "government": {
        "information_disclosure": "high",
        "transport_security": "high",
        "auth": "high",
    },
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_gte(a: str, b: str) -> bool:
    """Return True if severity a >= severity b."""
    try:
        return SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b)
    except ValueError:
        return True


def _boost_severity(current: str, desired: str) -> str:
    """Return the higher of the two severities."""
    try:
        idx_current = SEVERITY_ORDER.index(current)
        idx_desired = SEVERITY_ORDER.index(desired)
        return SEVERITY_ORDER[max(idx_current, idx_desired)]
    except ValueError:
        return current


def _compliance_context(category: str, frameworks: list[str]) -> str:
    """Build a short compliance context string for a finding category."""
    refs = COMPLIANCE_REFS.get(category, [])
    if not refs:
        return ""
    matched = [
        f"{fw} {ctrl}: {desc}"
        for fw, ctrl, desc in refs
        if not frameworks or fw in frameworks or fw == "OWASP Top-10"
    ]
    if not matched:
        return ""
    return "Compliance relevance: " + "; ".join(matched)


def apply_enterprise_tailoring(
    findings: list[dict],
    company_profile: dict,
) -> list[dict]:
    """
    Enrich and optionally filter findings for enterprise mode.

    Parameters
    ----------
    findings:
        Raw list of finding dicts produced by correlate_findings().
    company_profile:
        Deserialised CompanyProfile dict (keys: company_name, industry,
        tech_stack, known_asset_ranges, compliance_frameworks,
        max_severity_filter).

    Returns
    -------
    List of enriched (and possibly filtered) finding dicts.
    """
    if not company_profile:
        return findings

    industry: str = (company_profile.get("industry") or "").lower()
    frameworks: list[str] = company_profile.get("compliance_frameworks") or []
    tech_stack: list[str] = [t.lower() for t in (company_profile.get("tech_stack") or [])]
    company_name: str = company_profile.get("company_name") or "your organisation"
    min_severity: str | None = company_profile.get("min_severity_filter")

    industry_boosts = INDUSTRY_SEVERITY_BOOSTS.get(industry, {})

    tailored: list[dict] = []
    for finding in findings:
        f = copy.deepcopy(finding)  # deep copy so nested structures are not mutated

        category: str = f.get("category", "")

        # 1. Severity boost based on industry
        if industry_boosts and category in industry_boosts:
            f["severity"] = _boost_severity(f["severity"], industry_boosts[category])

        # 2. Filter by minimum severity (enterprise teams may only want high/critical)
        if min_severity and not _severity_gte(f["severity"], min_severity):
            continue

        # 3. Add compliance context to recommendation
        compliance_note = _compliance_context(category, frameworks)
        if compliance_note:
            existing_rec = f.get("recommendation") or ""
            f["recommendation"] = (
                f"{existing_rec}\n\n{compliance_note}".strip() if existing_rec else compliance_note
            )

        # 4. Add enterprise context note inside evidence
        evidence = f.get("evidence") or {}
        context_parts = []
        if industry:
            context_parts.append(f"Industry: {industry}")
        if tech_stack:
            context_parts.append(f"Tech stack: {', '.join(tech_stack)}")
        if frameworks:
            context_parts.append(f"Compliance frameworks: {', '.join(frameworks)}")
        if context_parts:
            evidence["enterprise_context"] = (
                f"Tailored for {company_name}. " + " | ".join(context_parts)
            )
        f["evidence"] = evidence

        tailored.append(f)

    return tailored
