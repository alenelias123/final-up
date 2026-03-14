"""Tests for the enterprise-mode tailoring logic."""
from __future__ import annotations

import pytest

from app.utils.enterprise import apply_enterprise_tailoring, _boost_severity, _severity_gte


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity="medium", category="transport_security", title="Test Finding"):
    return {
        "title": title,
        "severity": severity,
        "confidence": "high",
        "category": category,
        "affected_url": "https://example.com",
        "evidence": {},
        "recommendation": "Fix it.",
        "fingerprint_hash": "abc123",
    }


# ---------------------------------------------------------------------------
# _severity_gte
# ---------------------------------------------------------------------------

def test_severity_gte_equal():
    assert _severity_gte("medium", "medium") is True


def test_severity_gte_higher():
    assert _severity_gte("high", "medium") is True


def test_severity_gte_lower():
    assert _severity_gte("low", "medium") is False


# ---------------------------------------------------------------------------
# _boost_severity
# ---------------------------------------------------------------------------

def test_boost_severity_returns_higher():
    assert _boost_severity("low", "high") == "high"


def test_boost_severity_no_change_when_already_higher():
    assert _boost_severity("critical", "medium") == "critical"


def test_boost_severity_same():
    assert _boost_severity("medium", "medium") == "medium"


# ---------------------------------------------------------------------------
# apply_enterprise_tailoring – passthrough with empty profile
# ---------------------------------------------------------------------------

def test_empty_profile_returns_all_findings():
    findings = [_finding(), _finding(severity="low")]
    result = apply_enterprise_tailoring(findings, {})
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Severity boost based on industry
# ---------------------------------------------------------------------------

def test_healthcare_boosts_info_disclosure():
    findings = [_finding(severity="low", category="information_disclosure")]
    result = apply_enterprise_tailoring(findings, {"industry": "healthcare"})
    assert result[0]["severity"] == "critical"


def test_finance_boosts_transport_security():
    findings = [_finding(severity="medium", category="transport_security")]
    result = apply_enterprise_tailoring(findings, {"industry": "finance"})
    assert result[0]["severity"] == "critical"


def test_unrecognised_industry_no_boost():
    findings = [_finding(severity="low", category="transport_security")]
    result = apply_enterprise_tailoring(findings, {"industry": "acmecorp"})
    assert result[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

def test_min_severity_filter_removes_low():
    findings = [
        _finding(severity="low"),
        _finding(severity="high"),
    ]
    result = apply_enterprise_tailoring(findings, {"min_severity_filter": "medium"})
    assert len(result) == 1
    assert result[0]["severity"] == "high"


def test_min_severity_filter_keeps_equal():
    findings = [_finding(severity="medium")]
    result = apply_enterprise_tailoring(findings, {"min_severity_filter": "medium"})
    assert len(result) == 1


# ---------------------------------------------------------------------------
# Compliance context added to recommendation
# ---------------------------------------------------------------------------

def test_compliance_context_appended():
    findings = [_finding(category="transport_security")]
    result = apply_enterprise_tailoring(
        findings,
        {"compliance_frameworks": ["PCI-DSS"]},
    )
    rec = result[0]["recommendation"]
    assert "PCI-DSS" in rec
    assert "Compliance relevance" in rec


def test_no_compliance_when_category_unknown():
    findings = [_finding(category="unknown_category")]
    result = apply_enterprise_tailoring(
        findings,
        {"compliance_frameworks": ["PCI-DSS"]},
    )
    # recommendation unchanged (no compliance refs for unknown_category)
    assert result[0]["recommendation"] == "Fix it."


# ---------------------------------------------------------------------------
# Enterprise context added to evidence
# ---------------------------------------------------------------------------

def test_enterprise_context_in_evidence():
    findings = [_finding()]
    result = apply_enterprise_tailoring(
        findings,
        {
            "company_name": "Acme Corp",
            "industry": "finance",
            "tech_stack": ["django", "postgres"],
            "compliance_frameworks": ["PCI-DSS"],
        },
    )
    ctx = result[0]["evidence"].get("enterprise_context", "")
    assert "Acme Corp" in ctx
    assert "finance" in ctx
    assert "django" in ctx


def test_original_findings_not_mutated():
    """apply_enterprise_tailoring must not mutate the input list."""
    original = _finding(severity="low", category="transport_security")
    findings = [original]
    apply_enterprise_tailoring(findings, {"industry": "finance"})
    # The dict passed in should be unchanged
    assert original["severity"] == "low"
