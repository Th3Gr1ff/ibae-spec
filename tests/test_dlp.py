#!/usr/bin/env python3
"""Tests for IntentGuard DLP scanner."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from intentguard_ai.dlp import scan_text, scan_email, summary, Action, Severity

# -- SSN --
def test_ssn_with_context():
    text = "Employee SSN: 123-45-6789 on file"
    result = scan_text(text)
    assert result.has_sensitive_data
    ssn_findings = [f for f in result.findings if f.pattern_name == "ssn"]
    assert len(ssn_findings) == 1
    assert ssn_findings[0].severity == Severity.CRITICAL
    assert "123-45-6789" not in result.redacted_content
    assert "[SSN REDACTED]" in result.redacted_content
    print("  PASS: SSN with context detected and redacted")

def test_ssn_without_context():
    text = "Reference number: 123-45-6789"
    result = scan_text(text)
    ssn_findings = [f for f in result.findings if f.pattern_name == "ssn"]
    assert len(ssn_findings) == 0
    print("  PASS: SSN-shaped number without context not flagged (reduces FP)")

# -- Credit card --
def test_credit_card_luhn():
    text = "Card: 4111-1111-1111-1111 on file"
    result = scan_text(text)
    cc_findings = [f for f in result.findings if f.pattern_name == "credit_card"]
    assert len(cc_findings) == 1
    assert "...1111" in cc_findings[0].redacted_text
    print("  PASS: Credit card (Luhn valid) detected, last-4 preserved")

def test_invalid_cc_not_flagged():
    text = "Number: 1234-5678-9012-3456"
    result = scan_text(text)
    cc_findings = [f for f in result.findings if f.pattern_name == "credit_card"]
    assert len(cc_findings) == 0
    print("  PASS: Invalid CC (fails Luhn) not flagged")

# -- API keys --
def test_api_key_blocks():
    text = "Use this key: sk-abc123def456ghi789jkl012mno345pqr678"
    result = scan_text(text)
    key_findings = [f for f in result.findings if f.pattern_name == "api_key"]
    assert len(key_findings) == 1
    assert result.blocked
    print("  PASS: API key detected, scan blocked")

def test_aws_key():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    result = scan_text(text)
    key_findings = [f for f in result.findings if f.pattern_name == "api_key"]
    assert len(key_findings) == 1
    print("  PASS: AWS access key detected")

# -- Private key --
def test_private_key_blocks():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    result = scan_text(text)
    assert result.blocked
    print("  PASS: Private key detected, scan blocked")

# -- PHI --
def test_mrn():
    text = "Patient MRN: 1234567890, admitted 2026-01-15"
    result = scan_text(text)
    mrn_findings = [f for f in result.findings if f.pattern_name == "mrn"]
    assert len(mrn_findings) == 1
    assert "[MRN REDACTED]" in result.redacted_content
    print("  PASS: MRN detected and redacted")

# -- Financial --
def test_ein_with_context():
    text = "Company EIN: 12-3456789"
    result = scan_text(text)
    ein_findings = [f for f in result.findings if f.pattern_name == "ein"]
    assert len(ein_findings) == 1
    print("  PASS: EIN with context detected")

def test_salary_context():
    text = "Her annual salary is $125,000.00 before bonus"
    result = scan_text(text)
    sal_findings = [f for f in result.findings if f.pattern_name == "salary"]
    assert len(sal_findings) == 1
    assert sal_findings[0].action == Action.FLAG
    print("  PASS: Salary data flagged (not redacted)")

# -- Connection string --
def test_connection_string():
    text = 'Server=db.prod.internal;Database=hr;User=admin;Password=S3cret!Pass'
    result = scan_text(text)
    conn_findings = [f for f in result.findings if f.pattern_name == "connection_string"]
    assert len(conn_findings) == 1
    print("  PASS: Connection string detected")

# -- Email wrapper --
def test_email_scan():
    result = scan_email(
        subject="Employee SSN verification",
        body="Please verify SSN 987-65-4321 for payroll.\nAccount number: 12345678901234",
        sender="hr@company.com",
        recipients=["payroll@company.com"],
    )
    assert result.has_sensitive_data
    s = summary(result)
    assert s["finding_count"] > 0
    print(f"  PASS: Email scan found {s['finding_count']} findings across {s['findings_by_category']}")

# -- Policy override --
def test_policy_override():
    text = "SSN: 111-22-3333 for John Doe"
    result_default = scan_text(text)
    result_block = scan_text(text, policy={"ssn": "block"})
    assert result_default.findings[0].action == Action.REDACT
    assert result_block.findings[0].action == Action.BLOCK
    print("  PASS: Policy override changes action from redact to block")

# -- Clean text --
def test_clean_text():
    text = "This is a normal business email about Q3 planning. No sensitive data here."
    result = scan_text(text)
    assert not result.has_sensitive_data
    assert result.redacted_content == text
    print("  PASS: Clean text passes through unchanged")


if __name__ == "__main__":
    tests = [
        test_ssn_with_context,
        test_ssn_without_context,
        test_credit_card_luhn,
        test_invalid_cc_not_flagged,
        test_api_key_blocks,
        test_aws_key,
        test_private_key_blocks,
        test_mrn,
        test_ein_with_context,
        test_salary_context,
        test_connection_string,
        test_email_scan,
        test_policy_override,
        test_clean_text,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed+failed} tests passed")
    sys.exit(1 if failed else 0)
