"""IntentGuard DLP Scanner -- sensitive data detection on tool results before they enter LLM context.

Scans text for PII, financial data, PHI, and credentials. Returns findings with
classification, location, and recommended action (redact/block/flag). Designed
to run on the proxy hot path: tool result comes back from MCP server, DLP scans
it, redacts or blocks before forwarding to the agent.

Dependency-free (stdlib only). Pattern-based + Luhn validation for credit cards.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Action(Enum):
    REDACT = "redact"
    BLOCK = "block"
    FLAG = "flag"


@dataclass
class Finding:
    category: str
    pattern_name: str
    severity: Severity
    action: Action
    line: int
    column: int
    matched_text: str
    redacted_text: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    redacted_content: Optional[str] = None
    blocked: bool = False
    block_reason: Optional[str] = None

    @property
    def has_sensitive_data(self) -> bool:
        return len(self.findings) > 0


def _luhn_check(num_str: str) -> bool:
    digits = [int(d) for d in num_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _linecol(text: str, idx: int) -> tuple[int, int]:
    line = text[:idx].count("\n") + 1
    last_nl = text.rfind("\n", 0, idx)
    col = idx - last_nl if last_nl >= 0 else idx + 1
    return line, col


# -- Pattern definitions --

SSN_RE = re.compile(r'\b(\d{3}-\d{2}-\d{4})\b')
SSN_CONTEXT = re.compile(r'(ssn|social\s*security|soc\s*sec)', re.I)

CC_RE = re.compile(r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4})\b')

EIN_RE = re.compile(r'\b(\d{2}-\d{7})\b')
EIN_CONTEXT = re.compile(r'(ein|employer\s*id|tax\s*id|federal\s*id)', re.I)

ABA_RE = re.compile(r'\b(\d{9})\b')
ABA_CONTEXT = re.compile(r'(routing|aba|transit|wire)', re.I)

IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{1,4}){0,5})\b')

SWIFT_RE = re.compile(r'\b([A-Z]{4}[A-Z]{2}[A-Z\d]{2}(?:[A-Z\d]{3})?)\b')
SWIFT_CONTEXT = re.compile(r'(swift|bic|bank\s*code)', re.I)

ACCT_RE = re.compile(r'\b(\d{8,17})\b')
ACCT_CONTEXT = re.compile(r'(account\s*(number|#|no|num)|acct)', re.I)

PHONE_RE = re.compile(r'\b(\+?1?\s*\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})\b')

EMAIL_RE = re.compile(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')

DOB_RE = re.compile(r'\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b')
DOB_CONTEXT = re.compile(r'(dob|date\s*of\s*birth|birth\s*date|born)', re.I)

DL_RE = re.compile(r'\b([A-Z]\d{3,8}[\-]?\d{3,8}[\-]?\d{0,4})\b')
DL_CONTEXT = re.compile(r'(driver.?s?\s*licen|dl\s*#|dl\s*num)', re.I)

PASSPORT_RE = re.compile(r'\b([A-Z]\d{8})\b')
PASSPORT_CONTEXT = re.compile(r'(passport)', re.I)

# PHI
MRN_RE = re.compile(r'\b(MRN\s*[:#]?\s*\d{5,12})\b', re.I)
ICD10_RE = re.compile(r'\b([A-TV-Z]\d{2}(?:\.\d{1,4})?)\b')
ICD10_CONTEXT = re.compile(r'(diagnosis|icd|dx\s*code|condition)', re.I)
NPI_RE = re.compile(r'\b(1\d{9})\b')
NPI_CONTEXT = re.compile(r'(npi|provider\s*(number|id|#)|national\s*provider)', re.I)

# Credentials
API_KEY_RE = re.compile(r'(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|xox[boapr]-[a-zA-Z0-9\-]{10,})')
GENERIC_SECRET_RE = re.compile(r'(?i)(password|passwd|pwd|secret|token|api[_\-]?key|private[_\-]?key|access[_\-]?key)\s*[=:]\s*["\']?([^\s"\']{8,})')
PRIVATE_KEY_RE = re.compile(r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----')
CONN_STRING_RE = re.compile(r'(?i)(Server|Data\s+Source|Host|jdbc)[=:].{5,80}(Password|Pwd|Pass)[=:][^\s;]{3,}')

# Financial context
SALARY_CONTEXT = re.compile(r'(salary|compensation|wage|pay\s*rate|annual\s*income|gross\s*pay|net\s*pay|take\s*home|bonus\s*amount|severance)', re.I)
CURRENCY_AMOUNT = re.compile(r'\$[\d,]{3,}(?:\.\d{2})?|\b\d{2,3},\d{3}(?:\.\d{2})?\b')


def _context_window(text: str, idx: int, window: int = 200) -> str:
    start = max(0, idx - window)
    end = min(len(text), idx + window)
    return text[start:end]


def scan_text(text: str, policy: Optional[dict] = None) -> ScanResult:
    """Scan text for sensitive data. Returns ScanResult with findings and redacted content.

    policy: optional dict overriding default actions per category. Shape:
        {"ssn": "redact", "credit_card": "block", "api_key": "block", ...}
    Default actions are used when no policy is provided.
    """
    if policy is None:
        policy = {}

    findings: list[Finding] = []
    blocked = False
    block_reason = None

    def _action_for(category: str, default: Action) -> Action:
        override = policy.get(category)
        if override:
            return Action(override)
        return default

    # SSN
    for m in SSN_RE.finditer(text):
        ctx = _context_window(text, m.start())
        # require contextual keyword nearby OR standalone format (reduces FP on dates)
        if SSN_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("ssn", Action.REDACT)
            findings.append(Finding("pii", "ssn", Severity.CRITICAL, action, line, col, m.group(1), "[SSN REDACTED]"))

    # Credit card (Luhn validated)
    for m in CC_RE.finditer(text):
        digits_only = re.sub(r'[\s\-]', '', m.group(1))
        if _luhn_check(digits_only):
            line, col = _linecol(text, m.start())
            action = _action_for("credit_card", Action.REDACT)
            last4 = digits_only[-4:]
            findings.append(Finding("financial", "credit_card", Severity.CRITICAL, action, line, col, m.group(1), f"[CC REDACTED ...{last4}]"))

    # EIN (with context)
    for m in EIN_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if EIN_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("ein", Action.REDACT)
            findings.append(Finding("financial", "ein", Severity.HIGH, action, line, col, m.group(1), "[EIN REDACTED]"))

    # IBAN
    for m in IBAN_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("iban", Action.REDACT)
        findings.append(Finding("financial", "iban", Severity.HIGH, action, line, col, m.group(1), "[IBAN REDACTED]"))

    # Bank account (with context)
    for m in ACCT_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if ACCT_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("bank_account", Action.REDACT)
            findings.append(Finding("financial", "bank_account", Severity.HIGH, action, line, col, m.group(1), "[ACCT REDACTED]"))

    # Routing number (with context)
    for m in ABA_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if ABA_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("routing_number", Action.REDACT)
            findings.append(Finding("financial", "routing_number", Severity.HIGH, action, line, col, m.group(1), "[ROUTING REDACTED]"))

    # API keys / tokens (no context needed, pattern is specific enough)
    for m in API_KEY_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("api_key", Action.BLOCK)
        findings.append(Finding("credential", "api_key", Severity.CRITICAL, action, line, col, m.group(1), "[API KEY REDACTED]"))
        if action == Action.BLOCK:
            blocked = True
            block_reason = f"API key/token detected at line {line}"

    # Generic secrets (password=..., token=..., etc.)
    for m in GENERIC_SECRET_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("credential", Action.REDACT)
        findings.append(Finding("credential", "generic_secret", Severity.HIGH, action, line, col, m.group(0), f"{m.group(1)}=[REDACTED]"))

    # Private keys
    for m in PRIVATE_KEY_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("private_key", Action.BLOCK)
        findings.append(Finding("credential", "private_key", Severity.CRITICAL, action, line, col, "[PRIVATE KEY]", "[PRIVATE KEY REDACTED]"))
        if action == Action.BLOCK:
            blocked = True
            block_reason = f"Private key detected at line {line}"

    # Connection strings
    for m in CONN_STRING_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("connection_string", Action.REDACT)
        findings.append(Finding("credential", "connection_string", Severity.HIGH, action, line, col, m.group(0), "[CONNECTION STRING REDACTED]"))

    # MRN (medical record number)
    for m in MRN_RE.finditer(text):
        line, col = _linecol(text, m.start())
        action = _action_for("mrn", Action.REDACT)
        findings.append(Finding("phi", "mrn", Severity.CRITICAL, action, line, col, m.group(1), "[MRN REDACTED]"))

    # ICD-10 codes (with context)
    for m in ICD10_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if ICD10_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("icd10", Action.REDACT)
            findings.append(Finding("phi", "icd10", Severity.HIGH, action, line, col, m.group(1), "[DX CODE REDACTED]"))

    # NPI (with context)
    for m in NPI_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if NPI_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("npi", Action.REDACT)
            findings.append(Finding("phi", "npi", Severity.HIGH, action, line, col, m.group(1), "[NPI REDACTED]"))

    # Salary/compensation (contextual keyword near a dollar amount)
    for m in SALARY_CONTEXT.finditer(text):
        ctx = _context_window(text, m.start(), 100)
        amount_match = CURRENCY_AMOUNT.search(ctx)
        if amount_match:
            line, col = _linecol(text, m.start())
            action = _action_for("salary", Action.FLAG)
            findings.append(Finding("financial", "salary", Severity.MEDIUM, action, line, col, f"{m.group(0)}...{amount_match.group(0)}", "[COMPENSATION DATA FLAGGED]"))

    # DOB (with context)
    for m in DOB_RE.finditer(text):
        ctx = _context_window(text, m.start())
        if DOB_CONTEXT.search(ctx):
            line, col = _linecol(text, m.start())
            action = _action_for("dob", Action.REDACT)
            findings.append(Finding("pii", "dob", Severity.MEDIUM, action, line, col, m.group(1), "[DOB REDACTED]"))

    # Build redacted content
    if findings and not blocked:
        redacted = text
        for f in sorted(findings, key=lambda f: f.column, reverse=True):
            if f.action == Action.REDACT:
                redacted = redacted.replace(f.matched_text, f.redacted_text, 1)
        result = ScanResult(findings=findings, redacted_content=redacted, blocked=blocked, block_reason=block_reason)
    elif blocked:
        result = ScanResult(findings=findings, redacted_content=None, blocked=True, block_reason=block_reason)
    else:
        result = ScanResult(findings=findings, redacted_content=text)

    return result


def scan_email(subject: str, body: str, sender: str = "", recipients: list[str] | None = None, policy: Optional[dict] = None) -> ScanResult:
    """Convenience wrapper for email scanning. Combines subject + body + metadata into one scan."""
    combined = f"From: {sender}\n"
    if recipients:
        combined += f"To: {', '.join(recipients)}\n"
    combined += f"Subject: {subject}\n\n{body}"
    return scan_text(combined, policy)


def summary(result: ScanResult) -> dict:
    """Return a JSON-serializable summary of a scan result."""
    return {
        "has_sensitive_data": result.has_sensitive_data,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "finding_count": len(result.findings),
        "findings_by_category": _group_findings(result.findings),
        "findings": [
            {
                "category": f.category,
                "pattern": f.pattern_name,
                "severity": f.severity.value,
                "action": f.action.value,
                "line": f.line,
            }
            for f in result.findings
        ],
    }


def _group_findings(findings: list[Finding]) -> dict[str, int]:
    groups: dict[str, int] = {}
    for f in findings:
        groups[f.category] = groups.get(f.category, 0) + 1
    return groups
