#!/usr/bin/env python3
"""Email DLP Scanner -- scan M365 mailboxes for sensitive data via Microsoft Graph API.

Uses application-level permissions (Mail.Read) to scan all mailboxes in a tenant
without individual user credentials. Global Admin registers the app and grants
consent once; this scanner authenticates with client credentials.

Usage:
    # Scan all mailboxes
    python email_dlp_scanner.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET

    # Scan specific users
    python email_dlp_scanner.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET \
        --users user1@org.com user2@org.com

    # Scan with custom policy
    python email_dlp_scanner.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET \
        --policy policy.yaml

    # Output to JSONL ledger
    python email_dlp_scanner.py ... --ledger findings.jsonl

Requires: msal, requests (both already installed via azure-identity/ScoutSuite deps)
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import msal
    import requests
except ImportError:
    print("Missing dependencies: pip install msal requests", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intentguard_ai.dlp import scan_email, summary

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/.default"]


def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    result = app.acquire_token_for_client(scopes=SCOPES)
    if "access_token" not in result:
        print(f"Auth failed: {result.get('error_description', result)}", file=sys.stderr)
        sys.exit(1)
    return result["access_token"]


def list_users(token: str) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"}
    users = []
    url = f"{GRAPH_BASE}/users?$select=id,displayName,mail,userPrincipalName&$top=999"
    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return users


def list_messages(token: str, user_id: str, max_messages: int = 100, days_back: int = 30) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"}
    cutoff = datetime.now(timezone.utc).isoformat()
    from datetime import timedelta
    start = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

    messages = []
    url = (
        f"{GRAPH_BASE}/users/{user_id}/messages"
        f"?$filter=receivedDateTime ge {start}"
        f"&$select=id,subject,from,toRecipients,receivedDateTime,body"
        f"&$top=50"
        f"&$orderby=receivedDateTime desc"
    )
    while url and len(messages) < max_messages:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        data = resp.json()
        messages.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return messages[:max_messages]


def extract_email_fields(msg: dict) -> tuple[str, str, str, list[str]]:
    subject = msg.get("subject", "")
    body = msg.get("body", {}).get("content", "")
    sender = msg.get("from", {}).get("emailAddress", {}).get("address", "")
    recipients = [r.get("emailAddress", {}).get("address", "") for r in msg.get("toRecipients", [])]
    return subject, body, sender, recipients


def run_scan(tenant_id: str, client_id: str, client_secret: str,
             target_users: list[str] | None = None,
             max_messages: int = 100,
             days_back: int = 30,
             policy: dict | None = None,
             ledger_path: str | None = None,
             verbose: bool = False) -> dict:
    """Run the full scan. Returns aggregate results."""
    token = get_token(tenant_id, client_id, client_secret)

    if target_users:
        users = [{"userPrincipalName": u, "id": u, "displayName": u} for u in target_users]
    else:
        users = list_users(token)
        if verbose:
            print(f"Found {len(users)} users in tenant", file=sys.stderr)

    ledger_file = open(ledger_path, "a") if ledger_path else None
    aggregate = {
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "users_scanned": 0,
        "messages_scanned": 0,
        "findings_total": 0,
        "findings_by_category": {},
        "blocked_messages": 0,
        "user_results": [],
    }

    for user in users:
        upn = user.get("userPrincipalName") or user.get("mail") or user["id"]
        if verbose:
            print(f"Scanning {upn}...", file=sys.stderr)

        try:
            messages = list_messages(token, upn, max_messages, days_back)
        except requests.HTTPError as e:
            if verbose:
                print(f"  Skipped {upn}: {e}", file=sys.stderr)
            continue

        user_findings = 0
        aggregate["users_scanned"] += 1

        for msg in messages:
            aggregate["messages_scanned"] += 1
            subject, body, sender, recipients = extract_email_fields(msg)
            result = scan_email(subject, body, sender, recipients, policy)

            if result.has_sensitive_data:
                user_findings += len(result.findings)
                aggregate["findings_total"] += len(result.findings)

                if result.blocked:
                    aggregate["blocked_messages"] += 1

                scan_summary = summary(result)
                for cat, count in scan_summary["findings_by_category"].items():
                    aggregate["findings_by_category"][cat] = aggregate["findings_by_category"].get(cat, 0) + count

                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user": upn,
                    "message_id": msg.get("id", ""),
                    "received": msg.get("receivedDateTime", ""),
                    "subject_redacted": subject[:50] + "..." if len(subject) > 50 else subject,
                    "sender": sender,
                    "scan": scan_summary,
                }

                if ledger_file:
                    ledger_file.write(json.dumps(entry) + "\n")
                    ledger_file.flush()

                if verbose:
                    cats = ", ".join(f"{k}:{v}" for k, v in scan_summary["findings_by_category"].items())
                    print(f"  [{msg.get('receivedDateTime', '?')[:10]}] {subject[:60]} -- {cats}", file=sys.stderr)

        if user_findings > 0:
            aggregate["user_results"].append({"user": upn, "findings": user_findings})

    aggregate["scan_end"] = datetime.now(timezone.utc).isoformat()

    if ledger_file:
        ledger_file.close()

    return aggregate


def main():
    parser = argparse.ArgumentParser(description="Scan M365 mailboxes for sensitive data via Graph API")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App client secret")
    parser.add_argument("--users", nargs="*", help="Specific users to scan (default: all)")
    parser.add_argument("--max-messages", type=int, default=100, help="Max messages per user (default: 100)")
    parser.add_argument("--days-back", type=int, default=30, help="How many days back to scan (default: 30)")
    parser.add_argument("--policy", help="Policy YAML file with per-category action overrides")
    parser.add_argument("--ledger", help="Output JSONL ledger file for findings")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    policy = None
    if args.policy:
        import yaml
        with open(args.policy) as f:
            policy = yaml.safe_load(f).get("data_classification", {}).get("rules", {})

    result = run_scan(
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
        target_users=args.users,
        max_messages=args.max_messages,
        days_back=args.days_back,
        policy=policy,
        ledger_path=args.ledger,
        verbose=args.verbose,
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
