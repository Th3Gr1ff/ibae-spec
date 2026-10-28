"""Demo REST API backend - the thing IntentGuard protects.

A simple invoice + user management API. In a real deployment this would be
your actual microservice. The gateway sits in front of it and only forwards
requests that pass the 6-step admission chain.
"""

import os
from fastapi import FastAPI

app = FastAPI(title="Acme Corp Internal API", version="1.0.0")

INVOICES = {
    "INV-001": {"id": "INV-001", "vendor": "CloudFlare", "amount": 4200.00, "status": "paid"},
    "INV-002": {"id": "INV-002", "vendor": "AWS", "amount": 18750.00, "status": "pending"},
    "INV-003": {"id": "INV-003", "vendor": "Datadog", "amount": 6100.00, "status": "overdue"},
}

USERS = {
    "u-admin": {"id": "u-admin", "name": "Admin", "role": "system-admin", "email": "admin@acme.internal"},
    "u-alice": {"id": "u-alice", "name": "Alice Chen", "role": "finance", "email": "alice@acme.internal"},
    "u-bob": {"id": "u-bob", "name": "Bob Park", "role": "engineering", "email": "bob@acme.internal"},
}

CONFIG = {
    "auth_provider": "okta",
    "mfa_required": True,
    "session_timeout_minutes": 30,
    "api_rate_limit": 1000,
}


@app.get("/api/invoices")
async def list_invoices():
    return {"invoices": list(INVOICES.values())}


@app.get("/api/invoices/{invoice_id}")
async def get_invoice(invoice_id: str):
    inv = INVOICES.get(invoice_id)
    if not inv:
        return {"error": "not_found"}, 404
    return inv


@app.post("/api/invoices")
async def create_invoice():
    return {"created": True, "id": "INV-004", "message": "invoice created"}


@app.delete("/api/invoices/{invoice_id}")
async def delete_invoice(invoice_id: str):
    return {"deleted": True, "id": invoice_id}


@app.get("/api/users")
async def list_users():
    return {"users": list(USERS.values())}


@app.get("/api/users/{user_id}")
async def get_user(user_id: str):
    user = USERS.get(user_id)
    if not user:
        return {"error": "not_found"}, 404
    return user


@app.post("/api/users")
async def create_user():
    return {"created": True, "id": "u-new", "message": "user account created"}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str):
    return {"deleted": True, "id": user_id}


@app.get("/api/admin/config")
async def get_config():
    return CONFIG


@app.post("/api/admin/config")
async def update_config():
    return {"updated": True, "message": "system configuration changed"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "acme-internal-api"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("BACKEND_PORT", "8720"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
