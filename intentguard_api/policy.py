"""IntentGuard API - Purpose-to-Envelope policy catalog.

Each purpose maps to the HTTP methods and path prefixes that purpose authorizes.
The gateway's structural match (step 4) checks every request against this.

In production this would load from a policy store or compiled config file.
"""

ENVELOPE_CATALOG: dict[str, dict] = {
    "read-invoices": {
        "allowed_methods": ["GET"],
        "allowed_paths": ["/api/invoices"],
        "description": "Read-only access to invoice data",
    },
    "manage-invoices": {
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "allowed_paths": ["/api/invoices"],
        "description": "Full CRUD on invoices",
    },
    "read-users": {
        "allowed_methods": ["GET"],
        "allowed_paths": ["/api/users"],
        "description": "Read-only access to user directory",
    },
    "manage-users": {
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "allowed_paths": ["/api/users"],
        "description": "Full CRUD on user accounts",
    },
    "system-admin": {
        "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "allowed_paths": ["/"],
        "description": "Unrestricted administrative access",
    },
}
