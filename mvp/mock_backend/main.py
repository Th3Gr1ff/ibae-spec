"""
Mock backend for MVP: simple FastAPI echo service that returns
whatever it received. Represents the "protected backend API"
in the IntentGuard architecture diagram.
"""
from fastapi import FastAPI, Request

app = FastAPI(title="IntentGuard MVP Mock Backend")


@app.get("/health")
def health():
    return {"status": "ok", "service": "mock_backend"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def echo(path: str, request: Request):
    body = await request.body()
    return {
        "backend": "mock",
        "method": request.method,
        "path": "/" + path,
        "query": dict(request.query_params),
        "body_bytes": len(body),
        "message": (
            f"Backend received your {request.method} to /{path}. "
            f"If you're seeing this, the gateway admitted the request."
        ),
    }
