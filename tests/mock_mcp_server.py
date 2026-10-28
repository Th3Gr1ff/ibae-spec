"""Minimal MCP server for testing IntentGuard proxy.

Speaks JSON-RPC 2.0 over stdio. Implements a handful of fake tools:
  - db_query: pretends to query a database
  - summarize: pretends to summarize text
  - format_report: pretends to format a report
  - send_message: pretends to send a message
  - send_email: pretends to send an email (should be DENIED for most purposes)
  - delete_records: pretends to delete records (should be DENIED for most purposes)
"""

import json
import sys


TOOLS = {
    "db_query": {
        "name": "db_query",
        "description": "Query a database table",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "operation": {"type": "string", "enum": ["select", "insert", "update", "delete"]},
                "query": {"type": "string"},
            },
            "required": ["table", "operation"],
        },
    },
    "summarize": {
        "name": "summarize",
        "description": "Summarize provided text",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
            },
            "required": ["text"],
        },
    },
    "format_report": {
        "name": "format_report",
        "description": "Format data into a report",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "object"},
                "format": {"type": "string", "enum": ["markdown", "html", "pdf"]},
            },
        },
    },
    "send_message": {
        "name": "send_message",
        "description": "Send a message to a channel",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["channel", "text"],
        },
    },
    "send_email": {
        "name": "send_email",
        "description": "Send an email",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    "delete_records": {
        "name": "delete_records",
        "description": "Delete records from a table",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "where": {"type": "string"},
            },
            "required": ["table", "where"],
        },
    },
}


def handle_message(msg: dict) -> dict | None:
    method = msg.get("method", "")
    request_id = msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": list(TOOLS.values())},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        if tool_name not in TOOLS:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": f"unknown tool: {tool_name}"},
            }

        response_text = json.dumps({
            "status": "ok",
            "tool": tool_name,
            "args": tool_args,
            "mock_result": f"executed {tool_name} successfully",
        })

        if tool_args.get("_inject_response"):
            response_text = tool_args["_inject_response"]

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": response_text,
                }],
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"unknown method: {method}"},
    }


def main():
    sys.stderr.write("[MockMCP] server started\n")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        resp = handle_message(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
