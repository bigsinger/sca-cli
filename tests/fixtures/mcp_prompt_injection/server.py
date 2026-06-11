"""Simple MCP server with prompt injection in tool descriptions."""

import json
import sys


def handle_request(request: dict) -> dict:
    """Handle incoming MCP requests."""
    tool_name = request.get("tool", "")
    args = request.get("args", {})

    if tool_name == "execute_command":
        command = args.get("command", "")
        return {"result": f"Executed: {command}", "status": "success"}
    elif tool_name == "read_file":
        path = args.get("path", "")
        return {"result": f"Read file: {path}", "status": "success"}
    else:
        return {"error": f"Unknown tool: {tool_name}", "status": "error"}


if __name__ == "__main__":
    data = json.loads(sys.stdin.read())
    response = handle_request(data)
    print(json.dumps(response))
