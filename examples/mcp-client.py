#!/usr/bin/env python3
"""Small stdlib-only MCP client for the local maskura-mcp stdio server."""

import json
import os
import shlex
import subprocess
import sys


def require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def send(process: subprocess.Popen[str], message: dict) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen[str], request_id: int) -> dict:
    assert process.stdout is not None
    for line in process.stdout:
        message = json.loads(line)
        if message.get("id") == request_id:
            if "error" in message:
                raise RuntimeError(message["error"].get("message", "MCP request failed"))
            return message["result"]
    raise RuntimeError("maskura-mcp closed before returning a response")


def request(process: subprocess.Popen[str], request_id: int, method: str, params=None):
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    send(process, message)
    return receive(process, request_id)


def call_tool(process: subprocess.Popen[str], request_id: int, name: str, arguments: dict):
    result = request(
        process,
        request_id,
        "tools/call",
        {"name": name, "arguments": arguments},
    )
    if result.get("isError"):
        text = result.get("content", [{}])[0].get("text", "tool call failed")
        raise RuntimeError(text)
    return result


def main() -> None:
    gateway_url = require("MASKURA_GATEWAY_URL")
    command = shlex.split(os.environ.get("MASKURA_MCP_COMMAND", "maskura-mcp"))
    environment = os.environ.copy()
    environment["MASKURA_GATEWAY_URL"] = gateway_url
    token = os.environ.get("MASKURA_MCP_TOKEN")
    access_key = os.environ.get("MASKURA_ACCESS_KEY")
    secret_key = os.environ.get("MASKURA_SECRET_KEY")
    if token:
        environment["MASKURA_MCP_TOKEN"] = token
    elif access_key and secret_key:
        environment.pop("MASKURA_MCP_TOKEN", None)
        environment["MASKURA_ACCESS_KEY"] = access_key
        environment["MASKURA_SECRET_KEY"] = secret_key
    else:
        raise SystemExit(
            "set MASKURA_MCP_TOKEN, or both MASKURA_ACCESS_KEY and "
            "MASKURA_SECRET_KEY"
        )

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        initialize = request(
            process,
            1,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "maskura-example", "version": "1"},
            },
        )
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = request(process, 2, "tools/list")
        print(f"Connected to {initialize['serverInfo']['name']}")
        print("Tools:", ", ".join(tool["name"] for tool in tools["tools"]))

        if os.environ.get("MCP_EXAMPLE_RUN_MUTATIONS") != "1":
            print("Set MCP_EXAMPLE_RUN_MUTATIONS=1 to run put/get/list/delete.")
            return

        bucket = os.environ.get("MCP_EXAMPLE_BUCKET", "agent-data")
        key = os.environ.get("MCP_EXAMPLE_KEY", "examples/mcp.txt")
        call_tool(
            process,
            3,
            "maskura_put_object",
            {
                "bucket": bucket,
                "key": key,
                "body": "Contact alice@example.com",
                "content_type": "text/plain; charset=utf-8",
            },
        )
        read = call_tool(
            process, 4, "maskura_get_object", {"bucket": bucket, "key": key}
        )
        print("Read:", read["content"][0]["text"])
        listed = call_tool(
            process,
            5,
            "maskura_list_objects",
            {"bucket": bucket, "prefix": "examples/", "max_keys": 10},
        )
        print("List:", listed["content"][0]["text"])
        call_tool(
            process, 6, "maskura_delete_object", {"bucket": bucket, "key": key}
        )
        print(f"Deleted {bucket}/{key}")
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"MCP example failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
