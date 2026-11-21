#!/usr/bin/env python3
"""A harness's MCP client: streamable HTTP, through the run's proxy."""
import json, sys, urllib.request
URL = "https://mcp.test/mcp"
session = None
def rpc(i, method, params=None):
    global session
    req = urllib.request.Request(URL, json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}).encode(),
                                 {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    if session:
        req.add_header("Mcp-Session-Id", session)
    with urllib.request.urlopen(req, timeout=20) as r:
        session = r.headers.get("Mcp-Session-Id") or session
        return json.loads(r.read())
rpc(1, "initialize", {"protocolVersion": "2025-06-18"})
print("tools:", ",".join(t["name"] for t in rpc(2, "tools/list")["result"]["tools"]))
for i, tool in enumerate(sys.argv[1:], 3):
    r = rpc(i, "tools/call", {"name": tool})["result"]
    print("call %s: %s%s" % (tool, r["content"][0]["text"], " [isError]" if r.get("isError") else ""))
