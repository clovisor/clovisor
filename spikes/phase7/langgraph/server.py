# Copyright (c) Authors of Clovisor
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

"""Phase 7.0 spike: many agent sessions in one LangGraph process.

Each session is a prebuilt ReAct agent with one tool, "bash", which does
its work in-process ("fetch URL" through the session's HTTP client), so
that nothing distinguishes the sessions to the kernel. Sessions run
concurrently, in threads.

    server.py shared       sessions use the process's proxy and trust
                           settings: one run for all
    server.py default-client  as shared, but the model uses langchain-openai's
                           own HTTP client
    server.py per-session  each session creates a run of its own through
                           the run API, and sends through that run's proxy
                           URL: one run per session (credential identity)
    server.py sessions     each session mints a session inside the
                           process's run (op session, milestone 7.3), and
                           sends through its proxy URL: nested in the run,
                           with either identity

Each session is NAME=PATH[=PROFILE]: its tool fetches
https://origin.test/PATH; per-session and sessions, its run or session
requests PROFILE (default: the second argument).
"""

import json
import os
import socket
import ssl
import sys
import threading
import urllib.parse

import httpx
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

MODEL = "https://origin.test:8443/v1"
SOCK = os.environ.get("CLOVISOR_SOCKET", "/run/clovisor/agent.sock")


def trust(cafile):
    """The run's trust bundle, plus the origin's own CA for what the
    proxy does not terminate."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.load_verify_locations("/it/test-ca.crt")
    return ctx


def proxy_token():
    """The process's run credential, from the proxy URL agentctl set:
    with credential identity, the proof a session is minted inside the
    run. With cgroup identity there is none, and none is needed."""
    for k in ("https_proxy", "HTTPS_PROXY"):
        u = urllib.parse.urlsplit(os.environ.get(k, ""))
        if u.username and u.username.startswith("run-"):
            return urllib.parse.unquote(u.password or "")
    return ""


class SessionRun:
    """A run of the session's own (op create, credential identity), or a
    session inside the process's run (op session), held for its life on a
    run API connection, as agentctl holds a run."""

    def __init__(self, name, profile, op="create"):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.s.connect(SOCK)
        req = {"op": op, "command": ["langgraph-session", name], "profile": profile}
        if op == "session" and proxy_token():
            req["token"] = proxy_token()
        r = self.call(req)
        if not r.get("ok"):
            raise RuntimeError("%s: %s" % (op, r.get("error")))
        if op == "create" and r.get("identity") != "credential":
            raise RuntimeError("the node knows runs by %s, not by credential" % r.get("identity"))
        self.run_id, self.proxy, self.bundle = r["run_id"], r["proxy"], r.get("trust_bundle")

    def call(self, req):
        self.s.send(json.dumps(req).encode())
        return json.loads(self.s.recv(1 << 16))

    def end(self, code=0):
        self.call({"op": "end", "exit_code": code})
        self.s.close()


def session(name, path, mode, profile, out):
    run = None
    if mode in ("per-session", "sessions"):
        run = SessionRun(name, profile, "session" if mode == "sessions" else "create")
        client = httpx.Client(proxy=run.proxy, verify=trust(run.bundle), timeout=20)
    else:
        # The process's own settings: what agentctl gave the whole run.
        client = httpx.Client(verify=trust(os.environ["SSL_CERT_FILE"]), timeout=20)

    @tool("bash")
    def bash(command: str) -> str:
        """Run a command. 'fetch URL' fetches URL."""
        if command.startswith("fetch "):
            r = client.get(command.split(None, 1)[1])
            return "status %d" % r.status_code
        return "unsupported"

    if mode == "default-client":
        # langchain-openai's own HTTP client, as most apps use it.
        model = ChatOpenAI(model="mock", base_url=MODEL, api_key="x")
    else:
        model = ChatOpenAI(model="mock", base_url=MODEL, api_key="x", http_client=client)
    agent = create_react_agent(model, [bash])
    res = agent.invoke({"messages": [("user", "MOCK-RUN: fetch https://origin.test/%s" % path)]})
    tools = [m.content for m in res["messages"] if m.type == "tool"]
    out[name] = {"run": run.run_id if run else None, "tool": tools, "final": res["messages"][-1].content}
    if run:
        run.end()


def main():
    mode, profile, specs = sys.argv[1], sys.argv[2], sys.argv[3:]
    out, threads = {}, []
    for spec in specs:
        name, path, prof = (spec.split("=") + [profile])[:3]
        t = threading.Thread(target=session, args=(name, path, mode, prof, out))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    for name in sorted(out):
        print("session %s: %s" % (name, json.dumps(out[name])))


if __name__ == "__main__":
    main()
