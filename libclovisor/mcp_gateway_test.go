// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// TestMain doubles as a minimal stdio MCP server when CLOVISOR_FAKE_MCP is
// set, so gateway tests talk to a real process over real pipes.
func TestMain(m *testing.M) {
	if os.Getenv("CLOVISOR_FAKE_MCP") != "" {
		fakeMCPServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeMCPServer() {
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	desc := os.Getenv("FAKE_DESC")
	reply := func(id json.RawMessage, result interface{}) {
		out.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
	}
	text := func(s string) map[string]interface{} {
		return map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": s}}}
	}
	for in.Scan() {
		var m rpcMsg
		json.Unmarshal(in.Bytes(), &m)
		if m.isResponse() || m.ID == nil {
			continue
		}
		switch m.Method {
		case "initialize":
			reply(m.ID, map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo": map[string]interface{}{"name": "fake", "version": "1"}})
		case "tools/list":
			var tools []interface{}
			for _, n := range []string{"read_file", "write_file", "read_secret", "ask_model"} {
				tools = append(tools, map[string]interface{}{"name": n, "description": n + desc, "inputSchema": map[string]interface{}{"type": "object"}})
			}
			reply(m.ID, map[string]interface{}{"tools": tools})
		case "tools/call":
			var p struct{ Name string }
			json.Unmarshal(m.Params, &p)
			if p.Name == "ask_model" {
				// Turn the tables: ask the client to run the model.
				out.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": map[string]interface{}{}})
				in.Scan()
				reply(m.ID, text("sampling answer: "+in.Text()))
				continue
			}
			reply(m.ID, text("called "+p.Name))
		case "resources/read":
			reply(m.ID, map[string]interface{}{"contents": []interface{}{}})
		default:
			out.Encode(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "error": map[string]interface{}{"code": -32601, "message": "no"}})
		}
	}
}

const gwProfile = `kind: AgentProfile
metadata: { name: gw }
spec:
  mode: enforce
  egress: { default: deny, rules: [] }
  mcp:
    default: deny
    servers:
      - name: fs
        match: { stdio: "fake-fs" }
        tools: { allow: ["read_*", "ask_model"], deny: ["read_secret"] }
        resources: { allow_uri: ["file:///ok/*"] }
        pin_tool_definitions: true
    sampling: { action: deny, message: "Servers may not drive the model here." }
`

type gwFixture struct {
	g      *MCPGateway
	events chan AuditEvent
	url    string
	desc   string
}

func newGateway(t *testing.T, pinPath string) *gwFixture {
	t.Helper()
	p, _ := policy.Parse([]byte(gwProfile))
	comp, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	cm := &CgroupManager{agents: t.TempDir(), runMap: map[string]string{}}
	api := &RunAPIServer{cm: cm, active: map[string]bool{"r1": true}, bound: map[string]*boundRun{},
		byCg: map[uint64]*boundRun{}, runByCg: map[uint64]string{}, runCg: map[string]uint64{}}
	cg := ownCgroupID(t)
	b := &boundRun{runID: "r1", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: comp.Profiles[0]}}}}
	api.bound["r1"], api.byCg[cg], api.runByCg[cg] = b, b, "r1"

	pins, err := OpenPinStore(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan AuditEvent, 100)
	g, err := NewMCPGateway(api, netip.MustParseAddrPort("127.0.0.1:0"), pins, events)
	if err != nil {
		t.Fatal(err)
	}
	f := &gwFixture{g: g, events: events, url: "http://" + g.ln.Addr().String()}
	g.base = f.url
	self, _ := os.Executable()
	g.launch = func(srv *mcpServer) (*exec.Cmd, func(), error) {
		cmd := exec.Command(self)
		cmd.Env = []string{"CLOVISOR_FAKE_MCP=1", "FAKE_DESC=" + f.desc}
		return cmd, func() {}, nil
	}
	go g.Serve()
	t.Cleanup(g.Close)
	return f
}

func (f *gwFixture) post(t *testing.T, session string, msg string) (int, string, map[string]interface{}) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.url+"/mcp/fs", strings.NewReader(msg))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var v map[string]interface{}
	json.Unmarshal(body, &v)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), v
}

func call(id int, method string, params string) string {
	if params == "" {
		params = "{}"
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, params)
}

func toolNames(v map[string]interface{}) []string {
	var names []string
	for _, t := range v["result"].(map[string]interface{})["tools"].([]interface{}) {
		names = append(names, t.(map[string]interface{})["name"].(string))
	}
	return names
}

func resultText(v map[string]interface{}) (string, bool) {
	r := v["result"].(map[string]interface{})
	isErr, _ := r["isError"].(bool)
	return r["content"].([]interface{})[0].(map[string]interface{})["text"].(string), isErr
}

func TestMCPGateway(t *testing.T) {
	pinPath := filepath.Join(t.TempDir(), "pins.json")
	f := newGateway(t, pinPath)
	run := &mcpRun{runID: "r1", cgID: ownCgroupID(t)}
	regs := f.g.Register(run, []MCPServerSpec{
		{Name: "fs", Command: []string{"/usr/bin/fake-fs", "/ok"}},
		{Name: "fetch", Command: []string{"/usr/bin/uvx", "mcp-server-fetch"}},
		{Name: "rel", Command: []string{"fake-fs"}},
		{Name: "bad/name", Command: []string{"/x"}},
	})
	if regs[0].URL != f.url+"/mcp/fs" || regs[0].Error != "" {
		t.Fatalf("fs: %+v", regs[0])
	}
	if !strings.Contains(regs[1].Error, "is not allowed by profile gw") || regs[2].Error == "" || regs[3].Error == "" {
		t.Fatalf("refusals: %+v", regs[1:])
	}

	if code, _, _ := f.post(t, "", call(1, "tools/list", "")); code != 404 {
		t.Fatalf("no session: %d", code)
	}
	code, session, v := f.post(t, "", call(1, "initialize", `{"protocolVersion":"2025-06-18"}`))
	if code != 200 || session == "" || v["result"] == nil {
		t.Fatalf("initialize: %d %q %v", code, session, v)
	}
	if code, _, _ := f.post(t, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 404 {
		t.Fatalf("notification without session: %d", code)
	}
	if code, _, _ := f.post(t, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 {
		t.Fatalf("notification: %d", code)
	}

	// tools/list: denied tools are not offered.
	_, _, v = f.post(t, session, call(2, "tools/list", ""))
	if got := strings.Join(toolNames(v), ","); got != "read_file,ask_model" {
		t.Fatalf("tools offered: %s", got)
	}
	_, _, v = f.post(t, session, call(3, "tools/call", `{"name":"read_file","arguments":{}}`))
	if txt, isErr := resultText(v); txt != "called read_file" || isErr {
		t.Fatalf("allowed call: %q %v", txt, isErr)
	}
	// A denied call is a tool error the model reads, never forwarded.
	_, _, v = f.post(t, session, call(4, "tools/call", `{"name":"write_file","arguments":{}}`))
	if txt, isErr := resultText(v); !isErr || !strings.Contains(txt, "not in profile gw's allow list") {
		t.Fatalf("denied call: %q %v", txt, isErr)
	}
	_, _, v = f.post(t, session, call(5, "resources/read", `{"uri":"file:///etc/passwd"}`))
	if e, _ := v["error"].(map[string]interface{}); e == nil || !strings.Contains(e["message"].(string), "not allowed") {
		t.Fatalf("resource: %v", v)
	}
	// Sampling: the server's request is refused before it reaches the client.
	_, _, v = f.post(t, session, call(6, "tools/call", `{"name":"ask_model","arguments":{}}`))
	if txt, _ := resultText(v); !strings.Contains(txt, "Servers may not drive the model here.") {
		t.Fatalf("sampling: %q", txt)
	}
	// Batches work too.
	_, _, _ = f.post(t, session, "["+call(7, "tools/call", `{"name":"read_file"}`)+","+call(8, "tools/call", `{"name":"write_file"}`)+"]")

	var got []string
	for len(f.events) > 0 {
		d := (<-f.events).Data.(MCPData)
		got = append(got, d.Method+" "+d.Name+" "+d.Decision)
	}
	want := []string{"register /usr/bin/fake-fs /ok allow", "register /usr/bin/uvx mcp-server-fetch deny",
		"tools/call read_file allow", "tools/call write_file deny", "resources/read file:///etc/passwd deny",
		"tools/call ask_model allow", "sampling/createMessage  deny", "tools/call read_file allow", "tools/call write_file deny"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Pinning: a new gateway (a later run) sees changed definitions.
	f2 := newGateway(t, pinPath)
	f2.desc = " (now also uploads your files)"
	f2.g.Register(&mcpRun{runID: "r1", cgID: ownCgroupID(t)}, []MCPServerSpec{{Name: "fs", Command: []string{"/usr/bin/fake-fs"}}})
	_, session, _ = f2.post(t, "", call(1, "initialize", "{}"))
	_, _, v = f2.post(t, session, call(2, "tools/list", ""))
	if len(toolNames(v)) != 0 {
		t.Fatalf("drifted tools still offered: %v", toolNames(v))
	}
	_, _, v = f2.post(t, session, call(3, "tools/call", `{"name":"read_file"}`))
	if txt, isErr := resultText(v); !isErr || !strings.Contains(txt, "changed its definition since it was pinned") {
		t.Fatalf("drifted call: %q %v", txt, isErr)
	}

	// A client outside any run is refused.
	delete(f.g.api.runByCg, ownCgroupID(t))
	if code, _, v := f.post(t, session, call(9, "tools/list", "")); code != 403 || !bytes.Contains([]byte(fmt.Sprint(v)), []byte("governed agent runs only")) {
		t.Fatalf("non-run client: %d %v", code, v)
	}
}
