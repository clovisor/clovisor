// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command mockmodel is the integration tests' scripted model (milestones
// 7.0, 7.1): it speaks enough of the OpenAI Chat Completions, Anthropic
// Messages and Gemini APIs, streaming or not, for a coding agent to run
// one scripted turn. Its first answer calls the agent's shell tool with
// -cmd, or the command a prompt asks for ("MOCK-RUN: <command>"); once a tool
// result comes back, it answers -done. Every request is logged: path,
// model, the tools offered, and the tool results the agent sent back.
//
//	mockmodel -listen :8080 [-cert c -key k] -cmd 'curl -s https://origin.test/allowed'
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var (
	listen = flag.String("listen", ":8080", "listen address")
	cert   = flag.String("cert", "", "TLS certificate (with -key): serve HTTPS")
	key    = flag.String("key", "", "TLS key")
	cmd    = flag.String("cmd", "curl -s -o /dev/null -w 'tool-curl %{http_code}\\n' https://origin.test/allowed", "the shell command the first turn asks for")
	done   = flag.String("done", "mock: done", "the final answer")
)

// shellTool matches the names agents give their shell tool.
var shellTool = regexp.MustCompile(`(?i)^(shell|bash|run_shell_command|exec_command|local_shell|execute_command|terminal)$`)

func main() {
	flag.Parse()
	http.HandleFunc("/", route)
	log.Printf("mockmodel on %s", *listen)
	if *cert != "" {
		log.Fatal(http.ListenAndServeTLS(*listen, *cert, *key, nil))
	}
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func route(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	json.Unmarshal(body, &req)
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/chat/completions"):
		openai(w, req)
	case strings.HasSuffix(p, "/responses"):
		responses(w, req)
	case strings.HasSuffix(p, "/messages"):
		anthropic(w, req)
	case strings.Contains(p, ":generateContent") || strings.Contains(p, ":streamGenerateContent"):
		gemini(w, r, req)
	case strings.Contains(p, ":countTokens"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"totalTokens": 10}`)
		logReq(p, req, "countTokens")
	case strings.HasSuffix(p, "/models"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"mock","object":"model"}],"models":[{"name":"models/mock"}]}`)
		logReq(p, req, "models")
	default:
		logReq(r.Method+" "+p, req, "unhandled: 404")
		http.NotFound(w, r)
	}
}

func logReq(path string, req map[string]any, what string) {
	model, _ := req["model"].(string)
	line := fmt.Sprintf("%s model=%q tools=%v stream=%v -> %s", path, model, toolNames(req), req["stream"], what)
	if r := toolResults(req); len(r) > 0 {
		b, _ := json.Marshal(r)
		line += " tool-results=" + string(b)
	}
	log.Print(line)
}

// toolResults collects what the agent sent back from its tools, in any of
// the four APIs' shapes: what the agent saw, narrated denials included.
func toolResults(req map[string]any) []string {
	var out []string
	var walk func(v any, parentRole string)
	walk = func(v any, parentRole string) {
		switch x := v.(type) {
		case map[string]any:
			role, _ := x["role"].(string)
			switch {
			case x["type"] == "function_call_output": // OpenAI Responses
				out = append(out, flat(x["output"]))
			case x["type"] == "tool_result": // Anthropic
				out = append(out, flat(x["content"]))
			case role == "tool": // OpenAI Chat Completions
				out = append(out, flat(x["content"]))
			case x["functionResponse"] != nil: // Gemini
				out = append(out, flat(x["functionResponse"]))
			default:
				for _, e := range x {
					walk(e, role)
				}
			}
		case []any:
			for _, e := range x {
				walk(e, parentRole)
			}
		}
	}
	for _, k := range []string{"messages", "input", "contents"} {
		walk(req[k], "")
	}
	return out
}

// flat renders a tool result's content as text, whatever its shape.
func flat(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// toolNames lists the tools a request offers, in any of the three shapes.
func toolNames(req map[string]any) []string {
	var out []string
	tools, _ := req["tools"].([]any)
	for _, t := range tools {
		m, _ := t.(map[string]any)
		if f, ok := m["function"].(map[string]any); ok { // OpenAI
			out = append(out, str(f["name"]))
		} else if decls, ok := m["functionDeclarations"].([]any); ok { // Gemini
			for _, d := range decls {
				dm, _ := d.(map[string]any)
				out = append(out, str(dm["name"]))
			}
		} else if n := str(m["name"]); n != "" { // Anthropic
			out = append(out, n)
		}
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

// promptCmd is a command a prompt asks for ("MOCK-RUN: <command>"), so
// that one mock can script several sessions differently. The marker is one
// no agent's own system prompt contains: "run: " is in Claude Code's.
var promptCmd = regexp.MustCompile(`MOCK-RUN: ([^"\\]+)`)

// pickShell finds the shell tool and the arguments to call it with: the
// command as a string, or as an argv when the schema wants an array.
func pickShell(req map[string]any) (name string, args map[string]any) {
	cmd := cmd
	if b, err := json.Marshal(req); err == nil {
		if m := promptCmd.FindSubmatch(b); m != nil {
			c := strings.TrimSpace(string(m[1]))
			cmd = &c
		}
	}
	tools, _ := req["tools"].([]any)
	try := func(n string, params map[string]any) bool {
		if !shellTool.MatchString(n) {
			return false
		}
		props, _ := params["properties"].(map[string]any)
		args = map[string]any{}
		for _, k := range []string{"command", "cmd"} {
			if p, ok := props[k].(map[string]any); ok {
				if p["type"] == "array" {
					args[k] = []string{"bash", "-lc", *cmd}
				} else {
					args[k] = *cmd
				}
				break
			}
		}
		if _, ok := props["description"]; ok {
			args["description"] = "the spike's scripted command"
		}
		name = n
		return true
	}
	for _, t := range tools {
		m, _ := t.(map[string]any)
		if f, ok := m["function"].(map[string]any); ok {
			p, _ := f["parameters"].(map[string]any)
			if try(str(f["name"]), p) {
				return
			}
		} else if decls, ok := m["functionDeclarations"].([]any); ok {
			for _, d := range decls {
				dm, _ := d.(map[string]any)
				p, _ := dm["parameters"].(map[string]any)
				if p == nil {
					p, _ = dm["parametersJsonSchema"].(map[string]any)
				}
				if try(str(dm["name"]), p) {
					return
				}
			}
		} else {
			p, _ := m["input_schema"].(map[string]any) // Anthropic
			if p == nil {
				p, _ = m["parameters"].(map[string]any) // OpenAI Responses
			}
			if try(str(m["name"]), p) {
				return
			}
		}
	}
	return "", nil
}

// answered reports whether the conversation already holds a tool result.
func answered(req map[string]any) bool {
	b, _ := json.Marshal(req)
	s := string(b)
	return strings.Contains(s, `"role":"tool"`) || strings.Contains(s, `"tool_result"`) ||
		strings.Contains(s, `"functionResponse"`) || strings.Contains(s, `"function_call_output"`)
}

func sse(w http.ResponseWriter) func(event string, v any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	fl, _ := w.(http.Flusher)
	return func(event string, v any) {
		if event != "" {
			fmt.Fprintf(w, "event: %s\n", event)
		}
		if s, ok := v.(string); ok {
			fmt.Fprintf(w, "data: %s\n\n", s)
		} else {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

func openai(w http.ResponseWriter, req map[string]any) {
	name, args := "", map[string]any(nil)
	if !answered(req) {
		name, args = pickShell(req)
	}
	what := "final"
	if name != "" {
		what = "tool call " + name
	}
	logReq("/chat/completions", req, what)
	model := str(req["model"])
	usage := map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
	argJSON, _ := json.Marshal(args)
	if stream, _ := req["stream"].(bool); stream {
		send := sse(w)
		chunk := func(delta map[string]any, finish any) map[string]any {
			return map[string]any{"id": "mock-1", "object": "chat.completion.chunk", "created": 1, "model": model,
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		}
		if name != "" {
			send("", chunk(map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"index": 0, "id": "call_1", "type": "function",
				"function": map[string]any{"name": name, "arguments": string(argJSON)}}}}, nil))
			send("", chunk(map[string]any{}, "tool_calls"))
		} else {
			send("", chunk(map[string]any{"role": "assistant", "content": *done}, nil))
			send("", chunk(map[string]any{}, "stop"))
		}
		c := chunk(map[string]any{}, nil)
		c["choices"], c["usage"] = []any{}, usage
		send("", c)
		send("", "[DONE]")
		return
	}
	msg := map[string]any{"role": "assistant", "content": *done}
	finish := "stop"
	if name != "" {
		msg = map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "call_1", "type": "function",
			"function": map[string]any{"name": name, "arguments": string(argJSON)}}}}
		finish = "tool_calls"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": "mock-1", "object": "chat.completion", "created": 1, "model": model,
		"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}}, "usage": usage})
}

func anthropic(w http.ResponseWriter, req map[string]any) {
	name, args := "", map[string]any(nil)
	if !answered(req) {
		name, args = pickShell(req)
	}
	what := "final"
	if name != "" {
		what = "tool call " + name
	}
	logReq("/messages", req, what)
	model := str(req["model"])
	usage := map[string]any{"input_tokens": 10, "output_tokens": 5}
	var block map[string]any
	stop := "end_turn"
	if name != "" {
		block, stop = map[string]any{"type": "tool_use", "id": "toolu_1", "name": name, "input": args}, "tool_use"
	} else {
		block = map[string]any{"type": "text", "text": *done}
	}
	if stream, _ := req["stream"].(bool); !stream {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": "msg_1", "type": "message", "role": "assistant", "model": model,
			"content": []any{block}, "stop_reason": stop, "usage": usage})
		return
	}
	send := sse(w)
	send("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_1", "type": "message",
		"role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "usage": usage}})
	if name != "" {
		argJSON, _ := json.Marshal(args)
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "tool_use", "id": "toolu_1", "name": name, "input": map[string]any{}}})
		send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": string(argJSON)}})
	} else {
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""}})
		send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "text_delta", "text": *done}})
	}
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop}, "usage": map[string]any{"output_tokens": 5}})
	send("message_stop", map[string]any{"type": "message_stop"})
}

func gemini(w http.ResponseWriter, r *http.Request, req map[string]any) {
	name, args := "", map[string]any(nil)
	if !answered(req) {
		name, args = pickShell(req)
	}
	what := "final"
	if name != "" {
		what = "tool call " + name
	}
	logReq(r.URL.Path, req, what)
	part := map[string]any{"text": *done}
	if name != "" {
		part = map[string]any{"functionCall": map[string]any{"name": name, "args": args}}
	}
	resp := map[string]any{
		"candidates":    []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{part}}, "finishReason": "STOP", "index": 0}},
		"usageMetadata": map[string]any{"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
		"modelVersion":  "mock",
	}
	if strings.Contains(r.URL.Path, ":streamGenerateContent") {
		sse(w)("", resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// responses is the OpenAI Responses API, which Codex requires: streamed
// as response.* events, the output items in response.output_item.done.
func responses(w http.ResponseWriter, req map[string]any) {
	name, args := "", map[string]any(nil)
	if !answered(req) {
		name, args = pickShell(req)
	}
	what := "final"
	if name != "" {
		what = "tool call " + name
	}
	logReq("/responses", req, what)
	model := str(req["model"])
	var item map[string]any
	if name != "" {
		argJSON, _ := json.Marshal(args)
		item = map[string]any{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": name,
			"arguments": string(argJSON), "status": "completed"}
	} else {
		item = map[string]any{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": *done, "annotations": []any{}}}}
	}
	usage := map[string]any{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
		"input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens_details": map[string]any{"reasoning_tokens": 0}}
	resp := func(status string, output []any) map[string]any {
		r := map[string]any{"id": "resp_1", "object": "response", "created_at": 1, "status": status, "model": model, "output": output}
		if status == "completed" {
			r["usage"] = usage
		}
		return r
	}
	if stream, _ := req["stream"].(bool); !stream {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp("completed", []any{item}))
		return
	}
	send := sse(w)
	ev := func(t string, m map[string]any) {
		m["type"] = t
		send(t, m)
	}
	ev("response.created", map[string]any{"response": resp("in_progress", []any{})})
	ev("response.output_item.added", map[string]any{"output_index": 0, "item": item})
	if name == "" {
		ev("response.output_text.delta", map[string]any{"output_index": 0, "content_index": 0, "item_id": "msg_1", "delta": *done})
	}
	ev("response.output_item.done", map[string]any{"output_index": 0, "item": item})
	ev("response.completed", map[string]any{"response": resp("completed", []any{item})})
}
