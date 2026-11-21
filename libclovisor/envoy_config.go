// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// EnvoyConfig is what the generated bootstrap needs. It carries policy
// shape only, never per-run state (design §6.5 rule 2), so it changes
// when the node's configuration does, not when runs come and go.
type EnvoyConfig struct {
	// ProxyListen is where runs send proxied traffic, e.g. 127.0.0.1:18000.
	ProxyListen netip.AddrPort
	// ExtProcSocket is the node agent's ext_proc unix socket.
	ExtProcSocket string
	// AdminSocket is Envoy's admin interface. It is a unix socket, never
	// TCP: a run that can reach a TCP admin port through the proxy could
	// reconfigure or stop it.
	AdminSocket string
	// Terminate lists the host patterns whose CONNECTs are ended and whose
	// TLS is terminated (milestone 2.4): exactly the destinations whose
	// rules need method or path, as the compiler derives (§6.6).
	Terminate []TerminatedHost
	// UpstreamCA verifies origin certificates behind termination, as
	// Envoy sees the file system.
	UpstreamCA string
}

// TerminatedHost is one terminated pattern and its leaf certificate.
type TerminatedHost struct {
	Pattern  string // "api.example.com" or "*.example.com"
	CertPath string
	KeyPath  string
}

// authorityRegex matches a CONNECT authority for pattern on any port.
func authorityRegex(pattern string) string {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return `^[^.:\[\]]+\.` + regexp.QuoteMeta(suffix) + `:[0-9]+$`
	}
	return "^" + regexp.QuoteMeta(pattern) + ":[0-9]+$"
}

// TerminateRoutePrefix names the routes that end a CONNECT for termination.
const TerminateRoutePrefix = "clovisor-terminate-"

// Header names Envoy sets on the inner (terminated) hop. ext_proc trusts
// them only on requests arriving over an internal listener.
const (
	hdrClient  = "x-clovisor-client"  // "<client addr:port>,<proxy addr:port>"
	hdrConnect = "x-clovisor-connect" // the CONNECT authority
)

type obj = map[string]interface{}
type arr = []interface{}

func typed(t string, fields obj) obj {
	fields["@type"] = t
	return fields
}

// EnvoyBootstrap renders the static Envoy bootstrap for explicit-proxy
// mode (milestone 2.3): one listener taking CONNECT and absolute-form
// plain HTTP, ext_proc deciding every request on its headers, and the
// dynamic forward proxy. Nothing is terminated yet (2.4).
func EnvoyBootstrap(c EnvoyConfig) ([]byte, error) {
	if !c.ProxyListen.IsValid() || c.ExtProcSocket == "" || c.AdminSocket == "" {
		return nil, fmt.Errorf("envoy config needs a proxy listen address, an ext_proc socket and an admin socket")
	}
	dns := obj{"name": "dfp_cache", "dns_lookup_family": "V4_PREFERRED"}
	extproc := obj{"name": "envoy.filters.http.ext_proc", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor", obj{
			"grpc_service": obj{"envoy_grpc": obj{"cluster_name": "ext_proc"}, "timeout": "2s"},
			// Fail closed: without a decision, nothing passes.
			"failure_mode_allow": false,
			// Lets ext_proc turn on body processing for the streams that
			// need it (remote MCP) and only those.
			"allow_mode_override": true,
			"request_attributes": arr{"source.address", "source.port", "destination.address", "destination.port", "xds.route_name"},
			"processing_mode": obj{
				"request_header_mode":  "SEND",
				"response_header_mode": "SKIP",
				"request_body_mode":    "NONE",
				"response_body_mode":   "NONE",
			},
		})}
	dfpFilter := obj{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
		obj{"dns_cache_config": dns})}
	router := obj{"name": "envoy.filters.http.router", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router", obj{})}
	// Before ext_proc on the outer hop: drop any client copies of the
	// inner-hop headers, and record the client address and CONNECT target
	// as filter state that crosses the internal hop.
	stripOwn := obj{"name": "envoy.filters.http.header_mutation", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
		obj{"mutations": obj{"request_mutations": arr{obj{"remove": hdrClient}, obj{"remove": hdrConnect}, obj{"remove": "x-clovisor-run"}}}})}
	fsEntry := func(key, format string) obj {
		return obj{"object_key": key, "factory_key": "envoy.string", "shared_with_upstream": "TRANSITIVE",
			"format_string": obj{"text_format_source": obj{"inline_string": format}}}
	}
	setState := obj{"name": "envoy.filters.http.set_filter_state", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config",
		obj{"on_request_headers": arr{
			fsEntry("clovisor.client", "%DOWNSTREAM_REMOTE_ADDRESS%,%DOWNSTREAM_LOCAL_ADDRESS%"),
			fsEntry("clovisor.connect", "%REQ(:AUTHORITY)%"),
		}})}
	var terminateRoutes arr
	for i, th := range c.Terminate {
		terminateRoutes = append(terminateRoutes, obj{
			// ext_proc reads the route name to know this CONNECT is
			// terminated, so its decision follows what Envoy actually does.
			"name": fmt.Sprintf("%s%d", TerminateRoutePrefix, i),
			"match": obj{
				"connect_matcher": obj{},
				"headers":         arr{obj{"name": ":authority", "string_match": obj{"safe_regex": obj{"regex": authorityRegex(th.Pattern)}}}},
			},
			"route": obj{"cluster": fmt.Sprintf("terminate-%d", i), "upgrade_configs": arr{obj{"upgrade_type": "CONNECT", "connect_config": obj{}}}},
		})
	}
	hcm := typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
		"stat_prefix":     "proxy",
		"upgrade_configs": arr{obj{"upgrade_type": "CONNECT"}},
		"route_config": obj{
			// Strip headers a client could use to impersonate the proxy's
			// own annotations; ext_proc trusts only attributes.
			"request_headers_to_remove": arr{"x-clovisor-client", "x-clovisor-run"},
			"virtual_hosts": arr{obj{
				"name":    "all",
				"domains": arr{"*"},
				"routes": append(terminateRoutes,
					obj{
						"match": obj{"connect_matcher": obj{}},
						"route": obj{"cluster": "dfp", "upgrade_configs": arr{obj{"upgrade_type": "CONNECT", "connect_config": obj{}}}},
					},
					obj{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp"}},
				),
			}},
		},
		"http_filters": arr{stripOwn, setState, extproc, dfpFilter, router},
	})

	listeners := arr{obj{
		"name": "proxy",
		"address": obj{"socket_address": obj{
			"address": c.ProxyListen.Addr().String(), "port_value": c.ProxyListen.Port()}},
		"filter_chains": arr{obj{"filters": arr{obj{
			"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}}},
	}}
	clusters := arr{}
	if len(c.Terminate) > 0 {
		if c.UpstreamCA == "" {
			return nil, fmt.Errorf("termination needs an upstream CA bundle to verify origins")
		}
		// Inner hop: write the crossed filter state into headers, before
		// ext_proc, overwriting anything the client sent (spike B).
		setHeaders := obj{"name": "envoy.filters.http.header_mutation", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
			obj{"mutations": obj{"request_mutations": arr{
				obj{"append": obj{"header": obj{"key": hdrClient, "value": "%FILTER_STATE(clovisor.client:PLAIN)%"}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}},
				obj{"append": obj{"header": obj{"key": hdrConnect, "value": "%FILTER_STATE(clovisor.connect:PLAIN)%"}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}},
			}}})}
		for i, th := range c.Terminate {
			name := fmt.Sprintf("mitm-%d", i)
			inner := typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
				"stat_prefix": name,
				"codec_type":  "AUTO",
				"route_config": obj{"virtual_hosts": arr{obj{
					"name": "all", "domains": arr{"*"},
					"routes": arr{obj{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp_tls"}}},
				}}},
				"http_filters": arr{setHeaders, extproc, dfpFilter, router},
			})
			listeners = append(listeners, obj{
				"name":              name,
				"internal_listener": obj{},
				"filter_chains": arr{obj{
					"transport_socket": obj{"name": "envoy.transport_sockets.tls", "typed_config": typed(
						"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", obj{
							"common_tls_context": obj{
								"alpn_protocols":   arr{"h2", "http/1.1"},
								"tls_certificates": arr{obj{"certificate_chain": obj{"filename": th.CertPath}, "private_key": obj{"filename": th.KeyPath}}},
							},
						})},
					"filters": arr{obj{"name": "envoy.filters.network.http_connection_manager", "typed_config": inner}},
				}},
			})
			clusters = append(clusters, obj{
				"name": fmt.Sprintf("terminate-%d", i),
				"load_assignment": obj{"cluster_name": fmt.Sprintf("terminate-%d", i), "endpoints": arr{obj{"lb_endpoints": arr{obj{
					"endpoint": obj{"address": obj{"envoy_internal_address": obj{"server_listener_name": name}}}}}}}},
				"transport_socket": obj{"name": "envoy.transport_sockets.internal_upstream", "typed_config": typed(
					"type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport",
					obj{"transport_socket": obj{"name": "envoy.transport_sockets.raw_buffer", "typed_config": typed(
						"type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer", obj{})}})},
			})
		}
		clusters = append(clusters, obj{
			"name":      "dfp_tls",
			"lb_policy": "CLUSTER_PROVIDED",
			"cluster_type": obj{"name": "envoy.clusters.dynamic_forward_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{"dns_cache_config": dns})},
			"typed_extension_protocol_options": obj{
				"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed(
					"type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
						"upstream_http_protocol_options": obj{"auto_sni": true, "auto_san_validation": true},
						"auto_config":                    obj{"http2_protocol_options": obj{}},
					}),
			},
			"transport_socket": obj{"name": "envoy.transport_sockets.tls", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", obj{
					"common_tls_context": obj{"validation_context": obj{"trusted_ca": obj{"filename": c.UpstreamCA}}},
				})},
		})
	}
	clusters = append(clusters,
		obj{
			"name":      "dfp",
			"lb_policy": "CLUSTER_PROVIDED",
			"cluster_type": obj{
				"name": "envoy.clusters.dynamic_forward_proxy",
				"typed_config": typed(
					"type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
					obj{"dns_cache_config": dns}),
			},
		},
		obj{
			"name": "ext_proc",
			"type": "STATIC",
			"typed_extension_protocol_options": obj{
				"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed(
					"type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
					obj{"explicit_http_config": obj{"http2_protocol_options": obj{}}}),
			},
			"load_assignment": obj{
				"cluster_name": "ext_proc",
				"endpoints": arr{obj{"lb_endpoints": arr{obj{"endpoint": obj{
					"address": obj{"pipe": obj{"path": c.ExtProcSocket}}}}}}},
			},
		},
	)
	boot := obj{
		"admin":            obj{"address": obj{"pipe": obj{"path": c.AdminSocket, "mode": 0o600}}},
		"static_resources": obj{"listeners": listeners, "clusters": clusters},
	}
	if len(c.Terminate) > 0 {
		boot["bootstrap_extensions"] = arr{obj{"name": "envoy.bootstrap.internal_listener", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener", obj{})}}
	}
	return json.MarshalIndent(boot, "", "  ")
}
