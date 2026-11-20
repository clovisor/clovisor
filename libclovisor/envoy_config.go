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
}

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
				"routes": arr{
					obj{
						"match": obj{"connect_matcher": obj{}},
						"route": obj{"cluster": "dfp", "upgrade_configs": arr{obj{"upgrade_type": "CONNECT", "connect_config": obj{}}}},
					},
					obj{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp"}},
				},
			}},
		},
		"http_filters": arr{
			obj{"name": "envoy.filters.http.ext_proc", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor", obj{
					"grpc_service": obj{"envoy_grpc": obj{"cluster_name": "ext_proc"}, "timeout": "2s"},
					// Fail closed: without a decision, nothing passes.
					"failure_mode_allow": false,
					"request_attributes": arr{"source.address", "source.port", "destination.address", "destination.port"},
					"processing_mode": obj{
						"request_header_mode":  "SEND",
						"response_header_mode": "SKIP",
						"request_body_mode":    "NONE",
						"response_body_mode":   "NONE",
					},
				})},
			obj{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
				obj{"dns_cache_config": dns})},
			obj{"name": "envoy.filters.http.router", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router", obj{})},
		},
	})
	boot := obj{
		"admin": obj{"address": obj{"pipe": obj{"path": c.AdminSocket, "mode": 0o600}}},
		"static_resources": obj{
			"listeners": arr{obj{
				"name": "proxy",
				"address": obj{"socket_address": obj{
					"address": c.ProxyListen.Addr().String(), "port_value": c.ProxyListen.Port()}},
				"filter_chains": arr{obj{"filters": arr{obj{
					"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}}},
			}},
			"clusters": arr{
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
			},
		},
	}
	return json.MarshalIndent(boot, "", "  ")
}
