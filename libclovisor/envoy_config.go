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
	// TransparentPort, if not 0, adds the transparent listener on
	// 127.0.0.1 and ::1 (milestone 3.2), where the connect hooks send
	// every TCP connect from a run.
	TransparentPort uint16
	// ActorTLS, if set, makes the proxy listener mTLS for Agent Substrate
	// Actors (milestone 7.3): a client certificate from the Actor CA is
	// required, and its chain is forwarded to ext_proc, which verifies it
	// again.
	ActorTLS *ActorListenerTLS
}

// ActorListenerTLS is the proxy listener's TLS with Actor identity, as
// Envoy sees the file system.
type ActorListenerTLS struct {
	CertPath, KeyPath string // the proxy's own certificate
	ClientCA          string // the Actor CA
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

// TransparentHTTPRoute names the route of plain HTTP that arrived on the
// transparent listener. ext_proc trusts the identity headers Envoy wrote
// on requests that took it.
const TransparentHTTPRoute = "clovisor-transparent-http"

// Header names Envoy sets on the inner (terminated or transparent) hop.
// ext_proc trusts them only on requests arriving over an internal
// listener, or on TransparentHTTPRoute.
const (
	hdrClient  = "x-clovisor-client"   // "<client addr:port>,<proxy addr:port>"
	hdrConnect = "x-clovisor-connect"  // the CONNECT authority
	hdrCred    = "x-clovisor-cred"     // the outer request's Proxy-Authorization (credential identity)
	hdrOrigDst = "x-clovisor-orig-dst" // the address a transparent connection was made to
	hdrSNI     = "x-clovisor-sni"      // its TLS server name, if any
	hdrXFCC    = "x-clovisor-xfcc"     // the CONNECT's client certificate chain (Actor identity)
)

// ownHeaders are the headers only Envoy may set; clients' copies are
// removed, and none reach an origin.
var ownHeaders = []string{hdrClient, hdrConnect, hdrCred, hdrOrigDst, hdrSNI, hdrXFCC, "x-clovisor-run"}

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
			// ext_proc may extend the timer for one message: to check a
			// large body (milestone 5.1), or to hold a request for a
			// person's decision, at most 4m (milestone 5.5).
			"max_message_timeout": "300s",
			// Lets ext_proc turn on body processing for the streams that
			// need it (remote MCP) and only those.
			"allow_mode_override": true,
			"request_attributes":  arr{"source.address", "source.port", "destination.address", "destination.port", "xds.route_name"},
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
	headerMutation := func(muts arr) obj {
		return obj{"name": "envoy.filters.http.header_mutation", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
			obj{"mutations": obj{"request_mutations": muts}})}
	}
	remove := func(names ...string) arr {
		var a arr
		for _, n := range names {
			a = append(a, obj{"remove": n})
		}
		return a
	}
	overwrite := func(name, format string) obj {
		return obj{"append": obj{"header": obj{"key": name, "value": format}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}}
	}
	stripOwn := headerMutation(remove(ownHeaders...))
	fsEntry := func(key, format string) obj {
		return obj{"object_key": key, "factory_key": "envoy.string", "shared_with_upstream": "TRANSITIVE",
			"format_string": obj{"text_format_source": obj{"inline_string": format}}}
	}
	// The identity crosses to the terminating listener as filter state
	// on the upstream connection, set when the connection is made. Envoy
	// pools connections by the hash of their options, and plain string
	// objects have none: while one run's tunnel to a terminated host was
	// open, another run's tunnels came from its pool, and their requests
	// were taken as the first run's, decided under its policy (milestone
	// 6.6). A hashable string holding the client is hashed into the pool
	// key, so each client's tunnels have a pool of their own (Envoy 1.39;
	// 6.6 used the upstream server name, before Envoy had one; Agent
	// Substrate keys its tunnels the same way, 7.0). Shared once, it
	// reaches the connection to the terminating listener and no further.
	// The credential is in the key too, as the identity is: one client
	// connection's CONNECTs for two sessions (7.3) or two credential runs
	// must not share a tunnel either.
	poolKey := func(client string) obj {
		return obj{"object_key": "clovisor.pool", "factory_key": "envoy.hashable_string", "shared_with_upstream": "ONCE",
			"format_string": obj{"text_format_source": obj{"inline_string": client + "|%REQ(PROXY-AUTHORIZATION)%|%REQ(X-FORWARDED-CLIENT-CERT)%"}}}
	}
	setState := func(client string) obj {
		return obj{"name": "envoy.filters.http.set_filter_state", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config",
			obj{"on_request_headers": arr{
				poolKey(client),
				fsEntry("clovisor.client", client),
				fsEntry("clovisor.connect", "%REQ(:AUTHORITY)%"),
				// With credential identity the run's secret is on the CONNECT
				// only; the requests inside a terminated tunnel need it too.
				fsEntry("clovisor.cred", "%REQ(PROXY-AUTHORIZATION)%"),
				// Likewise an Actor's certificate chain (Actor identity).
				fsEntry("clovisor.xfcc", "%REQ(X-FORWARDED-CLIENT-CERT)%"),
			}})}
	}
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
	// Strip headers a client could use to impersonate the proxy's own
	// annotations; ext_proc trusts only attributes. The router applies
	// this after ext_proc, which has read the run's credential by then: it
	// must not reach the origin.
	routerStrip := append(append(arr{}, strSlice(ownHeaders)...), "proxy-authorization", "x-forwarded-client-cert")
	// connectHCM is the CONNECT and plain-HTTP pipeline: on the explicit
	// listener, and on the internal listener transparent TLS and TCP are
	// tunnelled into.
	connectHCM := func(stat string, filters arr) obj {
		return typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
			"stat_prefix":     stat,
			"upgrade_configs": arr{obj{"upgrade_type": "CONNECT"}},
			// Python before 3.12 sends CONNECT as HTTP/1.0, which Envoy
			// otherwise refuses with 426.
			"http_protocol_options": obj{"accept_http_10": true},
			"route_config": obj{
				"request_headers_to_remove": routerStrip,
				"virtual_hosts": arr{obj{
					"name":    "all",
					"domains": arr{"*"},
					"routes": append(append(arr{}, terminateRoutes...),
						obj{
							"match": obj{"connect_matcher": obj{}},
							"route": obj{"cluster": "dfp", "upgrade_configs": arr{obj{"upgrade_type": "CONNECT", "connect_config": obj{}}}},
						},
						obj{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp"}},
					),
				}},
			},
			"http_filters": filters,
		})
	}
	hcm := connectHCM("proxy", arr{stripOwn, setState("%DOWNSTREAM_REMOTE_ADDRESS%,%DOWNSTREAM_LOCAL_ADDRESS%"), extproc, dfpFilter, router})
	proxyChain := obj{"filters": arr{obj{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}}
	if t := c.ActorTLS; t != nil {
		// Envoy is the only writer of x-forwarded-client-cert: whatever a
		// client sent is replaced with this connection's chain.
		hcm["forward_client_cert_details"] = "SANITIZE_SET"
		hcm["set_current_client_cert_details"] = obj{"uri": true, "cert": true, "chain": true}
		proxyChain["transport_socket"] = obj{"name": "envoy.transport_sockets.tls", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", obj{
				"require_client_certificate": true,
				"common_tls_context": obj{
					"alpn_protocols":     arr{"http/1.1"},
					"tls_certificates":   arr{obj{"certificate_chain": obj{"filename": t.CertPath}, "private_key": obj{"filename": t.KeyPath}}},
					"validation_context": obj{"trusted_ca": obj{"filename": t.ClientCA}},
				},
			})}
	}

	listeners := arr{obj{
		"name": "proxy",
		"address": obj{"socket_address": obj{
			"address": c.ProxyListen.Addr().String(), "port_value": c.ProxyListen.Port()}},
		"filter_chains": arr{proxyChain},
	}}
	clusters := arr{}
	internal := len(c.Terminate) > 0
	if c.TransparentPort != 0 {
		internal = true
		// The tunnel's headers come from Envoy's tcp_proxy, over an
		// internal listener no client can reach: keep them, and carry the
		// client across a further terminating hop. Credentials do not
		// apply (transparent mode is cgroup identity only).
		tconnect := connectHCM("transparent_connect", arr{
			headerMutation(remove(hdrCred, "x-clovisor-run", "proxy-authorization")),
			setState("%REQ(" + hdrClient + ")%"), extproc, dfpFilter, router})
		// Plain HTTP on the transparent listener: no CONNECT, routed by
		// Host. Envoy writes the identity headers itself, overwriting any
		// client value; ext_proc trusts them on this route only.
		thttp := typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
			"stat_prefix":           "transparent_http",
			"http_protocol_options": obj{"accept_http_10": true},
			"route_config": obj{
				"request_headers_to_remove": routerStrip,
				"virtual_hosts": arr{obj{
					"name": "all", "domains": arr{"*"},
					"routes": arr{obj{"name": TransparentHTTPRoute, "match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp"}}},
				}},
			},
			"http_filters": arr{
				headerMutation(append(remove(hdrConnect, hdrCred, hdrSNI, "x-clovisor-run"),
					// The client socket is connected to the listener's own
					// address, which the original destination replaced as
					// the local address: sock_diag needs the former.
					overwrite(hdrClient, "%DOWNSTREAM_REMOTE_ADDRESS%,%DOWNSTREAM_DIRECT_LOCAL_ADDRESS%"),
					overwrite(hdrOrigDst, "%DOWNSTREAM_LOCAL_ADDRESS%"))),
				extproc, dfpFilter, router},
		})
		tunnel := func(stat, hostname string) obj {
			return obj{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", obj{
					"stat_prefix": stat,
					"cluster":     "transparent-connect",
					"tunneling_config": obj{
						"hostname": hostname,
						"headers_to_add": arr{
							obj{"header": obj{"key": hdrClient, "value": "%DOWNSTREAM_REMOTE_ADDRESS%,%DOWNSTREAM_DIRECT_LOCAL_ADDRESS%"}},
							obj{"header": obj{"key": hdrConnect, "value": hostname}},
							obj{"header": obj{"key": hdrOrigDst, "value": "%DOWNSTREAM_LOCAL_ADDRESS%"}},
							obj{"header": obj{"key": hdrSNI, "value": "%REQUESTED_SERVER_NAME%"}},
						},
					},
				})}
		}
		input := func(name, typ string) obj {
			return obj{"name": "envoy.matching.inputs." + name, "typed_config": typed(
				"type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3."+typ, obj{})}
		}
		exact := func(in obj, v string) obj {
			return obj{"single_predicate": obj{"input": in, "value_match": obj{"exact": v}}}
		}
		regex := func(in obj, re string) obj {
			return obj{"single_predicate": obj{"input": in, "value_match": obj{"safe_regex": obj{"google_re2": obj{}, "regex": re}}}}
		}
		chain := func(name string) obj {
			return obj{"action": obj{"name": name, "typed_config": typed("type.googleapis.com/google.protobuf.StringValue", obj{"value": name})}}
		}
		tls := exact(input("transport_protocol", "TransportProtocolInput"), "tls")
		port := fmt.Sprint(c.TransparentPort)
		listeners = append(listeners, obj{
			"name":                 "transparent",
			"address":              obj{"socket_address": obj{"address": "127.0.0.1", "port_value": c.TransparentPort}},
			"additional_addresses": arr{obj{"address": obj{"socket_address": obj{"address": "::1", "port_value": c.TransparentPort}}}},
			"listener_filters": arr{
				obj{"name": "envoy.filters.listener.original_dst", "typed_config": typed(
					"type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst", obj{})},
				obj{"name": "envoy.filters.listener.tls_inspector", "typed_config": typed(
					"type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector", obj{})},
				obj{"name": "envoy.filters.listener.http_inspector", "typed_config": typed(
					"type.googleapis.com/envoy.extensions.filters.listener.http_inspector.v3.HttpInspector", obj{})},
			},
			// Server-speaks-first protocols (SSH, SMTP) give the
			// inspectors nothing to read: after a second, treat them as
			// plain TCP instead of closing them (3.0 spike).
			"listener_filters_timeout":             "1s",
			"continue_on_listener_filters_timeout": true,
			"filter_chain_matcher": obj{
				"matcher_list": obj{"matchers": arr{
					// No original destination: a run connected to this
					// port itself. Tunnelling it would make Envoy connect
					// to itself, over and over (3.0 spike).
					obj{"predicate": exact(input("destination_port", "DestinationPortInput"), port), "on_match": chain("self")},
					// TLS with a server name: CONNECT to the name, so the
					// proxy resolves the name the client asked for rather
					// than trusting the address it picked.
					obj{"predicate": obj{"and_matcher": obj{"predicate": arr{tls, regex(input("server_name", "ServerNameInput"), ".+")}}}, "on_match": chain("tls-sni")},
					obj{"predicate": tls, "on_match": chain("tls-ip")},
					// The input is a quoted list, e.g. 'http/1.1', and
					// the regex must match all of it.
					obj{"predicate": regex(input("application_protocol", "ApplicationProtocolInput"), ".*('http/1\\.[01]'|'h2c').*"), "on_match": chain("http")},
				}},
				"on_no_match": chain("tcp"),
			},
			"filter_chains": arr{
				obj{"name": "self", "filters": arr{
					obj{"name": "envoy.filters.network.rbac", "typed_config": typed(
						"type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC", obj{
							"stat_prefix": "transparent_self",
							"rules": obj{"action": "DENY", "policies": obj{"all": obj{
								"permissions": arr{obj{"any": true}}, "principals": arr{obj{"any": true}}}}},
						})},
					// Never reached; a chain must end in a terminal filter.
					obj{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
						"type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
						obj{"stat_prefix": "transparent_self", "cluster": "transparent-connect"})},
				}},
				obj{"name": "tls-sni", "filters": arr{tunnel("transparent_tls", "%REQUESTED_SERVER_NAME%:%DOWNSTREAM_LOCAL_PORT%")}},
				obj{"name": "tls-ip", "filters": arr{tunnel("transparent_tls_ip", "%DOWNSTREAM_LOCAL_ADDRESS%")}},
				obj{"name": "http", "filters": arr{obj{"name": "envoy.filters.network.http_connection_manager", "typed_config": thttp}}},
				obj{"name": "tcp", "filters": arr{tunnel("transparent_tcp", "%DOWNSTREAM_LOCAL_ADDRESS%")}},
			},
		}, obj{
			"name":              "transparent-connect",
			"internal_listener": obj{},
			"filter_chains": arr{obj{"filters": arr{obj{
				"name": "envoy.filters.network.http_connection_manager", "typed_config": tconnect}}}},
		})
		clusters = append(clusters, internalCluster("transparent-connect", "transparent-connect"))
	}
	if len(c.Terminate) > 0 {
		if c.UpstreamCA == "" {
			return nil, fmt.Errorf("termination needs an upstream CA bundle to verify origins")
		}
		// Inner hop: write the crossed filter state into headers, before
		// ext_proc, overwriting anything the client sent (spike B).
		setHeaders := headerMutation(append(remove(hdrOrigDst, hdrSNI, "x-clovisor-run"),
			overwrite(hdrClient, "%FILTER_STATE(clovisor.client:PLAIN)%"),
			overwrite(hdrConnect, "%FILTER_STATE(clovisor.connect:PLAIN)%"),
			overwrite(hdrCred, "%FILTER_STATE(clovisor.cred:PLAIN)%"),
			overwrite(hdrXFCC, "%FILTER_STATE(clovisor.xfcc:PLAIN)%")))
		for i, th := range c.Terminate {
			name := fmt.Sprintf("mitm-%d", i)
			inner := typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
				"stat_prefix": name,
				"codec_type":  "AUTO",
				"route_config": obj{
					// The inner-hop annotations are for ext_proc only: the
					// router drops them before the origin sees them.
					"request_headers_to_remove": routerStrip,
					"virtual_hosts": arr{obj{
						"name": "all", "domains": arr{"*"},
						"routes": arr{obj{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp_tls"}}},
					}},
				},
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
			clusters = append(clusters, internalCluster(fmt.Sprintf("terminate-%d", i), name))
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
						// A body ext_proc held and released at once (milestone
						// 5.1) draws a burst of WINDOW_UPDATEs from the origin,
						// which the default limit of 10 per DATA frame sent
						// takes for a flood, killing the connection and every
						// request on it.
						"auto_config": obj{"http2_protocol_options": obj{"max_inbound_window_update_frames_per_data_frame_sent": 100}},
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
			// Every inspected stream is a request on this cluster, and the
			// default circuit breaker allows 1,024 at once: past it, every
			// request on the node would fail (5.0 spikes). ext_proc keeps
			// its own, lower limits (DefaultMaxInspected).
			"circuit_breakers": obj{"thresholds": arr{obj{"max_requests": 1000000, "max_pending_requests": 1000000}}},
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
	if internal {
		boot["bootstrap_extensions"] = arr{obj{"name": "envoy.bootstrap.internal_listener", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener", obj{})}}
	}
	return json.MarshalIndent(boot, "", "  ")
}

// internalCluster sends to the internal listener named listener.
func internalCluster(name, listener string) obj {
	return obj{
		"name": name,
		"load_assignment": obj{"cluster_name": name, "endpoints": arr{obj{"lb_endpoints": arr{obj{
			"endpoint": obj{"address": obj{"envoy_internal_address": obj{"server_listener_name": listener}}}}}}}},
		"transport_socket": obj{"name": "envoy.transport_sockets.internal_upstream", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport",
			obj{"transport_socket": obj{"name": "envoy.transport_sockets.raw_buffer", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer", obj{})}})},
	}
}

func strSlice(ss []string) arr {
	a := make(arr, len(ss))
	for i, s := range ss {
		a[i] = s
	}
	return a
}
