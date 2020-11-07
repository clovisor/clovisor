// Copyright (c) Authors of Clover
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

#include <bcc/proto.h>

#define HTTP_HDR_MIN_LEN 7
#define MAX_SESSION_TABLE_ENTRIES 8192

#define bpf_memcpy __builtin_memcpy

typedef enum {
    UNDEFINED = 0,
    HTTP = 1,
    HTTP2 = 2,
    TCP = 3,
    UDP = 4,
    REDIRECTED = 5,
} app_proto_t;

typedef struct session_key_ {
    u32 src_ip;
    u32 dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
} session_key_t;

typedef struct session_ {
    u64 req_time;
    u64 resp_time;
} session_t;

typedef struct egress_match_ {
    u32 dst_ip;
    unsigned short dst_port;
} egress_match_t;

typedef enum policy_action_ {
    RECORD = 1,
} policy_action_t;

typedef struct redirect_action_ {
    u32 ingress;
    u32 to_ifidx;
    u32 src_ip;
    u32 dst_ip;
    unsigned char src_mac[ETH_ALEN];
    unsigned char dst_mac[ETH_ALEN];
} redirect_action_t;

BPF_PERF_OUTPUT(skb_events);
BPF_HASH(dports2proto, u16, u32);
BPF_HASH(egress_lookup_table, egress_match_t, policy_action_t);
BPF_HASH(sessions, session_key_t, session_t, MAX_SESSION_TABLE_ENTRIES);
BPF_HASH(redirect_lookup_table, session_key_t, redirect_action_t);

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CSUM_OFFSET (ETH_HLEN + offsetof(struct iphdr, check))
#define IS_PSEUDO 0x10

static inline int ipv4_hdrlen(struct iphdr *ip4)
{
    return ip4->ihl * 4;
}

static inline int tcp_doff(struct tcphdr *tcp_hdr)
{
    return tcp_hdr->doff * 4;
}

static inline int http_parsing(void *data, void *data_end)
{

    int is_http = 1;
    if (data + HTTP_HDR_MIN_LEN > data_end) {
        bpf_trace_printk("No HTTP Header in TCP segment");
        return 0;
    }
    if (strncmp((char*)data, "HTTP", 4)) {
        if (strncmp((char*)data, "GET", 3)) {
            if (strncmp((char*)data, "POST", 4)) {
                if (strncmp((char*)data, "PUT", 3)) {
                    if (strncmp((char*)data, "HEAD", 4)) {
                        is_http = 0;
                    }
                }
            }
        }
    }
    return is_http;
}

static inline void fill_up_sess_key(session_key_t *key, u32 src_ip,
                                    u32 dst_ip, u16 src_port, u16 dst_port)
{
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
}

static inline int process_response(u32 src_ip, u32 dst_ip, u16 src_port,
                                   u16 dst_port)
{
    session_key_t sess_key = {};
    session_t *session_ptr = NULL;
    fill_up_sess_key(&sess_key, src_ip, dst_ip, src_port, dst_port);
    session_ptr = sessions.lookup(&sess_key);
    if (session_ptr != NULL) {
        u64 resp_time = bpf_ktime_get_ns();
        session_t update_session = {
            session_ptr->req_time,
            resp_time
        };
        sessions.update(&sess_key, &update_session);
        return 1;
    }
    return 0;
}

static inline void process_request(u32 src_ip, u32 dst_ip, u16 src_port,
                                   u16 dst_port)
{
    session_key_t sess_key = {};
    session_t *session_ptr = NULL;
    session_t new_session = {
        bpf_ktime_get_ns(),
        0
    };
    fill_up_sess_key(&sess_key, src_ip, dst_ip, src_port, dst_port);
    session_ptr = sessions.lookup(&sess_key);
    if (! session_ptr) {
        sessions.insert(&sess_key, &new_session);
    }
    /*
    if (session_ptr != NULL) {
        sessions.update(&sess_key, &new_session);
    } else {
        sessions.insert(&sess_key, &new_session);
    }
    */
}

static inline int mac_compare(u8 *addr1, u8 *addr2)
{
    int i;
    for (i = 0; i < ETH_ALEN; i++) {
        if (addr1[i] != addr2[i]) {
            return -1;
        }
    }
    return 0;
}

static inline app_proto_t redirect(struct __sk_buff *skb,
                                   session_key_t *redirect_lookup_key,
                                   struct tcphdr *tcp_hdr,
                                   struct iphdr *ipv4_hdr,
                                   void *data_end)
{
    redirect_action_t *redirect_action_ptr = NULL;

    redirect_action_ptr = redirect_lookup_table.lookup(redirect_lookup_key);
    if (redirect_action_ptr != NULL) {
        char zero[ETH_ALEN] = { 0 };
        char src_mac[ETH_ALEN] = { 0 };
        char dst_mac[ETH_ALEN] = { 0 };
        int ret;
	    void *data = (void *)(long)skb->data;
	    struct eth_hdr *eth = data;
        /*
	    if (data + sizeof(*eth) + sizeof(*ipv4_hdr) + sizeof(*tcp_hdr) > data_end)
		    return TC_ACT_OK;
        bpf_trace_printk("Original Source IP: 0x%x, dst IP 0x%x\n", ntohl(ipv4_hdr->saddr), ntohl(ipv4_hdr->daddr));
        bpf_trace_printk("with src mac %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
        bpf_trace_printk("%x:%x:%x ", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        bpf_trace_printk("with dst mac %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        bpf_trace_printk("%x:%x:%x ", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        bpf_trace_printk("redirect: ingrerss:%d to %d \n", redirect_action_ptr->ingress, redirect_action_ptr->to_ifidx);
        bpf_trace_printk("with src mac %x:%x:%x:", redirect_action_ptr->src_mac[0], redirect_action_ptr->src_mac[1], redirect_action_ptr->src_mac[2]);
        bpf_trace_printk("%x:%x:%x ", redirect_action_ptr->src_mac[3], redirect_action_ptr->src_mac[4], redirect_action_ptr->src_mac[5]);
        bpf_trace_printk("dst mac %x:%x:%x:", redirect_action_ptr->dst_mac[0], redirect_action_ptr->dst_mac[1], redirect_action_ptr->dst_mac[2]);
        bpf_trace_printk("%x:%x:%x ", redirect_action_ptr->dst_mac[3], redirect_action_ptr->dst_mac[4], redirect_action_ptr->dst_mac[5]);
        bpf_trace_printk(" src ip: 0x%x\n", redirect_action_ptr->src_ip);
        */
        bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, ETH_ALEN);
        if (mac_compare(src_mac, zero) != 0) {
            bpf_trace_printk("Change source mac\n");
            bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                redirect_action_ptr->src_mac, ETH_ALEN, 0);
        }
        bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN);
        if (mac_compare(dst_mac, zero) != 0) {
            bpf_trace_printk("Change dest mac\n");
            bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                redirect_action_ptr->dst_mac, ETH_ALEN, 0);
        }
        if (redirect_action_ptr->src_ip != 0) {
            bpf_trace_printk("Change src ip\n");
            u32 src_ip = 0, old_src_ip = 0;
            bpf_skb_load_bytes(skb, IP_SRC_OFF, &old_src_ip, sizeof(old_src_ip));
            src_ip = htonl(redirect_action_ptr->src_ip);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_src_ip, src_ip, IS_PSEUDO | sizeof(src_ip));
            bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, old_src_ip, src_ip, 4);
            bpf_skb_store_bytes(skb, IP_SRC_OFF, &src_ip, sizeof(src_ip), 0);
        }
        if (redirect_action_ptr->dst_ip != 0) {
            bpf_trace_printk("Change dst ip\n");
            u32 dst_ip = 0, old_dst_ip = 0;
            bpf_skb_load_bytes(skb, IP_DST_OFF, &old_dst_ip, sizeof(old_dst_ip));
            dst_ip = htonl(redirect_action_ptr->dst_ip);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_dst_ip, dst_ip, IS_PSEUDO | sizeof(dst_ip));
            bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, old_dst_ip, dst_ip, 4);
            bpf_skb_store_bytes(skb, IP_DST_OFF, &dst_ip, sizeof(dst_ip), 0);
        }
        if (redirect_action_ptr->ingress) {
            bpf_trace_printk("redirect with ingress\n");
            ret = bpf_clone_redirect(skb, redirect_action_ptr->to_ifidx, BPF_F_INGRESS);
        } else {
            bpf_trace_printk("redirect without ingress\n");
            ret = bpf_clone_redirect(skb, redirect_action_ptr->to_ifidx, 0);
        }
        return REDIRECTED;
    }
    return UNDEFINED;
}

static inline app_proto_t ingress_tcp_parsing(struct __sk_buff *skb,
                                              struct tcphdr *tcp_hdr,
                                              struct iphdr *ipv4_hdr,
                                              void *data_end)
{
    unsigned short dest_port = htons(tcp_hdr->dest);
    egress_match_t egress_match = {};
    policy_action_t *policy_ptr = NULL;
    app_proto_t ret = TCP;
    unsigned short wildcard_port = 0;
    session_key_t redirect_lookup_key = {};

    // First, look up redirect on outbound
    redirect_lookup_key.dst_ip = ntohl(ipv4_hdr->daddr);
    redirect_lookup_key.dst_port = ntohs(tcp_hdr->dest);
    redirect_lookup_key.src_ip = 0;
    redirect_lookup_key.src_port = 0;
    if (redirect(skb, &redirect_lookup_key, tcp_hdr, ipv4_hdr, data_end) == REDIRECTED) {
        return REDIRECTED;
    }

    unsigned int *proto = dports2proto.lookup(&dest_port);
    if (proto == NULL) {
        proto = dports2proto.lookup(&wildcard_port);
    }
    if (proto != NULL) {
        /*
        if (tcp_hdr->syn && !tcp_hdr->ack) {
            return ret;
        }
        */
        ret = HTTP;
        if (tcp_hdr->fin || tcp_hdr->rst) {
            process_response(ntohl(ipv4_hdr->saddr),
                             ntohl(ipv4_hdr->daddr),
                             ntohs(tcp_hdr->source),
                             ntohs(tcp_hdr->dest));
        } else {
            process_request(ntohl(ipv4_hdr->saddr),
                            ntohl(ipv4_hdr->daddr),
                            ntohs(tcp_hdr->source),
                            ntohs(tcp_hdr->dest));
        }
    } else {
        dest_port = htons(tcp_hdr->source);
        proto = dports2proto.lookup(&dest_port);
        if (proto == NULL) {
            proto = dports2proto.lookup(&wildcard_port);
        }
        if (proto != NULL) {
            // clock response receiving time
            process_response(ntohl(ipv4_hdr->daddr),
                             ntohl(ipv4_hdr->saddr),
                             ntohs(tcp_hdr->dest),
                             ntohs(tcp_hdr->source));
        }
        egress_match.dst_ip = ntohl(ipv4_hdr->saddr);
        egress_match.dst_port = ntohs(tcp_hdr->source);
        policy_ptr = egress_lookup_table.lookup(&egress_match);
        if (policy_ptr == NULL) {
            egress_match.dst_ip = 0;
            policy_ptr = egress_lookup_table.lookup(&egress_match);
            if (policy_ptr == NULL) {
                egress_match.dst_port = 0;
                policy_ptr = egress_lookup_table.lookup(&egress_match);
            }
        }

        if (policy_ptr != NULL) {
            if (*policy_ptr == RECORD) {
                ret = HTTP;
                if (tcp_hdr->fin || tcp_hdr->rst) {
                    process_response(ntohl(ipv4_hdr->daddr),
                                     ntohl(ipv4_hdr->saddr),
                                     ntohs(tcp_hdr->dest),
                                     ntohs(tcp_hdr->source));
                }
            }
        }
    }

    // everything else drops to TCP
    //return ((void*)tcp_hdr);
    return ret;
}

static inline app_proto_t egress_tcp_parsing(struct __sk_buff *skb,
                                             struct tcphdr *tcp_hdr,
                                             struct iphdr *ipv4_hdr,
                                             void *data_end)
{
    unsigned short src_port = htons(tcp_hdr->source);
    app_proto_t ret = TCP;
    egress_match_t egress_match = {};
    policy_action_t *policy_ptr = NULL;
    unsigned short wildcard_port = 0;
    session_key_t redirect_lookup_key = {};

    redirect_lookup_key.src_ip = ntohl(ipv4_hdr->saddr);
    redirect_lookup_key.src_port = ntohs(tcp_hdr->source);
    redirect_lookup_key.dst_ip = 0;
    redirect_lookup_key.dst_port = 0;
    if (redirect(skb, &redirect_lookup_key, tcp_hdr, ipv4_hdr, data_end) == REDIRECTED) {
        return REDIRECTED;
    }

    unsigned int *proto = dports2proto.lookup(&src_port);
    if (proto == NULL) {
        proto = dports2proto.lookup(&wildcard_port);
    }

    if (proto != NULL) {
        //if (tcp_hdr->fin || tcp_hdr->rst) {
        process_response(ntohl(ipv4_hdr->daddr),
                         ntohl(ipv4_hdr->saddr),
                         ntohs(tcp_hdr->dest),
                         ntohs(tcp_hdr->source));
        //}
        ret = HTTP;
    } else {

        egress_match.dst_ip = ntohl(ipv4_hdr->daddr);
        egress_match.dst_port = ntohs(tcp_hdr->dest);
        policy_ptr = egress_lookup_table.lookup(&egress_match);
        if (policy_ptr == NULL) {
            egress_match.dst_ip = 0;
            policy_ptr = egress_lookup_table.lookup(&egress_match);
            if (policy_ptr == NULL) {
                egress_match.dst_port = 0;
                policy_ptr = egress_lookup_table.lookup(&egress_match);
            }
        }

        if (policy_ptr != NULL) {
            if (*policy_ptr == RECORD) {
                process_request(ntohl(ipv4_hdr->saddr),
                                ntohl(ipv4_hdr->daddr),
                                ntohs(tcp_hdr->source),
                                ntohs(tcp_hdr->dest));
                ret = HTTP;
            }
        }
    }
    //return(ret_hdr);
    return ret;
}

static inline int handle_packet(struct __sk_buff *skb, int is_ingress)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
    struct iphdr *ipv4_hdr = data + sizeof(*eth);
    struct tcphdr *tcp_hdr = data + sizeof(*eth) + sizeof(*ipv4_hdr);
    app_proto_t proto = TCP;

    /* TODO(s3wong): assuming TCP only for now */
	/* single length check */
	if (data + sizeof(*eth) + sizeof(*ipv4_hdr) + sizeof(*tcp_hdr) > data_end)
		return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // TODO(s3wong): no support for IP options
    if (ipv4_hdr->protocol != IPPROTO_TCP || ipv4_hdr->ihl != 5)
        return TC_ACT_OK;

    if (is_ingress == 1) {
        proto = ingress_tcp_parsing(skb, tcp_hdr, ipv4_hdr, data_end);
    } else{
        proto = egress_tcp_parsing(skb, tcp_hdr, ipv4_hdr, data_end);
    }

	if (proto == HTTP) {
        int offset = is_ingress;
	    skb_events.perf_submit_skb(skb, skb->len, &offset, sizeof(offset));
    } else if (proto == REDIRECTED) {
        return TC_ACT_OK;
    }

	return TC_ACT_OK;
}

int handle_ingress(struct __sk_buff *skb)
{
    return handle_packet(skb, 1);
}

int handle_egress(struct __sk_buff *skb)
{
    return handle_packet(skb, 0);
}
