#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17
#define ETH_P_ARP_VAL 0x0806

#define MAX_PROFILES_BPF 32
#define MAX_ENCRYPT_PACK_BPF 256

#define XDP_INGRESS_RATE_LIMIT 1
#define XDP_RL_WINDOW_NS       1000000ULL
#define XDP_RL_MAX_BYTES_PER_WINDOW 62500ULL

/* Must match FORWARDER_XSK_QUEUE_ID in inc/config.h (single RX queue). */
#define NE_XSK_QUEUE_ID 0

#define XDP_RULE_SRC_ANY 1
#define XDP_RULE_DST_ANY 2
#define XDP_RULE_SRC_NEG 4
#define XDP_RULE_DST_NEG 8

struct xdp_encrypt_rule {
    __u32 src_net;
    __u32 src_mask;
    __u32 dst_net;
    __u32 dst_mask;
    __u32 flags;
    __u8 protocol;
    __u8 pad[3];
    __s32 src_port_from;
    __s32 src_port_to;
    __s32 dst_port_from;
    __s32 dst_port_to;
};

struct bpf_profile_meta {
    __u32 enabled;
    __u32 enc_start;
    __u32 enc_num;
};

struct xdp_encrypt_ctrl {
    __u32 profile_count;
    __u32 require_filter;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#if XDP_INGRESS_RATE_LIMIT
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rl_last_reset_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rl_byte_count SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_encrypt_ctrl);
} encrypt_ctrl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PROFILES_BPF);
    __type(key, __u32);
    __type(value, struct bpf_profile_meta);
} profile_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENCRYPT_PACK_BPF);
    __type(key, __u32);
    __type(value, struct xdp_encrypt_rule);
} encrypt_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} ingress_profile_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int read_tcp_udp_ports(void *data, void *data_end, __u8 ip_proto,
                                              __u16 *sport_out, __u16 *dport_out)
{
    *sport_out = 0;
    *dport_out = 0;
    if (ip_proto != IPPROTO_TCP_VAL && ip_proto != IPPROTO_UDP_VAL)
        return 0;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    __u32 ihl = (__u32)ip->ihl * 4U;
    if (ihl < 20)
        return -1;

    __u8 *l4 = (__u8 *)ip + ihl;
    if ((void *)(l4 + 4) > data_end)
        return -1;

    __be16 *ports = (__be16 *)l4;
    *sport_out = bpf_ntohs(ports[0]);
    *dport_out = bpf_ntohs(ports[1]);
    return 0;
}

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      __u32 *src_ip, __u32 *dst_ip, __u8 *proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    if (proto)
        *proto = ip->protocol;
    return 0;
}

static __always_inline int ip_in_net(__u32 ip, __u32 net, __u32 mask)
{
    return (ip & mask) == (net & mask);
}

/*
 * Detaching/replacing DB-driven setup is done in userspace: bpf_xdp_detach() on each
 * local/WAN ifindex — see interface_xdp_detach_all_from_config() before reloading cfg.
 *
 * stats_map (debug, bpftool map dump name stats_map):
 *   [0] packets entered program
 *   [1] bad/eth short / not IPv4 after ethernet header
 *   [4] ICMP → PASS
 *   [7] ARP → PASS
 *   [8] no encrypt_rule_matches → PASS (tuple không khớp encrypt_rules_map hoặc profile enc_num=0)
 *  [10] TCP/UDP port parse failed → PASS
 *  [13] encrypt_ctrl_map missing → PASS
 *  [12] rate-limit maps missing after match → PASS
 *  [11] rate-limit DROP after match
 *   [5] xsks_map missing FD after match → PASS (rule khớp nhưng chưa bind AF_XDP socket)
 *   [6] redirect to AF_XDP OK
 *
 * DB/userspace: interface_push_encrypt_filters fills encrypt_ctrl_map (profile_count),
 * profile_meta_map (per-profile enc_start/enc_num), encrypt_rules_map (flattened rules),
 * ingress_profile_map (ifindex → profile index, optional).
 */

static __always_inline int encrypt_rule_matches(__u32 sip, __u32 dip,
                                                 __u8 pkt_proto,
                                                 __u16 sport, __u16 dport,
                                                 struct xdp_encrypt_rule *r)
{
    int s_ok;
    if (r->flags & XDP_RULE_SRC_ANY) {
        s_ok = 1;
    } else {
        int in_s = ip_in_net(sip, r->src_net, r->src_mask);
        if (r->flags & XDP_RULE_SRC_NEG)
            s_ok = !in_s;
        else
            s_ok = in_s;
    }

    int d_ok;
    if (r->flags & XDP_RULE_DST_ANY) {
        d_ok = 1;
    } else {
        int in_d = ip_in_net(dip, r->dst_net, r->dst_mask);
        if (r->flags & XDP_RULE_DST_NEG)
            d_ok = !in_d;
        else
            d_ok = in_d;
    }

    if (!s_ok || !d_ok)
        return 0;

    if (r->protocol != 0 && r->protocol != pkt_proto)
        return 0;

    if (r->src_port_from >= 0 && r->src_port_to >= 0) {
        if ((__s32)sport < r->src_port_from || (__s32)sport > r->src_port_to)
            return 0;
    }
    if (r->dst_port_from >= 0 && r->dst_port_to >= 0) {
        if ((__s32)dport < r->dst_port_from || (__s32)dport > r->dst_port_to)
            return 0;
    }

    return 1;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    inc_stat(0);

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL)) {
        inc_stat(7);
        return XDP_PASS;
    }

    __u32 src_ip, dst_ip;
    __u8 l4_proto = 0;
    if (parse_ipv4(data, data_end, &src_ip, &dst_ip, &l4_proto) < 0) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_ICMP_VAL) {
        inc_stat(4);
        return XDP_PASS;
    }

    __u16 sport = 0;
    __u16 dport = 0;
    if (read_tcp_udp_ports(data, data_end, l4_proto, &sport, &dport) < 0) {
        inc_stat(10);
        return XDP_PASS;
    }

    __u32 cfg_key = 0;
    struct xdp_encrypt_ctrl *ctrl = bpf_map_lookup_elem(&encrypt_ctrl_map, &cfg_key);
    if (!ctrl) {
        inc_stat(13);
        return XDP_PASS;
    }

    __u32 npc = ctrl->profile_count;
    if (npc > MAX_PROFILES_BPF)
        npc = MAX_PROFILES_BPF;

    int redirect_hit = 0;

    __u32 ing_if = ctx->ingress_ifindex;
    __u32 *pick_prof = bpf_map_lookup_elem(&ingress_profile_map, &ing_if);

    if (pick_prof && *pick_prof < npc && *pick_prof < MAX_PROFILES_BPF) {
        __u32 pi = *pick_prof;
        struct bpf_profile_meta *meta =
            bpf_map_lookup_elem(&profile_meta_map, &pi);
        if (meta && meta->enabled && meta->enc_num > 0) {
            for (int e = 0; e < MAX_ENCRYPT_PACK_BPF; e++) {
                if ((__u32)e >= meta->enc_num)
                    break;
                __u32 ei = meta->enc_start + (__u32)e;
                if (ei >= MAX_ENCRYPT_PACK_BPF)
                    break;
                struct xdp_encrypt_rule *er =
                    bpf_map_lookup_elem(&encrypt_rules_map, &ei);
                if (!er)
                    continue;
                if (encrypt_rule_matches(src_ip, dst_ip, l4_proto, sport, dport, er)) {
                    redirect_hit = 1;
                    break;
                }
            }
        }
    }

    if (!redirect_hit) {
        for (int pi = 0; pi < MAX_PROFILES_BPF; pi++) {
            if ((__u32)pi >= npc)
                break;

            __u32 pik = (__u32)pi;
            struct bpf_profile_meta *meta =
                bpf_map_lookup_elem(&profile_meta_map, &pik);
            if (!meta || !meta->enabled)
                continue;

            if (meta->enc_num == 0)
                continue;

            for (int e = 0; e < MAX_ENCRYPT_PACK_BPF; e++) {
                if ((__u32)e >= meta->enc_num)
                    break;
                __u32 ei = meta->enc_start + (__u32)e;
                if (ei >= MAX_ENCRYPT_PACK_BPF)
                    break;
                struct xdp_encrypt_rule *er =
                    bpf_map_lookup_elem(&encrypt_rules_map, &ei);
                if (!er)
                    continue;
                if (encrypt_rule_matches(src_ip, dst_ip, l4_proto, sport, dport, er)) {
                    redirect_hit = 1;
                    break;
                }
            }

            if (redirect_hit)
                break;
        }
    }

    if (!redirect_hit) {
        inc_stat(8);
        return XDP_PASS;
    }

#if XDP_INGRESS_RATE_LIMIT
    {
        __u64 now = bpf_ktime_get_ns();
        __u32 rl_key = 0;
        __u64 pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);

        __u64 *last_reset = bpf_map_lookup_elem(&rl_last_reset_ns, &rl_key);
        __u64 *byte_count = bpf_map_lookup_elem(&rl_byte_count, &rl_key);
        if (!last_reset || !byte_count) {
            inc_stat(12);
            return XDP_PASS;
        }

        if (now - *last_reset > XDP_RL_WINDOW_NS) {
            *byte_count = 0;
            *last_reset = now;
        }

        if (*byte_count + pkt_len > XDP_RL_MAX_BYTES_PER_WINDOW) {
            inc_stat(11);
            return XDP_DROP;
        }
        *byte_count += pkt_len;
    }
#endif

    __u32 qid = NE_XSK_QUEUE_ID;
    int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
    if (!sock) {
        inc_stat(5);
        return XDP_PASS;
    }

    inc_stat(6);
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
