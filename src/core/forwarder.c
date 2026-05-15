#include "../../inc/forwarder.h"
#include "../../inc/packet_crypto.h"
#include "../../inc/flow_table.h"
#include "../../inc/config.h"
#include "../../inc/crypto_layer2.h"
#include "../../inc/crypto_layer3.h"
#include "../../inc/crypto_layer4.h"
#include "../../inc/crypto_policy_utils.h"
#include "../../inc/crypto_dispatch.h"
#include "../../inc/fragment.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

void forwarder_pin_cpu(void) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(FORWARDER_CPU_CORE, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

#define WORKER_RING_SIZE 4096

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;

static struct flow_table g_flow_table;

static struct frag_table g_wan_frag_l2;
static struct frag_table g_wan_frag_l3;
static struct frag_table g_wan_frag_l4;

static struct packet_crypto_ctx g_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];
static struct crypto_policy g_active_policies[MAX_CRYPTO_POLICIES];
static int g_active_policy_count = 0;
static struct packet_crypto_ctx g_prev_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_prev_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];
static struct crypto_policy g_prev_policies[MAX_CRYPTO_POLICIES];
static int g_prev_policy_count = 0;
static uint64_t g_prev_policy_grace_until_ms = 0;
#define POLICY_RELOAD_GRACE_MS 60000ULL
static uint64_t g_profile_hits[MAX_PROFILES];
static uint64_t g_profile_miss_hits;
static uint64_t g_profile_log_seq;
static int g_tcp_diag_enabled = 0;
static int g_tcp_diag_all_tcp = 0;


static struct app_config *g_cfg_ptr = NULL;
static atomic_int g_reload_pause = 0;
static atomic_int g_inflight_packets = 0;

static inline uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int packet_critical_enter(void) {
    for (;;) {
        while (atomic_load_explicit(&g_reload_pause, memory_order_acquire))
            sched_yield();
        atomic_fetch_add_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
        if (!atomic_load_explicit(&g_reload_pause, memory_order_acquire))
            return 1;
        atomic_fetch_sub_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
    }
}

static void packet_critical_leave(void) {
    atomic_fetch_sub_explicit(&g_inflight_packets, 1, memory_order_acq_rel);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static int is_ssh_flow(uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    return (protocol == IPPROTO_TCP) && (src_port == 22 || dst_port == 22);
}

static int tcp_diag_want_log(uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    if (!g_tcp_diag_enabled)
        return 0;
    if (g_tcp_diag_all_tcp)
        return (protocol == IPPROTO_TCP);
    return is_ssh_flow(protocol, src_port, dst_port);
}

/* Defaults match former NE_TCP_DIAG=1 NE_TCP_DIAG_ALL_TCP=1. Opt-out: NE_TCP_DIAG=0;
 * restrict to SSH-only logs: NE_TCP_DIAG_ALL_TCP=0. */
static int tcp_diag_env_is_off(const char *v) {
    return v && v[0] == '0' && v[1] == '\0';
}

static void forwarder_tcp_diag_print_ssh_hypothesis_banner(void);

static void forwarder_tcp_diag_apply_env(void) {
    const char *diag = getenv("NE_TCP_DIAG");
    g_tcp_diag_enabled = tcp_diag_env_is_off(diag) ? 0 : 1;

    const char *all_tcp = getenv("NE_TCP_DIAG_ALL_TCP");
    if (!g_tcp_diag_enabled)
        g_tcp_diag_all_tcp = 0;
    else
        g_tcp_diag_all_tcp = tcp_diag_env_is_off(all_tcp) ? 0 : 1;

    if (g_tcp_diag_enabled) {
        fprintf(stderr, "[TCP-DIAG] on (default all TCP; NE_TCP_DIAG=0 off, NE_TCP_DIAG_ALL_TCP=0 SSH-only)\n");
        fprintf(stderr,
                "[NE-RX] CLASS=... ; [NE-CHAIN] root=... tren cung dong NE-RX/NE-TX de biet: "
                "khong_toi_local vs sai_sau_ma_hoa_giai_ma_reasm vs loi_TX\n");
        fprintf(stderr,
                "[TCP-DIAG] WAN RX: moi goi nhan tren WAN in [NE-RX][RX_PKT]; decrypt OK/err xem "
                "[TCP-DIAG] RX-DEC-OK / RX-*FAIL va [NE-RX][CLASS=RX_*]. Im lang != client khong nhan — "
                "truoc day enc_l3 (fake proto) bi loc khoi log; gio khong loc RX_PKT/CLASS theo tuple wire.\n");
        forwarder_tcp_diag_print_ssh_hypothesis_banner();
    }
}

/* Tat ca gia thuyet SSH/TCP bat tay (trong pham vi NE) — grep [NE-HYP] */
static void forwarder_tcp_diag_print_ssh_hypothesis_banner(void) {
    fprintf(stderr,
            "[NE-HYP] ===== CHECKLIST: SSH khong bat tay — loai tru theo log (tim dung nguyen nhan roi debug) "
            "=====\n");
    fprintf(stderr,
            "[NE-HYP] H01_TX_STRICT_NO_POLICY: log [NE-TX] TX_NO_CRYPTO_POLICY_DROP hoac TX-SELECT cp=NULL + "
            "policy_count>0 (strict matrix)\n");
    fprintf(stderr,
            "[NE-HYP] H02_TX_POLICY_BYPASS_WRONG: TX-SELECT bypass=1 nhung van mong enc — policy sai action\n");
    fprintf(stderr,
            "[NE-HYP] H03_TX_ENCRYPT_L2L3L4_FAIL: [NE-TX] TX_L2/L3/L4_ENCRYPT_FAIL hoac TX_*SPLIT_ENCRYPT_FAIL — "
            "key, IV/nonce, buffer, layer khac RX\n");
    fprintf(stderr,
            "[NE-HYP] H04_TX_WAN_QUEUE_REJECT: [NE-TX] TX_WAN_SEND_FAIL / TX_BYPASS_WAN_SEND_FAIL — XSK TX day, "
            "NIC\n");
    fprintf(stderr,
            "[NE-HYP] H05_TX_WORKER_RING_FULL: [NE-TX] TX_WORKER_RING_FULL — vong local->worker day, SYN drop "
            "truoc ma hoa\n");
    fprintf(stderr,
            "[NE-HYP] H06_RX_WAN_DECRYPT_FAIL: [NE-RX] RX_L2_WAN_DECRYPT / RX_L2_MARKER / RX_L3/L4_*DECRYPT* — "
            "key/policy id khac TX hoac wire khong phai cipher NE\n");
    fprintf(stderr,
            "[NE-HYP] H07_RX_REASSEMBLE_FAIL: [NE-RX] RX_*REASSEMBLE_FAIL — mat manh, ID fragment lech hai dau\n");
    fprintf(stderr,
            "[NE-HYP] H08_RX_BAD_PLAINTEXT: [NE-RX] POST_DECRYPT_* / TO_LOCAL_IPV4_SHAPE — mo xong nhung IPv4/TCP "
            "vo ly\n");
    fprintf(stderr,
            "[NE-HYP] H09_RX_NO_DELIVERY_LOCAL: [NE-RX] RX_DST_MAC_NO_LOCAL / RX_LOCAL_INJECT — MAC dich, bang "
            "MAC, AF_XDP toi local\n");
    fprintf(stderr,
            "[NE-HYP] H10_MATRIX_PEER_SQL_SAI: matrix vs peer SQL doi nguoc — policy_id/decrypt ctx khac may kia\n");
    fprintf(stderr,
            "[NE-HYP] H11_MULTI_WAN_ASYM: TX-SSH-TX-PRE wan# khac duong RX — mat goi hoac sai thu tu (profile/WRR)\n");
    fprintf(stderr,
            "[NE-HYP] H12_FRAG_PENDING_OR_MTU: tren wire co fragment nhung khong du manh — MTU/PMTU, timeout "
            "reasm\n");
    fprintf(stderr,
            "[NE-HYP] H13_IP_ONLY_POLICY_PORTS: CRYPTO_POLICY_MATCH_IP_ONLY — port policy khong dung de match\n");
    fprintf(stderr,
            "[NE-HYP] H14_TCP_PIN_POLICY: tcp_policy_pin lech policy sau reload — grace / pin vs CIDR\n");
    fprintf(stderr,
            "[NE-HYP] H15_KHONG_PHAI_NE: tcpdump end-to-end; neu khong co [NE-TX]/[NE-RX] tuong ung flow thi "
            "ngoai NE\n");
    fprintf(stderr,
            "[NE-HYP] Doc [NE-CHAIN] root= tren dong NE-RX/NE-TX de gom nhanh: NO_DELIVERY vs BAD_PLAINTEXT vs "
            "RX_DECRYPT vs TX_*\n");
    fprintf(stderr, "[NE-HYP] ===== het checklist =====\n");
}

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS: return "bypass";
    case POLICY_ACTION_ENCRYPT_L2: return "enc_l2";
    case POLICY_ACTION_ENCRYPT_L3: return "enc_l3";
    case POLICY_ACTION_ENCRYPT_L4: return "enc_l4";
    default: return "unknown";
    }
}

static void log_tcp_diag_policy_select(const char *tag,
                                       uint32_t src_ip, uint16_t src_port,
                                       uint32_t dst_ip, uint16_t dst_port,
                                       const struct crypto_policy *cp,
                                       int bypass_crypto) {
    if (!g_tcp_diag_enabled)
        return;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    struct in_addr sa = { .s_addr = src_ip };
    struct in_addr da = { .s_addr = dst_ip };
    if (!inet_ntop(AF_INET, &sa, sip, sizeof(sip)))
        return;
    if (!inet_ntop(AF_INET, &da, dip, sizeof(dip)))
        return;
    fprintf(stderr,
            "[TCP-DIAG][%s] %s:%u -> %s:%u policy_id=%d action=%s bypass=%d\n",
            tag, sip, (unsigned)src_port, dip, (unsigned)dst_port,
            cp ? cp->id : -1, cp ? policy_action_name(cp->action) : "none",
            bypass_crypto);
}

static void log_tcp_diag_decrypt(const char *tag,
                                 uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port,
                                 int action_layer,
                                 int l3_extract_ok, int l3_policy_id,
                                 int l4_extract_ok, int l4_policy_id, int l4_nonce,
                                 int decrypt_rc) {
    if (!g_tcp_diag_enabled)
        return;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    struct in_addr sa = { .s_addr = src_ip };
    struct in_addr da = { .s_addr = dst_ip };
    if (!inet_ntop(AF_INET, &sa, sip, sizeof(sip)))
        return;
    if (!inet_ntop(AF_INET, &da, dip, sizeof(dip)))
        return;
    fprintf(stderr,
            "[TCP-DIAG][%s] %s:%u -> %s:%u action=%s rc=%d l3_ok=%d l3_pid=%d l4_ok=%d l4_pid=%d l4_nonce=%d\n",
            tag, sip, (unsigned)src_port, dip, (unsigned)dst_port,
            policy_action_name(action_layer), decrypt_rc,
            l3_extract_ok, l3_policy_id, l4_extract_ok, l4_policy_id, l4_nonce);
}

static void log_tcp_diag_decrypt_len(const char *tag,
                                     uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port,
                                     uint32_t old_len, uint32_t new_len,
                                     int post_parse_ok,
                                     uint8_t post_proto,
                                     uint16_t post_sport, uint16_t post_dport) {
    if (!g_tcp_diag_enabled)
        return;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    struct in_addr sa = { .s_addr = src_ip };
    struct in_addr da = { .s_addr = dst_ip };
    if (!inet_ntop(AF_INET, &sa, sip, sizeof(sip)))
        return;
    if (!inet_ntop(AF_INET, &da, dip, sizeof(dip)))
        return;
    fprintf(stderr,
            "[TCP-DIAG][%s] %s:%u -> %s:%u len=%u->%u post_parse=%d post_proto=%u post_ports=%u/%u\n",
            tag, sip, (unsigned)src_port, dip, (unsigned)dst_port,
            (unsigned)old_len, (unsigned)new_len,
            post_parse_ok, (unsigned)post_proto,
            (unsigned)post_sport, (unsigned)post_dport);
}

/* Classify WAN→stack failures: wrong decrypt, bad reassembly, or cleartext shape after NE. */
static int ne_rx_ipv4_frame_plausible(const uint8_t *pkt, uint32_t len) {
    int l3 = crypto_eth_ipv4_offset(pkt, len);
    if (l3 < 0 || (uint32_t)(l3 + 20) > len)
        return 0;
    const struct iphdr *ip = (const struct iphdr *)(pkt + (unsigned)l3);
    if (ip->version != 4)
        return 0;
    uint32_t tot = (uint32_t)ntohs(ip->tot_len);
    if (tot < 20u || (uint32_t)l3 + tot > len)
        return 0;
    int ihl = (int)ip->ihl * 4;
    if (ihl < 20 || (uint32_t)l3 + (uint32_t)ihl > len)
        return 0;
    if (ip->protocol == IPPROTO_TCP) {
        if ((uint32_t)l3 + (uint32_t)ihl + 20u > len)
            return 0;
    }
    return 1;
}

/* Handshake-oriented: map CLASS -> one root cause + what to verify next (VN). */
static void ne_chain_append_rx(const char *klass) {
    const char *root = "RX_OTHER";
    const char *vi = "Xem CLASS trong dong log.";
    if (!klass)
        klass = "";
    if (strncmp(klass, "RX_DST_MAC", 10) == 0 || strncmp(klass, "RX_LOCAL_INJECT", 15) == 0) {
        root = "NO_DELIVERY_TO_LOCAL_TCP";
        vi = "Khong day duoc goi vao stack TCP local (MAC dich / bridge / hang doi AF_XDP). "
             "Day KHONG phai loi ma hoa tren duong WAN den peer.";
    } else if (strstr(klass, "POST_DECRYPT") != NULL || strstr(klass, "TO_LOCAL_IPV4_SHAPE") != NULL) {
        root = "BAD_PLAINTEXT_AFTER_DECRYPT";
        vi = "Giai ma xong nhung IPv4/TCP sai kich thuoc hoac parse fail: doi chieu policy+key+layer "
             "voi TX va kiem tra reasm.";
    } else if (strstr(klass, "DECRYPT") != NULL || strstr(klass, "REASSEMBLE") != NULL ||
               strstr(klass, "_CTX") != NULL) {
        root = "RX_DECRYPT_REASM_OR_KEY";
        vi = "Peer co the gui dung nhung NE mo sai hoac rap manh sai: doi chieu TX (layer L2/L3/L4, "
             "key, policy id) va trace fragment.";
    }
    fprintf(stderr, " [NE-CHAIN] root=%s vi=\"%s\"", root, vi);
}

static void ne_chain_append_tx(const char *klass) {
    const char *root = "TX_OTHER";
    const char *vi = "Xem CLASS trong dong log.";
    if (!klass)
        klass = "";
    if (strstr(klass, "WORKER_RING") != NULL) {
        root = "TX_WORKER_BACKPRESSURE";
        vi = "Vong local->worker day: SYN co the bi drop truoc ma hoa — tang WORKER_RING_SIZE hoac giam tai.";
    } else if (strstr(klass, "ENCRYPT") != NULL || strstr(klass, "SPLIT") != NULL) {
        root = "TX_ENCRYPT_PIPELINE_FAIL";
        vi = "Ma hoa that bai: peer thuong im hoac RST — debug policy, layer, buffer truoc khi nghi RX.";
    } else if (strstr(klass, "NO_CRYPTO_POLICY") != NULL) {
        root = "TX_POLICY_DROP";
        vi = "Strict mode: khong policy khop — goi khong thanh cipher gui di, peer khong thay ban tin hop le.";
    } else if (strstr(klass, "WAN_SEND") != NULL || strstr(klass, "BYPASS_WAN") != NULL) {
        root = "TX_WAN_SEND_OR_QUEUE";
        vi = "Ma hoa (hoac bypass) xong nhung khong day len WAN: hang doi XSK / NIC.";
    }
    fprintf(stderr, " [NE-CHAIN] root=%s vi=\"%s\"", root, vi);
}

static void ne_rx_class_log(const char *klass,
                            const char *wan_if,
                            int wan_idx,
                            const char *phase,
                            const char *why,
                            uint32_t wire_len,
                            int wire_have_flow,
                            uint32_t sip,
                            uint16_t sport,
                            uint32_t dip,
                            uint16_t dport,
                            uint8_t proto,
                            const char *detail) {
    if (!g_tcp_diag_enabled)
        return;
    /* Do not gate on tcp_diag_want_log(wire tuple): enc_l3 wire uses fake IP
     * proto (e.g. 99), so SSH never "looks like" SSH on wire and errors were
     * invisible. */
    fprintf(stderr, "[NE-RX][CLASS=%s][wan=%s#%d][phase=%s] why=%s",
            klass, wan_if && wan_if[0] ? wan_if : "?", wan_idx,
            phase && phase[0] ? phase : "-", why && why[0] ? why : "-");
    if (wire_have_flow) {
        char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
        struct in_addr sa = { .s_addr = sip };
        struct in_addr da = { .s_addr = dip };
        if (inet_ntop(AF_INET, &sa, a, sizeof(a)) && inet_ntop(AF_INET, &da, b, sizeof(b)))
            fprintf(stderr, " %s:%u->%s:%u proto=%u", a, (unsigned)sport, b, (unsigned)dport, (unsigned)proto);
        else
            fprintf(stderr, " flow=(ntop_fail)");
    } else {
        fprintf(stderr, " flow=(wire_parse_fail)");
    }
    fprintf(stderr, " wire_len=%u", (unsigned)wire_len);
    if (detail && detail[0])
        fprintf(stderr, " %s", detail);
    ne_chain_append_rx(klass);
    fprintf(stderr, "\n");
}

static void ne_rx_pkt_recv_log(const struct xsk_interface *wan,
                               int wan_idx,
                               const uint8_t *pkt,
                               uint32_t pkt_len,
                               int wire_have_flow,
                               uint32_t sip,
                               uint16_t sport,
                               uint32_t dip,
                               uint16_t dport,
                               uint8_t proto) {
    if (!g_tcp_diag_enabled)
        return;
    /* Log every WAN frame when diag is on; wire tuple is often not TCP/22
     * under enc_l3 (fake protocol), so SSH-only filtering hid all RX_PKT. */
    unsigned eth = 0;
    if (pkt && pkt_len >= 14)
        eth = ((unsigned)pkt[12] << 8) | pkt[13];
    fprintf(stderr,
            "[NE-RX][RX_PKT][wan=%s#%d] len=%u ethertype=0x%04x",
            wan && wan->ifname[0] ? wan->ifname : "?", wan_idx, (unsigned)pkt_len, eth);
    if (wire_have_flow) {
        char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
        struct in_addr sa = { .s_addr = sip };
        struct in_addr da = { .s_addr = dip };
        if (inet_ntop(AF_INET, &sa, a, sizeof(a)) && inet_ntop(AF_INET, &da, b, sizeof(b)))
            fprintf(stderr, " %s:%u->%s:%u proto=%u", a, (unsigned)sport, b, (unsigned)dport, (unsigned)proto);
    } else {
        fprintf(stderr, " flow=(unparsed_on_wire)");
    }
    fprintf(stderr,
            " | if_peer_silent_suspect_NE_TX | if_peer_replies_gibberish_suspect_NE_RX_decrypt_reasm"
            " [NE-CHAIN] root=RX_PKT_OBSERVE next=neu_co_NE-RX_CLASS_thi_do_theo_root_cua_CLASS\n");
}

static void ne_tx_class_log(const char *klass,
                            const char *path,
                            const char *why,
                            int local_idx,
                            const char *wan_if,
                            int wan_idx,
                            int flow_ok,
                            uint32_t sip,
                            uint16_t sport,
                            uint32_t dip,
                            uint16_t dport,
                            uint8_t proto,
                            uint32_t len,
                            const char *detail) {
    if (!g_tcp_diag_enabled)
        return;
    if (flow_ok && !tcp_diag_want_log(proto, sport, dport))
        return;
    fprintf(stderr, "[NE-TX][CLASS=%s][path=%s][local=%d][wan=%s#%d] why=%s",
            klass, path && path[0] ? path : "-", local_idx,
            wan_if && wan_if[0] ? wan_if : "?", wan_idx,
            why && why[0] ? why : "-");
    if (flow_ok) {
        char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
        struct in_addr sa = { .s_addr = sip };
        struct in_addr da = { .s_addr = dip };
        if (inet_ntop(AF_INET, &sa, a, sizeof(a)) && inet_ntop(AF_INET, &da, b, sizeof(b)))
            fprintf(stderr, " %s:%u->%s:%u proto=%u", a, (unsigned)sport, b, (unsigned)dport, (unsigned)proto);
    } else
        fprintf(stderr, " flow=(unparsed)");
    fprintf(stderr, " len=%u", (unsigned)len);
    if (detail && detail[0])
        fprintf(stderr, " %s", detail);
    ne_chain_append_tx(klass);
    fprintf(stderr, " | TX_path_peer_may_be_silent\n");
}

static int prev_policy_grace_active(void) {
    if (g_prev_policy_count <= 0)
        return 0;
    uint64_t now = monotonic_ms();
    if (now == 0 || g_prev_policy_grace_until_ms == 0)
        return 0;
    return now <= g_prev_policy_grace_until_ms;
}

static int fwd_pi_for_action_wire(const struct forwarder *fwd, int action, uint32_t wire_pid) {
    if (!fwd || !fwd->cfg)
        return -1;
    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        if (!g_policy_crypto_ctx_ready[pi])
            continue;
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (cp->action == action && (uint32_t)cp->id == wire_pid)
            return pi;
    }
    return -1;
}

static int fwd_prev_pi_for_action_wire(int action, uint32_t wire_pid) {
    if (!prev_policy_grace_active())
        return -1;
    for (int ppi = 0; ppi < g_prev_policy_count && ppi < MAX_CRYPTO_POLICIES; ppi++) {
        if (!g_prev_policy_crypto_ctx_ready[ppi])
            continue;
        if (g_prev_policies[ppi].action == action && (uint32_t)g_prev_policies[ppi].id == wire_pid)
            return ppi;
    }
    return -1;
}

static int same_topology(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    for (int i = 0; i < a->local_count; i++) {
        if (strcmp(a->locals[i].ifname, b->locals[i].ifname) != 0)
            return 0;
    }
    for (int i = 0; i < a->wan_count; i++) {
        if (strcmp(a->wans[i].ifname, b->wans[i].ifname) != 0)
            return 0;
    }
    return 1;
}

static int same_crypto_policy(const struct crypto_policy *a, const struct crypto_policy *b) {
    if (!a || !b)
        return 0;
    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask &&
           a->crypto_mode == b->crypto_mode &&
           a->aes_bits == b->aes_bits &&
           a->nonce_size == b->nonce_size &&
           memcmp(a->key, b->key, AES_KEY_LEN) == 0;
}

static int crypto_runtime_changed(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 1;
    if (a->crypto_enabled != b->crypto_enabled ||
        a->encrypt_layer != b->encrypt_layer ||
        a->crypto_mode != b->crypto_mode ||
        a->aes_bits != b->aes_bits ||
        a->nonce_size != b->nonce_size ||
        a->fake_ethertype_ipv4 != b->fake_ethertype_ipv4 ||
        a->fake_protocol != b->fake_protocol ||
        a->policy_count != b->policy_count) {
        return 1;
    }
    for (int i = 0; i < a->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        if (!same_crypto_policy(&a->policies[i], &b->policies[i]))
            return 1;
    }
    return 0;
}

static int forwarding_runtime_changed(const struct app_config *a, const struct app_config *b) {
    if (!a || !b)
        return 1;
    if (a->profile_count != b->profile_count ||
        a->wan_count != b->wan_count ||
        a->local_count != b->local_count) {
        return 1;
    }
    return 0;
}

static int rebuild_crypto_runtime(const struct app_config *cfg, int *has_encrypt_l2_out) {
    int has_encrypt_l2 = 0;
    struct packet_crypto_ctx old_ctx[MAX_CRYPTO_POLICIES];
    int old_ready[MAX_CRYPTO_POLICIES];
    struct crypto_policy old_policies[MAX_CRYPTO_POLICIES];
    int old_policy_count = g_active_policy_count;
    if (old_policy_count > MAX_CRYPTO_POLICIES)
        old_policy_count = MAX_CRYPTO_POLICIES;
    memcpy(old_ctx, g_policy_crypto_ctx, sizeof(old_ctx));
    memcpy(old_ready, g_policy_crypto_ctx_ready, sizeof(old_ready));
    memcpy(old_policies, g_active_policies, sizeof(old_policies));

    memset(g_policy_crypto_ctx_ready, 0, sizeof(g_policy_crypto_ctx_ready));

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action == POLICY_ACTION_BYPASS)
            continue;
        int key_nonzero = 0;
        for (int k = 0; k < AES_KEY_LEN; k++) {
            if (cp->key[k] != 0) { key_nonzero = 1; break; }
        }
        if (!key_nonzero)
            continue;

        int reused = 0;
        for (int oi = 0; oi < old_policy_count; oi++) {
            if (!old_ready[oi])
                continue;
            if (!same_crypto_policy(&old_policies[oi], cp))
                continue;
            g_policy_crypto_ctx[pi] = old_ctx[oi];
            g_policy_crypto_ctx_ready[pi] = 1;
            reused = 1;
            break;
        }

        if (!reused) {
            packet_crypto_set_aes_bits(cp->aes_bits);
            if (packet_crypto_init(&g_policy_crypto_ctx[pi], cp->key) != 0) {
                fprintf(stderr, "[DB CRYPTO] Failed to init policy ctx id=%d (AES=%d)\n",
                        cp->id, cp->aes_bits);
                continue;
            }
            g_policy_crypto_ctx_ready[pi] = 1;
        }
        if (cp->action == POLICY_ACTION_ENCRYPT_L2)
            has_encrypt_l2 = 1;
    }
    g_active_policy_count = cfg->policy_count;
    if (g_active_policy_count > MAX_CRYPTO_POLICIES)
        g_active_policy_count = MAX_CRYPTO_POLICIES;
    memcpy(g_active_policies, cfg->policies, sizeof(g_active_policies));
    if (has_encrypt_l2_out)
        *has_encrypt_l2_out = has_encrypt_l2;
    return 0;
}

static void compute_profile_weighted_wan_windows(const struct app_config *cfg,
                                                 uint32_t *out_wan_window_sizes,
                                                 int max_wans) {
    if (!cfg || !out_wan_window_sizes || max_wans <= 0)
        return;


    const uint32_t base_kb = WAN_REORDER_WINDOW_KB;
    const uint32_t base_bytes = base_kb * 1024U;


    const uint32_t min_kb = 512; 
    const uint32_t min_bytes = min_kb * 1024U;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled || p->wan_count <= 0)
            continue;

        int sumw = 0;
        for (int i = 0; i < p->wan_count; i++) {
            int w = p->wan_bandwidth_weight[i];
            if (w > 0)
                sumw += w;
        }
        if (sumw <= 0)
            continue; 

        for (int i = 0; i < p->wan_count; i++) {
            int wan_idx = p->wan_indices[i];
            int w = p->wan_bandwidth_weight[i];
            if (wan_idx < 0 || wan_idx >= max_wans)
                continue;
            if (w <= 0)
                continue;

            uint64_t scaled = ((uint64_t)base_bytes * (uint64_t)w) / (uint64_t)sumw;
            uint32_t win = (scaled > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)scaled;
            win = clamp_u32(win, min_bytes, base_bytes);
            out_wan_window_sizes[wan_idx] = win;
        }
    }
}

#define TCP_POLICY_PIN_TIMEOUT_SEC 120

struct tcp_policy_pin_entry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int policy_pi;
    uint64_t last_seen_sec;
    struct tcp_policy_pin_entry *next;
};

static struct tcp_policy_pin_entry *g_tcp_policy_pins[FLOW_TABLE_SIZE];
static pthread_mutex_t g_tcp_policy_pin_locks[FLOW_TABLE_SIZE];
static int g_tcp_policy_pin_inited;

static uint64_t tcp_policy_pin_now_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec;
}

static void tcp_policy_pin_normalize_tuple(uint32_t *src_ip, uint32_t *dst_ip,
                                           uint16_t *src_port, uint16_t *dst_port) {
    if (!src_ip || !dst_ip || !src_port || !dst_port)
        return;
    uint32_t a = ntohl(*src_ip);
    uint32_t b = ntohl(*dst_ip);
    if (a > b || (a == b && *src_port > *dst_port)) {
        uint32_t t_ip = *src_ip;
        *src_ip = *dst_ip;
        *dst_ip = t_ip;
        uint16_t t_p = *src_port;
        *src_port = *dst_port;
        *dst_port = t_p;
    }
}

static uint32_t tcp_policy_pin_hash(uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t src_port, uint16_t dst_port) {
    uint32_t hash = src_ip ^ dst_ip;
    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= (uint32_t)IPPROTO_TCP;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6bU;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35U;
    hash ^= (hash >> 16);
    return hash % FLOW_TABLE_SIZE;
}

static void tcp_policy_pin_init(void) {
    if (g_tcp_policy_pin_inited)
        return;
    memset(g_tcp_policy_pins, 0, sizeof(g_tcp_policy_pins));
    for (int i = 0; i < FLOW_TABLE_SIZE; i++)
        pthread_mutex_init(&g_tcp_policy_pin_locks[i], NULL);
    g_tcp_policy_pin_inited = 1;
}

static void tcp_policy_pin_free_bucket_unlocked(struct tcp_policy_pin_entry **head) {
    while (*head) {
        struct tcp_policy_pin_entry *n = (*head)->next;
        free(*head);
        *head = n;
    }
}

static void tcp_policy_pin_cleanup(void) {
    if (!g_tcp_policy_pin_inited)
        return;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&g_tcp_policy_pin_locks[i]);
        tcp_policy_pin_free_bucket_unlocked(&g_tcp_policy_pins[i]);
        pthread_mutex_unlock(&g_tcp_policy_pin_locks[i]);
        pthread_mutex_destroy(&g_tcp_policy_pin_locks[i]);
    }
    memset(g_tcp_policy_pin_locks, 0, sizeof(g_tcp_policy_pin_locks));
    g_tcp_policy_pin_inited = 0;
}

static void tcp_policy_pin_clear_all(void) {
    if (!g_tcp_policy_pin_inited)
        return;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&g_tcp_policy_pin_locks[i]);
        tcp_policy_pin_free_bucket_unlocked(&g_tcp_policy_pins[i]);
        pthread_mutex_unlock(&g_tcp_policy_pin_locks[i]);
    }
}

static void tcp_policy_pin_gc(void) {
    if (!g_tcp_policy_pin_inited || !crypto_enabled)
        return;
    uint64_t now = tcp_policy_pin_now_sec();
    if (now == 0)
        return;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&g_tcp_policy_pin_locks[i]);
        struct tcp_policy_pin_entry **pp = &g_tcp_policy_pins[i];
        while (*pp) {
            struct tcp_policy_pin_entry *e = *pp;
            if (now - e->last_seen_sec > (uint64_t)TCP_POLICY_PIN_TIMEOUT_SEC) {
                *pp = e->next;
                free(e);
            } else {
                pp = &e->next;
            }
        }
        pthread_mutex_unlock(&g_tcp_policy_pin_locks[i]);
    }
}

static void tcp_policy_pin_set(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port, int policy_pi) {
    if (!crypto_enabled || !g_tcp_policy_pin_inited)
        return;
    if (policy_pi < 0 || policy_pi >= MAX_CRYPTO_POLICIES)
        return;

    uint32_t a = src_ip, b = dst_ip;
    uint16_t sp = src_port, dp = dst_port;
    tcp_policy_pin_normalize_tuple(&a, &b, &sp, &dp);
    uint32_t idx = tcp_policy_pin_hash(a, b, sp, dp);
    uint64_t now = tcp_policy_pin_now_sec();

    pthread_mutex_lock(&g_tcp_policy_pin_locks[idx]);
    struct tcp_policy_pin_entry *e = g_tcp_policy_pins[idx];
    while (e) {
        if (e->src_ip == a && e->dst_ip == b && e->src_port == sp && e->dst_port == dp) {
            e->policy_pi = policy_pi;
            e->last_seen_sec = now;
            pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
            return;
        }
        e = e->next;
    }

    struct tcp_policy_pin_entry *ne =
        (struct tcp_policy_pin_entry *)calloc(1, sizeof(struct tcp_policy_pin_entry));
    if (!ne) {
        pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
        return;
    }
    ne->src_ip = a;
    ne->dst_ip = b;
    ne->src_port = sp;
    ne->dst_port = dp;
    ne->policy_pi = policy_pi;
    ne->last_seen_sec = now;
    ne->next = g_tcp_policy_pins[idx];
    g_tcp_policy_pins[idx] = ne;
    pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
}

static void tcp_policy_pin_remove(uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port) {
    if (!crypto_enabled || !g_tcp_policy_pin_inited)
        return;

    uint32_t a = src_ip, b = dst_ip;
    uint16_t sp = src_port, dp = dst_port;
    tcp_policy_pin_normalize_tuple(&a, &b, &sp, &dp);
    uint32_t idx = tcp_policy_pin_hash(a, b, sp, dp);

    pthread_mutex_lock(&g_tcp_policy_pin_locks[idx]);
    struct tcp_policy_pin_entry **pp = &g_tcp_policy_pins[idx];
    while (*pp) {
        struct tcp_policy_pin_entry *e = *pp;
        if (e->src_ip == a && e->dst_ip == b && e->src_port == sp && e->dst_port == dp) {
            *pp = e->next;
            free(e);
            break;
        }
        pp = &e->next;
    }
    pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
}

static const struct crypto_policy *tcp_policy_pin_lookup(struct forwarder *fwd,
                                                         uint32_t src_ip, uint32_t dst_ip,
                                                         uint16_t src_port, uint16_t dst_port) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !g_tcp_policy_pin_inited)
        return NULL;

    uint32_t a = src_ip, b = dst_ip;
    uint16_t sp = src_port, dp = dst_port;
    tcp_policy_pin_normalize_tuple(&a, &b, &sp, &dp);
    uint32_t idx = tcp_policy_pin_hash(a, b, sp, dp);
    uint64_t now = tcp_policy_pin_now_sec();

    pthread_mutex_lock(&g_tcp_policy_pin_locks[idx]);
    struct tcp_policy_pin_entry **pp = &g_tcp_policy_pins[idx];
    while (*pp) {
        struct tcp_policy_pin_entry *e = *pp;
        if (e->src_ip == a && e->dst_ip == b && e->src_port == sp && e->dst_port == dp) {
            int pi = e->policy_pi;
            int ok = (pi >= 0 && pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES);
            const struct crypto_policy *pol = ok ? &fwd->cfg->policies[pi] : NULL;
            if (ok && pol->action != POLICY_ACTION_BYPASS && !g_policy_crypto_ctx_ready[pi])
                ok = 0;

            if (ok) {
                e->last_seen_sec = now;
                pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
                return pol;
            }

            *pp = e->next;
            free(e);
            pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
            return NULL;
        }
        pp = &e->next;
    }
    pthread_mutex_unlock(&g_tcp_policy_pin_locks[idx]);
    return NULL;
}

static int tcp_ipv4_tcp_flags(void *pkt_data, uint32_t pkt_len, uint8_t *flags_out) {
    if (!flags_out)
        return -1;
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0 || pkt_len < (uint32_t)(l3_off + 20))
        return -1;
    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    if (ip->protocol != IPPROTO_TCP)
        return -1;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 14))
        return -1;
    uint8_t *th = pkt + l3_off + ip_hdr_len;
    *flags_out = th[13];
    return 0;
}

static void tcp_diag_flags_fmt(uint8_t f, char *buf, size_t buflen) {
    size_t n = 0;
    if (!buf || buflen < 8)
        return;
    buf[0] = '\0';
    if (f & TH_FIN) {
        int r = snprintf(buf + n, buflen - n, "%sFIN", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (f & TH_SYN) {
        int r = snprintf(buf + n, buflen - n, "%sSYN", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (f & TH_RST) {
        int r = snprintf(buf + n, buflen - n, "%sRST", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (f & TH_PUSH) {
        int r = snprintf(buf + n, buflen - n, "%sPSH", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (f & TH_ACK) {
        int r = snprintf(buf + n, buflen - n, "%sACK", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (f & TH_URG) {
        int r = snprintf(buf + n, buflen - n, "%sURG", n ? "," : "");
        if (r > 0)
            n += (size_t)r;
    }
    if (n == 0)
        snprintf(buf, buflen, "0x%02x", (unsigned)f);
}

static int select_wan_idx_for_packet(struct forwarder *fwd,
                                     int local_idx,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t protocol, uint32_t pkt_len) {

    if (fwd && fwd->cfg && fwd->cfg->profile_count > 0 &&
        local_idx >= 0 && local_idx < fwd->cfg->local_count) {
        int profile_idx = config_select_profile_for_local(fwd->cfg, local_idx);
        if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
            struct profile_config *p = &fwd->cfg->profiles[profile_idx];
            if (p->wan_count > 1) {
                int allowed[MAX_INTERFACES];
                int weights[MAX_INTERFACES];
                int n = 0;
                int any_weight = 0;
                for (int i = 0; i < p->wan_count; i++) {
                    if (p->wan_bandwidth_weight[i] > 0)
                        any_weight = 1;
                }
                for (int i = 0; i < p->wan_count && n < MAX_INTERFACES; i++) {
                    int wi = p->wan_indices[i];
                    if (wi < 0 || wi >= fwd->cfg->wan_count)
                        continue;
                    if (any_weight && p->wan_bandwidth_weight[i] <= 0)
                        continue;
                    allowed[n] = wi;
                    weights[n] = p->wan_bandwidth_weight[i];
                    n++;
                }
                if (n == 1)
                    return allowed[0];
                if (n > 1) {
                    const int *wp = any_weight ? weights : NULL;
                    return flow_table_get_wan_profile(&g_flow_table,
                                                      src_ip, dst_ip,
                                                      src_port, dst_port,
                                                      protocol, pkt_len,
                                                      allowed, n, wp);
                }
            } else if (p->wan_count == 1) {
                int wi = p->wan_indices[0];
                if (wi >= 0 && wi < fwd->cfg->wan_count)
                    return wi;
            }
        }
    }

    return flow_table_get_wan(&g_flow_table,
                               src_ip, dst_ip, src_port, dst_port,
                               protocol, pkt_len);
}

static const struct crypto_policy *select_crypto_policy_for_packet(struct forwarder *fwd,
                                                                     int local_idx,
                                                                     uint32_t src_ip, uint32_t dst_ip,
                                                                     uint16_t src_port, uint16_t dst_port,
                                                                     uint8_t protocol) {
    if (!fwd || !fwd->cfg)
        return NULL;
    return crypto_select_policy_for_local(fwd->cfg, local_idx,
                                           src_ip, dst_ip,
                                           src_port, dst_port,
                                           protocol);
}

static int policy_index_from_action_id_current(const struct forwarder *fwd,
                                               int action_layer,
                                               uint32_t policy_wire_id) {
    if (!fwd || !fwd->cfg)
        return -1;
    if (action_layer < 0 || action_layer > POLICY_ACTION_ENCRYPT_L4)
        return -1;
    int pi = fwd_pi_for_action_wire(fwd, action_layer, policy_wire_id);
    if (pi < 0 || pi >= fwd->cfg->policy_count || pi >= MAX_CRYPTO_POLICIES)
        return -1;
    if (!g_policy_crypto_ctx_ready[pi])
        return -1;
    return pi;
}

static void apply_default_crypto_params(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    crypto_apply_default_from_cfg(fwd->cfg);
}

static void apply_crypto_params_from_policy(const struct crypto_policy *cp) {
    if (!cp)
        return;
    crypto_apply_from_policy(cp);
}

static int encrypt_packet_with_ctx(struct packet_crypto_ctx *ctx,
                                     void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled || !ctx) return 0;
    int new_len = packet_encrypt(ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0)
        return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}


#define LOCAL_MAC_LEARN_MAX 2048
#define LOCAL_MAC_AGE_MS    300000ULL

struct local_mac_entry {
    uint8_t mac[MAC_LEN];
    int local_idx;
    uint64_t last_seen_ms;
    uint8_t valid;
};

static struct local_mac_entry g_local_mac_table[LOCAL_MAC_LEARN_MAX];
static pthread_mutex_t g_local_mac_lock = PTHREAD_MUTEX_INITIALIZER;

static inline int mac_is_zero(const uint8_t mac[MAC_LEN]) {
    for (int i = 0; i < MAC_LEN; i++) {
        if (mac[i] != 0)
            return 0;
    }
    return 1;
}

static inline int mac_is_broadcast(const uint8_t mac[MAC_LEN]) {
    for (int i = 0; i < MAC_LEN; i++) {
        if (mac[i] != 0xFF)
            return 0;
    }
    return 1;
}

static inline int mac_is_multicast(const uint8_t mac[MAC_LEN]) {
    return (mac[0] & 0x01) != 0;
}

static inline uint32_t local_mac_hash(const uint8_t mac[MAC_LEN]) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < MAC_LEN; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return h;
}

static void local_mac_learn(int local_idx, const uint8_t mac[MAC_LEN]) {
    if (local_idx < 0 || local_idx >= MAX_INTERFACES || !mac)
        return;
    if (mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return;

    uint64_t now = monotonic_ms();
    uint32_t start = local_mac_hash(mac) % LOCAL_MAC_LEARN_MAX;

    pthread_mutex_lock(&g_local_mac_lock);
    int free_slot = -1;
    for (uint32_t step = 0; step < LOCAL_MAC_LEARN_MAX; step++) {
        uint32_t idx = (start + step) % LOCAL_MAC_LEARN_MAX;
        struct local_mac_entry *e = &g_local_mac_table[idx];
        if (!e->valid) {
            free_slot = (int)idx;
            break;
        }
        if (memcmp(e->mac, mac, MAC_LEN) == 0) {
            e->local_idx = local_idx;
            e->last_seen_ms = now;
            pthread_mutex_unlock(&g_local_mac_lock);
            return;
        }
        if ((now > e->last_seen_ms) && ((now - e->last_seen_ms) > LOCAL_MAC_AGE_MS)) {
            e->valid = 0;
            free_slot = (int)idx;
            break;
        }
    }
    if (free_slot < 0)
        free_slot = (int)start;

    struct local_mac_entry *dst = &g_local_mac_table[free_slot];
    memcpy(dst->mac, mac, MAC_LEN);
    dst->local_idx = local_idx;
    dst->last_seen_ms = now;
    dst->valid = 1;
    pthread_mutex_unlock(&g_local_mac_lock);
}

static int local_mac_lookup(const uint8_t mac[MAC_LEN]) {
    if (!mac || mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return -1;

    uint64_t now = monotonic_ms();
    uint32_t start = local_mac_hash(mac) % LOCAL_MAC_LEARN_MAX;

    pthread_mutex_lock(&g_local_mac_lock);
    for (uint32_t step = 0; step < LOCAL_MAC_LEARN_MAX; step++) {
        uint32_t idx = (start + step) % LOCAL_MAC_LEARN_MAX;
        struct local_mac_entry *e = &g_local_mac_table[idx];
        if (!e->valid)
            continue;
        if (memcmp(e->mac, mac, MAC_LEN) == 0) {
            if ((now > e->last_seen_ms) && ((now - e->last_seen_ms) > LOCAL_MAC_AGE_MS)) {
                e->valid = 0;
                break;
            }
            int out = e->local_idx;
            pthread_mutex_unlock(&g_local_mac_lock);
            return out;
        }
    }
    pthread_mutex_unlock(&g_local_mac_lock);
    return -1;
}

static void learn_local_src_mac(struct forwarder *fwd, int local_idx, const uint8_t *pkt,
                                uint32_t pkt_len) {
    if (!fwd || !pkt || pkt_len < sizeof(struct ether_header))
        return;
    const uint8_t *sm = pkt + 6;
    if (mac_is_zero(sm) || mac_is_broadcast(sm) || mac_is_multicast(sm))
        return;
    if (memcmp(fwd->cfg->locals[local_idx].dst_mac, sm, MAC_LEN) == 0)
        return;
    local_mac_learn(local_idx, sm);
    memcpy(fwd->cfg->locals[local_idx].dst_mac, sm, MAC_LEN);
    memcpy(fwd->locals[local_idx].dst_mac, sm, MAC_LEN);
}

static int local_idx_from_dst_mac(struct forwarder *fwd, const uint8_t *pkt, uint32_t pkt_len) {
    if (!fwd || !pkt || pkt_len < sizeof(struct ether_header))
        return -1;
    /* Match inner ether_dhost to peer MAC seeded at startup (or learned from local RX src). */
    int local_idx = local_mac_lookup(pkt);
    if (local_idx < 0 || local_idx >= fwd->local_count)
        return -1;
    return local_idx;
}

static void local_mac_table_clear(void) {
    pthread_mutex_lock(&g_local_mac_lock);
    for (uint32_t i = 0; i < LOCAL_MAC_LEARN_MAX; i++)
        g_local_mac_table[i].valid = 0;
    pthread_mutex_unlock(&g_local_mac_lock);
}

static int local_idx_by_ifname_cfg(struct app_config *cfg, const char *name) {
    if (!cfg || !name || !name[0])
        return -1;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, name) == 0)
            return i;
    }
    return -1;
}

static int read_local_iface_hwaddr(const char *ifname, uint8_t mac[MAC_LEN], int *ioctl_errno_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (ioctl_errno_out)
            *ioctl_errno_out = errno;
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        if (ioctl_errno_out)
            *ioctl_errno_out = errno;
        close(fd);
        return -1;
    }
    close(fd);
    if ((unsigned int)ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -2;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    return 0;
}

static void local_mac_log_iface_and_peer(const char *ifname, const uint8_t peer[MAC_LEN],
                                         uint8_t *store_src_mac) {
    uint8_t loc[MAC_LEN];
    int ioctl_err = 0;
    int rr = read_local_iface_hwaddr(ifname, loc, &ioctl_err);

    if (rr == 0) {
        if (store_src_mac)
            memcpy(store_src_mac, loc, MAC_LEN);
        fprintf(stderr,
                "[LOCAL-MAC] %s local %02x:%02x:%02x:%02x:%02x:%02x peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                loc[0], loc[1], loc[2], loc[3], loc[4], loc[5],
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    } else if (rr == -2) {
        fprintf(stderr,
                "[LOCAL-MAC] %s local not_ether peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    } else {
        fprintf(stderr,
                "[LOCAL-MAC] %s local ioctl_failed err=%d peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                ioctl_err,
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    }
}

#define NE_LLADDR_MAX 8

static int merge_lladdr(FILE *fp, uint8_t out[MAC_LEN]) {
    uint8_t uniq[NE_LLADDR_MAX][MAC_LEN];
    int n = 0;
    char line[768];

    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "lladdr ");
        if (!p)
            continue;
        p += 7;
        char mstr[32];
        if (sscanf(p, "%31s", mstr) != 1)
            continue;
        uint8_t m[MAC_LEN];
        if (parse_mac(mstr, m) != 0)
            continue;
        if (mac_is_zero(m) || mac_is_broadcast(m) || mac_is_multicast(m))
            continue;
        int dup = 0;
        for (int j = 0; j < n; j++) {
            if (memcmp(uniq[j], m, MAC_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (n >= NE_LLADDR_MAX)
            return -2;
        memcpy(uniq[n++], m, MAC_LEN);
    }
    if (n == 1) {
        memcpy(out, uniq[0], MAC_LEN);
        return 0;
    }
    if (n == 0)
        return -1;
    return -2;
}

static int merge_bridge_fdb(FILE *fp, uint8_t out[MAC_LEN], const uint8_t *skip_mac) {
    uint8_t uniq[NE_LLADDR_MAX][MAC_LEN];
    int n = 0;
    char line[768];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "self permanent"))
            continue;
        char macstr[32];
        if (sscanf(line, "%31s", macstr) != 1)
            continue;
        if (!strchr(macstr, ':'))
            continue;
        uint8_t m[MAC_LEN];
        if (parse_mac(macstr, m) != 0)
            continue;
        if (mac_is_zero(m) || mac_is_broadcast(m) || mac_is_multicast(m))
            continue;
        if (skip_mac && memcmp(m, skip_mac, MAC_LEN) == 0)
            continue;
        int dup = 0;
        for (int j = 0; j < n; j++) {
            if (memcmp(uniq[j], m, MAC_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (n >= NE_LLADDR_MAX)
            return -2;
        memcpy(uniq[n++], m, MAC_LEN);
    }
    if (n == 1) {
        memcpy(out, uniq[0], MAC_LEN);
        return 0;
    }
    if (n == 0)
        return -1;
    return -2;
}

static int net_sysfs_bridge_master(const char *slave, char master[IFNAMSIZ]) {
    char path[256];
    char buf[512];
    ssize_t len;

    snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge", slave);
    len = readlink(path, buf, sizeof(buf) - 1);
    if (len < 0)
        return -1;
    buf[len] = '\0';
    const char *base = strrchr(buf, '/');
    if (!base || !base[1])
        return -1;
    snprintf(master, IFNAMSIZ, "%s", base + 1);
    return 0;
}

static int merge_arp_device(const char *dev, uint8_t out[MAC_LEN], const uint8_t *skip_mac) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return -1;
    char line[512];
    uint8_t uniq[NE_LLADDR_MAX][MAC_LEN];
    int n = 0;

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        char ip[64], htype[32], flags[32], macstr[32], mask[32], dname[IFNAMSIZ];
        if (sscanf(line, "%63s %31s %31s %31s %31s %31s", ip, htype, flags, macstr, mask, dname) != 6)
            continue;
        if (strcmp(dname, dev) != 0)
            continue;
        if (strcmp(macstr, "00:00:00:00:00:00") == 0)
            continue;
        uint8_t m[MAC_LEN];
        if (parse_mac(macstr, m) != 0)
            continue;
        if (mac_is_zero(m) || mac_is_broadcast(m) || mac_is_multicast(m))
            continue;
        if (skip_mac && memcmp(m, skip_mac, MAC_LEN) == 0)
            continue;
        int dup = 0;
        for (int j = 0; j < n; j++) {
            if (memcmp(uniq[j], m, MAC_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (n >= NE_LLADDR_MAX)
            return -2;
        memcpy(uniq[n++], m, MAC_LEN);
    }
    fclose(fp);
    if (n == 1) {
        memcpy(out, uniq[0], MAC_LEN);
        return 0;
    }
    if (n == 0)
        return -1;
    return -2;
}

static int peer_mac_from_full_bridge_fdb(const char *ifname, const char *brm,
                                           const uint8_t *skip_mac, uint8_t out[MAC_LEN]) {
    char devm[IFNAMSIZ + 16];
    snprintf(devm, sizeof(devm), " dev %s ", ifname);

    FILE *fp = popen("bridge fdb show 2>/dev/null", "r");
    if (!fp)
        return -1;

    uint8_t dyn[NE_LLADDR_MAX][MAC_LEN];
    int n_dyn = 0;
    uint8_t oth[NE_LLADDR_MAX][MAC_LEN];
    int n_oth = 0;
    char line[768];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "self permanent"))
            continue;
        if (!strstr(line, devm))
            continue;
        char *mp = strstr(line, "master ");
        if (!mp)
            continue;
        char brtok[IFNAMSIZ];
        if (sscanf(mp, "master %31s", brtok) != 1 || strcmp(brtok, brm) != 0)
            continue;
        char macstr[32];
        if (sscanf(line, "%31s", macstr) != 1)
            continue;
        if (!strchr(macstr, ':'))
            continue;
        uint8_t m[MAC_LEN];
        if (parse_mac(macstr, m) != 0)
            continue;
        if (mac_is_zero(m) || mac_is_broadcast(m) || mac_is_multicast(m))
            continue;
        if (skip_mac && memcmp(m, skip_mac, MAC_LEN) == 0)
            continue;
        int is_perm = (strstr(line, "permanent") != NULL);
        uint8_t(*arr)[MAC_LEN];
        int *np;
        if (is_perm) {
            arr = oth;
            np = &n_oth;
        } else {
            arr = dyn;
            np = &n_dyn;
        }
        int dup = 0;
        for (int j = 0; j < *np; j++) {
            if (memcmp(arr[j], m, MAC_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (*np >= NE_LLADDR_MAX) {
            pclose(fp);
            return -2;
        }
        memcpy(arr[(*np)++], m, MAC_LEN);
    }
    pclose(fp);

    if (n_dyn == 1) {
        memcpy(out, dyn[0], MAC_LEN);
        return 0;
    }
    if (n_dyn > 1)
        return -2;
    if (n_oth == 1) {
        memcpy(out, oth[0], MAC_LEN);
        return 0;
    }
    if (n_oth > 1)
        return -2;
    return -1;
}

static int peer_mac_from_kernel(const char *ifname, uint8_t mac_out[MAC_LEN]) {
    char cmd[384];
    FILE *fp;
    uint8_t local_hw[MAC_LEN];
    int have_local = (read_local_iface_hwaddr(ifname, local_hw, NULL) == 0);
    char brm[IFNAMSIZ];
    int have_br = (net_sysfs_bridge_master(ifname, brm) == 0);

    if (have_br) {
        int bf = peer_mac_from_full_bridge_fdb(ifname, brm, have_local ? local_hw : NULL, mac_out);
        if (bf == 0) {
            fprintf(stderr,
                    "[LOCAL-MAC] %s peer from bridge fdb (dev %s master %s, learned or single candidate)\n",
                    ifname, ifname, brm);
            return 0;
        }
        if (bf == -2) {
            fprintf(stderr,
                    "[LOCAL-MAC][WARN] %s: multiple MAC in `bridge fdb show` for dev %s master %s; "
                    "try NE_LOCAL_MAC_PRELOAD or reduce hosts on segment\n",
                    ifname, ifname, brm);
        }
    }

    snprintf(cmd, sizeof(cmd), "ip neigh show dev %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (fp) {
        int r = merge_lladdr(fp, mac_out);
        pclose(fp);
        if (r == 0)
            return 0;
        if (r == -2) {
            fprintf(stderr,
                    "[LOCAL-MAC][WARN] %s: ip neigh has multiple lladdr; trying bridge master / fdb\n",
                    ifname);
        }
    }

    if (have_br) {
        snprintf(cmd, sizeof(cmd), "ip neigh show dev %s 2>/dev/null", brm);
        fp = popen(cmd, "r");
        if (fp) {
            int r = merge_lladdr(fp, mac_out);
            pclose(fp);
            if (r == 0)
                return 0;
            if (r == -2) {
                fprintf(stderr,
                        "[LOCAL-MAC][WARN] %s: bridge %s neigh has multiple lladdr; trying bridge fdb\n",
                        ifname, brm);
            }
        }
    }

    snprintf(cmd, sizeof(cmd), "bridge fdb show dev %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (!fp)
        return -1;
    int r = merge_bridge_fdb(fp, mac_out, have_local ? local_hw : NULL);
    pclose(fp);
    if (r == 0)
        return 0;
    if (r == -2)
        fprintf(stderr, "[FATAL][LOCAL-MAC] %s bridge fdb multiple MAC\n", ifname);

    if (have_br) {
        int ar = merge_arp_device(brm, mac_out, have_local ? local_hw : NULL);
        if (ar == 0)
            return 0;
        if (ar == -2) {
            fprintf(stderr,
                    "[LOCAL-MAC][WARN] %s: /proc/net/arp on %s has multiple MAC; try NE_LOCAL_MAC_PRELOAD\n",
                    ifname, brm);
        }
    }
    if (merge_arp_device(ifname, mac_out, have_local ? local_hw : NULL) == 0)
        return 0;

    return -1;
}

static int mac_load_from_kernel(struct app_config *cfg, uint64_t *out_n) {
    uint8_t macs[MAX_INTERFACES][MAC_LEN];

    fprintf(stderr, "[LOCAL-MAC] hardware MAC of local interfaces (ioctl):\n");
    for (int li = 0; li < cfg->local_count; li++) {
        uint8_t hw[MAC_LEN];
        if (read_local_iface_hwaddr(cfg->locals[li].ifname, hw, NULL) == 0) {
            fprintf(stderr,
                    "  %s %02x:%02x:%02x:%02x:%02x:%02x\n",
                    cfg->locals[li].ifname,
                    hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
        } else {
            fprintf(stderr, "  %s (SIOCGIFHWADDR failed)\n", cfg->locals[li].ifname);
        }
    }

    int n_ok = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        memset(macs[i], 0, MAC_LEN);
        if (peer_mac_from_kernel(cfg->locals[i].ifname, macs[i]) != 0) {
            fprintf(stderr,
                    "[LOCAL-MAC] %s peer not resolved yet (will learn from RX when link has traffic)\n",
                    cfg->locals[i].ifname);
            continue;
        }
        n_ok++;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        if (!mac_is_zero(macs[i])) {
            local_mac_learn(i, macs[i]);
            memcpy(cfg->locals[i].dst_mac, macs[i], MAC_LEN);
        }
        local_mac_log_iface_and_peer(cfg->locals[i].ifname, macs[i], cfg->locals[i].src_mac);
    }

    *out_n = (uint64_t)n_ok;
    return 0;
}

static int mac_load_from_preload_script(struct app_config *cfg, uint64_t *out_n) {
    const char *cmd = getenv("NE_LOCAL_MAC_PRELOAD");
    if (!cmd || !cmd[0])
        return -1;

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD: popen failed (%s)\n", cmd);
        return -1;
    }

    uint8_t covered[MAX_INTERFACES];
    memset(covered, 0, sizeof(covered));
    uint64_t nlines = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#' || *p == '\r')
            continue;

        char mac_tok[48];
        char if_tok[64];
        if (sscanf(p, "%47s %63s", mac_tok, if_tok) != 2) {
            fprintf(stderr,
                    "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD: bad line (need \"MAC ifname|index\"): %s\n",
                    line);
            pclose(fp);
            return -1;
        }

        uint8_t macb[MAC_LEN];
        if (parse_mac(mac_tok, macb) != 0) {
            fprintf(stderr, "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD: invalid MAC \"%s\"\n", mac_tok);
            pclose(fp);
            return -1;
        }
        if (mac_is_zero(macb) || mac_is_broadcast(macb) || mac_is_multicast(macb)) {
            fprintf(stderr, "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD: MAC must be unicast \"%s\"\n", mac_tok);
            pclose(fp);
            return -1;
        }

        int li = local_idx_by_ifname_cfg(cfg, if_tok);
        if (li < 0) {
            char *endp = NULL;
            long idx = strtol(if_tok, &endp, 10);
            if (!endp || *endp != '\0' || idx < 0 || idx >= cfg->local_count) {
                fprintf(stderr,
                        "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD: unknown local \"%s\" (use ifname or 0..n-1)\n",
                        if_tok);
                pclose(fp);
                return -1;
            }
            li = (int)idx;
        }

        local_mac_learn(li, macb);
        memcpy(cfg->locals[li].dst_mac, macb, MAC_LEN);
        local_mac_log_iface_and_peer(cfg->locals[li].ifname, macb, cfg->locals[li].src_mac);
        covered[li] = 1;
        nlines++;
    }

    int st = pclose(fp);
    if (st == -1 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr,
                "[FATAL][LOCAL-MAC] NE_LOCAL_MAC_PRELOAD command failed (status=%d).\n",
                st);
        return -1;
    }

    *out_n = nlines;
    return 0;
}

static int g_local_peer_macs_ready;
static uint64_t g_peer_mac_seed_count;

int forwarder_prepare_local_peer_macs(struct app_config *cfg) {
    if (!cfg || cfg->local_count <= 0)
        return 0;
    if (g_local_peer_macs_ready)
        return 0;

    local_mac_table_clear();
    uint64_t cnt = 0;

    unsigned wait_sec = 0;
    const char *wenv = getenv("NE_PEER_MAC_WAIT_SEC");
    if (wenv && wenv[0])
        wait_sec = (unsigned)strtoul(wenv, NULL, 10);
    time_t deadline = time(NULL) + (time_t)wait_sec;

    for (;;) {
        mac_load_from_kernel(cfg, &cnt);
        if (cnt >= (uint64_t)cfg->local_count)
            goto done;
        if (wait_sec == 0 || time(NULL) >= deadline)
            break;
        fprintf(stderr,
                "[LOCAL-MAC] partial peer MAC; sleep 1s (NE_PEER_MAC_WAIT_SEC=%u)\n",
                wait_sec);
        sleep(1);
    }

    if (getenv("NE_LOCAL_MAC_PRELOAD") && getenv("NE_LOCAL_MAC_PRELOAD")[0]) {
        if (mac_load_from_preload_script(cfg, &cnt) != 0)
            return -1;
    }

done:
    {
    uint64_t nz = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        if (!mac_is_zero(cfg->locals[i].dst_mac))
            nz++;
    }
    g_peer_mac_seed_count = nz;
    g_local_peer_macs_ready = 1;
    return 0;
    }
}

static int install_local_mac_table(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return -1;
    if (forwarder_prepare_local_peer_macs(fwd->cfg) != 0)
        return -1;
    fwd->local_mac_preload_loaded = g_peer_mac_seed_count;
    return 0;
}

struct packet_job {
    struct forwarder *fwd;
    int local_idx;
    int queue_idx;
    int tx_queue_base;
    void *pkt_ptr;
    uint32_t pkt_len;
    uint64_t addr;
};

struct worker_ring {
    struct packet_job jobs[WORKER_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    pthread_mutex_t lock;
} __attribute__((aligned(64)));

static struct worker_ring g_worker_ring;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int tx_queue_base;
    int wan_worker_index;
};

/*
 * Inbound WAN decrypt: pick AES ctx from policy id bytes inside the ciphertext
 * (see decrypt_packet_auto_l2 / crypto_l3_extract_policy_id / crypto_l4_*), not
 * from cleartext IP direction. Return-path IP swap does not change that id.
 * Outbound encrypt policy match already tries both tuple orders in config_select_crypto_policy().
 *
 * WAN L2 ciphertext must use crypto_layer2_decrypt(), not packet_decrypt(): the latter
 * follows g_encrypt_layer (often 3 from DB) and crypto_layer3_decrypt no-ops on non-0x0800
 * frames, leaving 0x88xx on wire and then injecting garbage toward LAN/firewall.
 */
static int ne_rx_ipv4_header_csum_ok(const uint8_t *ip, int ihl) {
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) {
        uint16_t w = ((uint16_t)ip[i] << 8);
        if (i + 1 < ihl)
            w |= ip[i + 1];
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ((uint16_t)sum) == 0xffff;
}

/* After WAN decrypt, ensure Ethernet II IPv4 (0x0800) before AF_XDP inject to LAN
 * so bridges/firewalls see standard frames. Belt-and-suspenders if L2 decrypt ran
 * but ethertype was left non-0800. */
static void ne_wan_rx_normalize_eth_ipv4_before_local_inject(uint8_t *pkt, uint32_t pkt_len) {
    if (!pkt || pkt_len < 14 + 20)
        return;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800)
        return;
    if (et == 0x8100)
        return;

    const uint8_t *iph = pkt + 14;
    if ((iph[0] >> 4) != 4)
        return;
    int ihl = (iph[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > 60 || pkt_len < 14 + (uint32_t)ihl)
        return;
    uint16_t tot = ((uint16_t)iph[2] << 8) | iph[3];
    if (tot < (uint16_t)ihl || pkt_len < 14 + (uint32_t)tot)
        return;
    if (!ne_rx_ipv4_header_csum_ok(iph, ihl))
        return;

    uint16_t fake4 = packet_crypto_get_fake_ethertype_ipv4();
    if (fake4 == 0)
        fake4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
    int ne_wireish = (pkt[12] == (uint8_t)(fake4 >> 8)) ? 1 : 0;

    if (!ne_wireish)
        return;

    pkt[12] = 0x08;
    pkt[13] = 0x00;
}

static int decrypt_packet_auto_l2(struct forwarder *fwd,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;


    uint8_t pkt_marker = pkt[12];
    uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    if (fake_ipv4 == 0)
        fake_ipv4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
    if (pkt_marker != (uint8_t)(fake_ipv4 >> 8)) {
        /* 0x88xx = NE L2-on-wire; never forward undecrypted (L3 thread no-op was leaking ciphertext). */
        if (pkt_marker == 0x88U)
            return -1;
        return 0;
    }

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        int new_len = crypto_layer2_decrypt(&crypto_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }


    uint32_t policy_wire = 0;
    if (*pkt_len < 17U)
        return -1;
    policy_wire = ((uint32_t)pkt[13] << 24) | ((uint32_t)pkt[14] << 16) | ((uint32_t)pkt[15] << 8) |
                   (uint32_t)pkt[16];
    int pi = fwd_pi_for_action_wire(fwd, POLICY_ACTION_ENCRYPT_L2, policy_wire);
    if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        apply_crypto_params_from_policy(cp);
        int new_len = crypto_layer2_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
        if (new_len < 0)
            return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    if (prev_policy_grace_active()) {
        int ppi = fwd_prev_pi_for_action_wire(POLICY_ACTION_ENCRYPT_L2, policy_wire);
        if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
            const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
            apply_crypto_params_from_policy(cp_prev);
            int new_len = crypto_layer2_decrypt(&g_prev_policy_crypto_ctx[ppi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }
    }


    return -1;
}


static int l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len,
                                uint32_t *policy_id_out) {
    if (!pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;


    return crypto_l3_extract_policy_id(pkt, pkt_len, policy_id_out);
}

static int decrypt_packet_auto_by_action(struct forwarder *fwd,
                                           uint8_t *pkt, uint32_t *pkt_len,
                                           int action_layer,
                                           uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;

    struct crypto_dispatch_ctx dctx = {
        .base_ctx = &crypto_ctx,
        .per_policy_ctx = g_policy_crypto_ctx,
        .per_policy_ready = g_policy_crypto_ctx_ready,
        .policies = fwd->cfg ? fwd->cfg->policies : NULL,
        .policy_count = fwd->cfg ? fwd->cfg->policy_count : 0,
        .prev_per_policy_ctx = g_prev_policy_crypto_ctx,
        .prev_per_policy_ready = g_prev_policy_crypto_ctx_ready,
        .prev_policies = g_prev_policies,
        .prev_policy_count = g_prev_policy_count,
        .prev_grace_active = prev_policy_grace_active()
    };
    return crypto_decrypt_packet_auto_by_action(crypto_enabled, fwd->cfg, &dctx,
                                                action_layer, pkt, pkt_len,
                                                scratch, scratch_sz);
}

/*
 * wan_queue_thread_l2 only strips outer L2 NE + L2 reasm. Any inner NE L3/L4 must still
 * go through crypto_decrypt_packet_auto_by_action: that path reads on-wire policy_id from
 * the L3/L4 tunnel header, maps it to the DB policy row, then apply_crypto_params_from_policy
 * (mode, nonce size, AES bits) before crypto_layer3_decrypt / crypto_layer4_decrypt — same
 * as wan_queue_thread_l3l4, not ad-hoc key guessing.
 *
 * For cleartext TCP/UDP after L2, those calls no-op (success, unchanged packet).
 */
static int wan_rx_inner_ne_after_outer_l2(struct forwarder *fwd,
                                          uint8_t *pkt, uint32_t *pkt_len,
                                          uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return 0;
    if (*pkt_len < (uint32_t)(ETH_HEADER_SIZE + 20))
        return 0;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et != 0x0800)
        return 0;

    if (decrypt_packet_auto_by_action(fwd, pkt, pkt_len, POLICY_ACTION_ENCRYPT_L3,
                                      scratch, scratch_sz) != 0)
        return -1;
    if (decrypt_packet_auto_by_action(fwd, pkt, pkt_len, POLICY_ACTION_ENCRYPT_L4,
                                      scratch, scratch_sz) != 0)
        return -1;
    return 0;
}

static struct packet_crypto_ctx *forwarder_resolve_l3_decrypt_ctx(struct forwarder *fwd,
                                                                   uint8_t *pkt,
                                                                   uint32_t pkt_len) {
    packet_crypto_set_l3_restore_ipproto_from_db(0);
    if (!fwd || !fwd->cfg)
        return NULL;

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        return &crypto_ctx;
    }

    uint32_t policy_id = 0;
    if (crypto_l3_extract_policy_id(pkt, pkt_len, &policy_id) != 0)
        return NULL;

    int pi = fwd_pi_for_action_wire(fwd, POLICY_ACTION_ENCRYPT_L3, policy_id);
    if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        apply_crypto_params_from_policy(cp);
        if (cp->protocol == 6 || cp->protocol == 17)
            packet_crypto_set_l3_restore_ipproto_from_db((uint8_t)cp->protocol);
        return &g_policy_crypto_ctx[pi];
    }
    if (prev_policy_grace_active()) {
        int ppi = fwd_prev_pi_for_action_wire(POLICY_ACTION_ENCRYPT_L3, policy_id);
        if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
            const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
            apply_crypto_params_from_policy(cp_prev);
            if (cp_prev->protocol == 6 || cp_prev->protocol == 17)
                packet_crypto_set_l3_restore_ipproto_from_db((uint8_t)cp_prev->protocol);
            return &g_prev_policy_crypto_ctx[ppi];
        }
    }
    return NULL;
}

static struct packet_crypto_ctx *forwarder_resolve_l4_decrypt_ctx(struct forwarder *fwd,
                                                                   uint8_t *pkt,
                                                                   uint32_t pkt_len) {
    if (!fwd || !fwd->cfg)
        return NULL;

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        return &crypto_ctx;
    }

    uint32_t policy_id = 0;
    int nonce_size = 0;
    if (crypto_l4_extract_policy_id_ipv4(pkt, pkt_len, &policy_id, &nonce_size) != 0)
        return NULL;

    int pi = fwd_pi_for_action_wire(fwd, POLICY_ACTION_ENCRYPT_L4, policy_id);
    if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (cp->nonce_size > 0 && cp->nonce_size == nonce_size) {
            apply_crypto_params_from_policy(cp);
            return &g_policy_crypto_ctx[pi];
        }
    }
    if (prev_policy_grace_active()) {
        int ppi = fwd_prev_pi_for_action_wire(POLICY_ACTION_ENCRYPT_L4, policy_id);
        if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
            const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
            if (cp_prev->nonce_size > 0 && cp_prev->nonce_size == nonce_size) {
                apply_crypto_params_from_policy(cp_prev);
                return &g_prev_policy_crypto_ctx[ppi];
            }
        }
    }
    return NULL;
}


static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol) {
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;

    uint16_t frag_word = ntohs(ip->frag_off);
    if (frag_word & (uint16_t)(IP_MF | IP_OFFMASK)) {
        *src_port = ntohs(ip->id);
        *dst_port = 0;
        return 0;
    }

    uint8_t *transport = pkt + l3_off + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct tcphdr)))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct udphdr)))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}

#define NE_WAN_NONIP_DIST_PROTO 253

static uint32_t pkt_l2_sig(const uint8_t *p, uint32_t len) {
    uint32_t h = 2166136261u ^ len;
    uint32_t cap = len < 192u ? len : 192u;
    for (uint32_t i = 0; i < cap; i++)
        h = h * 16777619u ^ p[i];
    return h;
}

static int select_wan_idx_nonip_flow(struct forwarder *fwd, int local_idx, const void *pkt,
                                     uint32_t pkt_len) {
    uint32_t h = pkt ? pkt_l2_sig((const uint8_t *)pkt, pkt_len) : 0;
    uint16_t sp = (uint16_t)h;
    uint16_t dp = (uint16_t)(h >> 16);
    return select_wan_idx_for_packet(fwd, local_idx, htonl(0xc0000201u), htonl(0xc0000202u), sp, dp,
                                       NE_WAN_NONIP_DIST_PROTO, pkt_len);
}

static inline uint32_t flow_hash_local_tq(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t src_port, uint16_t dst_port,
                                          uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

static void *gc_thread(void *arg) {
    (void)arg;
    forwarder_pin_cpu();
    while (running) {
        sleep(60); 
        flow_table_gc(&g_flow_table);
        tcp_policy_pin_gc();
        frag_table_gc(&g_wan_frag_l2);
        frag_table_gc(&g_wan_frag_l3);
        frag_table_gc(&g_wan_frag_l4);
    }
    return NULL;
}



static void *local_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    forwarder_pin_cpu();
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            learn_local_src_mac(fwd, local_idx, (const uint8_t *)pkt_ptrs[i], pkt_lens[i]);
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint8_t protocol = 0;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd, local_idx,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = select_wan_idx_nonip_flow(fwd, local_idx, pkt_ptrs[i], pkt_lens[i]);
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (interface_send_batch_queue(wan, tq, pkt, pkt_lens[i]) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *wan_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    forwarder_pin_cpu();
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];

            int local_idx = local_idx_from_dst_mac(fwd, pkt, pkt_len);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            ne_wan_rx_normalize_eth_ipv4_before_local_inject(pkt, pkt_len);
            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used_queues[l]) {
                for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++) {
                    if (local_used_queues[l] & (1u << q))
                        interface_send_flush_queue(&fwd->locals[l], q);
                }
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *local_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    forwarder_pin_cpu();
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            learn_local_src_mac(fwd, local_idx, (const uint8_t *)pkt_ptrs[i], pkt_lens[i]);
            uint32_t src_ip = 0, dst_ip = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint8_t protocol = 0;
            int flow_ok = 0;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                flow_ok = 1;
                wan_idx = select_wan_idx_for_packet(fwd, local_idx,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = select_wan_idx_nonip_flow(fwd, local_idx, pkt_ptrs[i], pkt_lens[i]);
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];

            uint32_t pkt_len = pkt_lens[i];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            const struct crypto_policy *cp = NULL;
            if (flow_ok) {
                cp = select_crypto_policy_for_packet(fwd, local_idx,
                                                     src_ip, dst_ip,
                                                     src_port, dst_port,
                                                     protocol);
            }
            struct packet_crypto_ctx *use_ctx = &crypto_ctx;
            int bypass_crypto = 0;
            int drop_unmatched = 0;

            if (cp) {
                if (cp->action == POLICY_ACTION_BYPASS) {
                    bypass_crypto = 1;
                } else if (cp->action != POLICY_ACTION_ENCRYPT_L2) {

                    bypass_crypto = 1;
                } else {
                    int pi = (int)(cp - fwd->cfg->policies);
                    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                        use_ctx = &g_policy_crypto_ctx[pi];
                    } else {
                        bypass_crypto = 1;
                    }
                    if (!bypass_crypto)
                        apply_crypto_params_from_policy(cp);
                }
            } else {
#if CRYPTO_POLICY_PASS_UNMATCHED
                drop_unmatched = 0;
#else
                drop_unmatched = (flow_ok && fwd->cfg && fwd->cfg->policy_count > 0) ? 1 : 0;
#endif
                bypass_crypto = !drop_unmatched;
            }

            if (drop_unmatched) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (bypass_crypto) {
                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    ne_tx_class_log("TX_BYPASS_WAN_SEND_FAIL", "LOCAL_L2_THREAD", "bypass_wan_send_reject",
                                    local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                    protocol, pkt_len, "interface_send_batch_queue bypass");
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                continue;
            }

            int split_done = 0;
            if (cp && cp->action == POLICY_ACTION_ENCRYPT_L2 && frag_need_split_l2(pkt_len)) {
                uint8_t f1[4096], f2[4096];
                uint32_t l1, l2;
                if (frag_split_and_encrypt_l2(use_ctx, pkt, pkt_len, f1, &l1, f2, &l2) == 0) {
                    split_done = 1;
                    if (interface_send_batch_queue(wan, tq, f1, l1) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_L2_WAN_SEND_FAIL", "LOCAL_L2_THREAD", "wan_batch_queue_reject_part1",
                                        local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l1, "frag1");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                    if (interface_send_batch_queue(wan, tq, f2, l2) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_L2_WAN_SEND_FAIL", "LOCAL_L2_THREAD", "wan_batch_queue_reject_part2",
                                        local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l2, "frag2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    ne_tx_class_log("TX_L2_SPLIT_ENCRYPT_FAIL", "LOCAL_L2_THREAD", "L2_split_encrypt_failed",
                                    local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                    protocol, pkt_len, "frag_split_and_encrypt_l2");
                    continue;
                }
            }

            if (!split_done) {
                if (encrypt_packet_with_ctx(use_ctx, pkt_ptrs[i], &pkt_len) != 0) {
                    ne_tx_class_log("TX_L2_ENCRYPT_FAIL", "LOCAL_L2_THREAD", "L2_encrypt_packet_with_ctx_failed",
                                    local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                    protocol, pkt_lens[i], "encrypt_packet_with_ctx");
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    ne_tx_class_log("TX_L2_WAN_SEND_FAIL", "LOCAL_L2_THREAD", "wan_batch_queue_reject",
                                    local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                    protocol, pkt_len, "interface_send_batch_queue");
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
        packet_critical_leave();
    }

    return NULL;
}

static void *local_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    forwarder_pin_cpu();
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();


        for (int i = 0; i < rcvd; i++) {
            learn_local_src_mac(fwd, local_idx, (const uint8_t *)pkt_ptrs[i], pkt_lens[i]);
            struct packet_job job;
            job.fwd = fwd;
            job.local_idx = local_idx;
            job.queue_idx = queue_idx;
            job.tx_queue_base = tx_base;
            job.pkt_ptr = pkt_ptrs[i];
            job.pkt_len = pkt_lens[i];
            job.addr = addrs[i];

            struct worker_ring *ring = &g_worker_ring;

            int enqueued = 0;
            pthread_mutex_lock(&ring->lock);
            uint32_t next_tail = (ring->tail + 1) % WORKER_RING_SIZE;
            if (next_tail != ring->head) {
                ring->jobs[ring->tail] = job;
                ring->tail = next_tail;
                enqueued = 1;
            }
            pthread_mutex_unlock(&ring->lock);

            if (!enqueued) {
                uint32_t sip = 0, dip = 0;
                uint16_t sp = 0, dp = 0;
                uint8_t pr = 0;
                int pfo = (parse_flow(pkt_ptrs[i], pkt_lens[i], &sip, &dip, &sp, &dp, &pr) == 0);
                const char *lif = (local_idx >= 0 && local_idx < fwd->local_count)
                                      ? fwd->locals[local_idx].ifname
                                      : "?";
                ne_tx_class_log("TX_WORKER_RING_FULL", "LOCAL_L3L4_THREAD", "g_worker_ring_saturated", local_idx,
                                lif, -1, pfo, sip, sp, dip, dp, pr, pkt_lens[i],
                                "WORKER_RING_SIZE see NE-HYP H05");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(local, queue_idx, &addrs[i], 1);
            }
        }
        packet_critical_leave();
    }

    return NULL;
}



static void *wan_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    forwarder_pin_cpu();
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        frag_table_gc(&g_wan_frag_l2);

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            {
                uint32_t sip = 0, dip = 0;
                uint16_t sp = 0, dp = 0;
                uint8_t pr = 0;
                int wf = (parse_flow(pkt, pkt_len, &sip, &dip, &sp, &dp, &pr) == 0);
                ne_rx_pkt_recv_log(wan, wan_idx, pkt, pkt_len, wf, sip, sp, dip, dp, pr);
            }


            if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                        decrypt_scratch, sizeof(decrypt_scratch)) != 0) {
                uint32_t sip = 0, dip = 0;
                uint16_t sp = 0, dp = 0;
                uint8_t pr = 0;
                int wf = (parse_flow(pkt, pkt_lens[i], &sip, &dip, &sp, &dp, &pr) == 0);
                ne_rx_class_log("RX_L2_WAN_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L2_WAN",
                                "L2_decrypt_fail_on_WAN", pkt_lens[i], wf, sip, sp, dip, dp, pr,
                                "decrypt_packet_auto_l2");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            {
                uint16_t fpid;
                uint8_t fidx;
                if (frag_is_fragment_l2(pkt, pkt_len, &fpid, &fidx)) {
                    uint8_t reass_buf[4096];
                    uint32_t reass_len = 0;
                    int rr = frag_try_reassemble_l2(&g_wan_frag_l2, pkt, pkt_len, fpid, fidx,
                                                    reass_buf, &reass_len);
                    if (rr == 0) {
                        continue;
                    }
                    if (rr != 1) {
                        char detail[80];
                        snprintf(detail, sizeof(detail), "L2_frag opid=%u idx=%u rr=%d", fpid, fidx, rr);
                        uint32_t sip = 0, dip = 0;
                        uint16_t sp = 0, dp = 0;
                        uint8_t pr = 0;
                        int wf = (parse_flow(pkt, pkt_len, &sip, &dip, &sp, &dp, &pr) == 0);
                        ne_rx_class_log("RX_L2_REASSEMBLE_FAIL", wan->ifname, wan_idx, "RX_L2_FRAG",
                                        "L2_reassemble_fail", pkt_len, wf, sip, sp, dip, dp, pr, detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    memcpy(pkt, reass_buf, reass_len);
                    pkt_len = reass_len;
                }
            }

            if (wan_rx_inner_ne_after_outer_l2(fwd, pkt, &pkt_len, decrypt_scratch,
                                               sizeof(decrypt_scratch)) != 0) {
                uint32_t sip = 0, dip = 0;
                uint16_t sp = 0, dp = 0;
                uint8_t pr = 0;
                int wf = (parse_flow(pkt, pkt_len, &sip, &dip, &sp, &dp, &pr) == 0);
                ne_rx_class_log("RX_L2_WAN_INNER_NE_FAIL", wan->ifname, wan_idx, "RX_L2_WAN",
                                "inner_L3_or_L4_decrypt_fail_after_L2", pkt_len, wf, sip, sp, dip, dp, pr,
                                "wan_rx_inner_ne_after_outer_l2");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            final_pkt = pkt;
            final_len = pkt_len;


            int local_idx = local_idx_from_dst_mac(fwd, final_pkt, final_len);
            if (local_idx < 0) {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                int pf = (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0);
                if (pf && tcp_diag_want_log(fp, fsp, fdp)) {
                    fprintf(stderr, "[TCP-DIAG][DROP-NO-LOCAL] dst_mac=%02x:%02x:%02x:%02x:%02x:%02x flow=%u:%u -> %u:%u len=%u\n",
                            final_pkt[0], final_pkt[1], final_pkt[2],
                            final_pkt[3], final_pkt[4], final_pkt[5],
                            ntohl(fs), (unsigned)fsp, ntohl(fd), (unsigned)fdp, (unsigned)final_len);
                }
                ne_rx_class_log("RX_DST_MAC_NO_LOCAL", wan->ifname, wan_idx, "TO_LOCAL",
                                "dst_mac_unknown_bridge", final_len, pf, fs, fsp, fd, fdp, fp,
                                "L2_only_WAN_RX_path");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            ne_wan_rx_normalize_eth_ipv4_before_local_inject(final_pkt, final_len);
            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                int pf = (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0);
                if (pf && tcp_diag_want_log(fp, fsp, fdp)) {
                    fprintf(stderr, "[TCP-DIAG][DROP-LOCAL-TX] local=%s q=%d flow=%u:%u -> %u:%u len=%u\n",
                            local_iface->ifname, tq,
                            ntohl(fs), (unsigned)fsp, ntohl(fd), (unsigned)fdp, (unsigned)final_len);
                }
                ne_rx_class_log("RX_LOCAL_INJECT_BATCH_FAIL", wan->ifname, wan_idx, "TO_LOCAL",
                                "af_xdp_local_queue_reject", final_len, pf, fs, fsp, fd, fdp, fp,
                                "L2_only_WAN_RX_path");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();

    }
    return NULL;
}



static void *wan_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    forwarder_pin_cpu();
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;
        packet_critical_enter();

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        frag_table_gc(&g_wan_frag_l3);
        frag_table_gc(&g_wan_frag_l4);

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *wire_pkt = pkt;
            uint32_t wire_len = pkt_len;
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;
            int inbound_policy_pi = -1;
            uint32_t wire_src_ip = 0, wire_dst_ip = 0;
            uint16_t wire_src_port = 0, wire_dst_port = 0;
            uint8_t wire_proto = 0;
            int wire_flow_ok = (parse_flow(wire_pkt, wire_len,
                                           &wire_src_ip, &wire_dst_ip,
                                           &wire_src_port, &wire_dst_port,
                                           &wire_proto) == 0);
            ne_rx_pkt_recv_log(wan, wan_idx, pkt, wire_len, wire_flow_ok,
                               wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto);
            if (wire_flow_ok && tcp_diag_want_log(wire_proto, wire_src_port, wire_dst_port)) {
                uint32_t l3pid = 0, l4pid = 0;
                int l4nonce = 0;
                int l3ok = (crypto_l3_extract_policy_id(wire_pkt, wire_len, &l3pid) == 0);
                int l4ok = (crypto_l4_extract_policy_id_ipv4(wire_pkt, wire_len, &l4pid, &l4nonce) == 0);
                log_tcp_diag_decrypt("RX-WIRE",
                                     wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port,
                                     POLICY_ACTION_ENCRYPT_L4,
                                     l3ok, l3ok ? (int)l3pid : -1,
                                     l4ok, l4ok ? (int)l4pid : -1, l4nonce,
                                     0);
            }

            (void)0;

            if (crypto_enabled && crypto_layer == POLICY_ACTION_ENCRYPT_L3 &&
                fwd->cfg && fwd->cfg->policy_count > 0) {
                uint16_t et_prime = ((uint16_t)pkt[12] << 8) | pkt[13];
                /* L2-on-WAN uses 0x88xx; l3_extract needs IPv4 — skip priming until after L2 strip. */
                if (et_prime == 0x0800) {
                    uint32_t policy_id = 0;
                    int found = 0;
                    if (l3_extract_policy_id(pkt, pkt_len, &policy_id) == 0) {
                        int pi = fwd_pi_for_action_wire(fwd, POLICY_ACTION_ENCRYPT_L3, policy_id);
                        if (pi >= 0 && pi < fwd->cfg->policy_count && g_policy_crypto_ctx_ready[pi]) {
                            const struct crypto_policy *cp = &fwd->cfg->policies[pi];
                            apply_crypto_params_from_policy(cp);
                            found = 1;
                        }
                        if (!found && prev_policy_grace_active()) {
                            int ppi = fwd_prev_pi_for_action_wire(POLICY_ACTION_ENCRYPT_L3, policy_id);
                            if (ppi >= 0 && ppi < g_prev_policy_count && g_prev_policy_crypto_ctx_ready[ppi]) {
                                const struct crypto_policy *cp_prev = &g_prev_policies[ppi];
                                apply_crypto_params_from_policy(cp_prev);
                                found = 1;
                            }
                        }
                    }
                    if (!found)
                        apply_default_crypto_params(fwd);
                }
            }


            {
                uint8_t pkt_marker = pkt[12];
                uint16_t f4 = packet_crypto_get_fake_ethertype_ipv4();
                if (f4 == 0)
                    f4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
                int has_l2_marker = (pkt_marker == (uint8_t)(f4 >> 8));
                if (has_l2_marker) {
                    if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                               decrypt_scratch,
                                               sizeof(decrypt_scratch)) != 0) {
                        ne_rx_class_log("RX_L2_MARKER_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L2_MARKER",
                                        "L2_decrypt_fail_on_L3L4_thread", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        "decrypt_packet_auto_l2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                }
            }

            {
                uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
                if (et != 0x0800 && pkt_len >= 14U && pkt[12] == 0x88U) {
                    ne_rx_class_log("RX_WAN_NE_ETH_NOT_IPV4", wan->ifname, wan_idx, "RX_WAN_GIBBERISH",
                                    "eth_88xx_not_decrypted_to_0800", wire_len, wire_flow_ok,
                                    wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                    "block_forward_ciphertext");
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            }

            if (crypto_enabled) {
                uint16_t l3_frag_pid;
                uint8_t l3_frag_idx;
                if (frag_is_fragment(pkt, pkt_len, &l3_frag_pid, &l3_frag_idx)) {
                    uint32_t l3_pid = 0;
                    if (crypto_l3_extract_policy_id(pkt, pkt_len, &l3_pid) == 0) {
                        int pi = policy_index_from_action_id_current(fwd, POLICY_ACTION_ENCRYPT_L3, l3_pid);
                        if (pi >= 0)
                            inbound_policy_pi = pi;
                    }
                    struct packet_crypto_ctx *l3ctx = forwarder_resolve_l3_decrypt_ctx(fwd, pkt, pkt_len);
                    if (!l3ctx) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L3_frag opid=%u idx=%u no_decrypt_ctx", l3_frag_pid,
                                 l3_frag_idx);
                        ne_rx_class_log("RX_L3_FRAG_NO_DECRYPT_CTX", wan->ifname, wan_idx, "RX_L3_FRAG",
                                        "L3_frag_no_crypto_ctx_or_policy", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    uint16_t opid;
                    uint8_t ofidx;
                    int nd = frag_decrypt_fragment(l3ctx, pkt, pkt_len, &opid, &ofidx);
                    packet_crypto_set_l3_restore_ipproto_from_db(0);
                    if (nd < 0) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L3_frag opid=%u idx=%u frag_decrypt rc=%d", opid, ofidx,
                                 nd);
                        ne_rx_class_log("RX_L3_FRAG_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L3_FRAG",
                                        "L3_frag_decrypt_fail_key_or_corrupt", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    pkt_len = (uint32_t)nd;
                    uint8_t reass_buf[4096];
                    uint32_t reass_len = 0;
                    int rr = frag_try_reassemble(&g_wan_frag_l3, pkt, pkt_len, opid, ofidx,
                                                 reass_buf, &reass_len);
                    if (rr == 0) {
                        continue;
                    }
                    if (rr != 1) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L3_frag opid=%u idx=%u rr=%d", opid, ofidx, rr);
                        ne_rx_class_log("RX_L3_REASSEMBLE_FAIL", wan->ifname, wan_idx, "RX_L3_FRAG",
                                        "L3_reassemble_fail_fragment_state", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    memcpy(pkt, reass_buf, reass_len);
                    pkt_len = reass_len;
                } else if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                         POLICY_ACTION_ENCRYPT_L3,
                                                         decrypt_scratch,
                                                         sizeof(decrypt_scratch)) != 0) {
                    uint32_t ds = 0, dd = 0;
                    uint16_t dsp = 0, ddp = 0;
                    uint8_t dproto = 0;
                    int pfl3 = (parse_flow(wire_pkt, wire_len, &ds, &dd, &dsp, &ddp, &dproto) == 0);
                    ne_rx_class_log("RX_L3_FULL_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L3_FULL",
                                    "L3_full_decrypt_fail_key_or_corrupt", wire_len, pfl3, ds, dsp, dd, ddp, dproto,
                                    "decrypt_packet_auto_by_action enc_l3");
                    if (pfl3 && tcp_diag_want_log(dproto, dsp, ddp)) {
                        uint32_t l3pid = 0;
                        int l4nonce = 0;
                        uint32_t l4pid = 0;
                        int l3ok = (crypto_l3_extract_policy_id(wire_pkt, wire_len, &l3pid) == 0);
                        int l4ok = (crypto_l4_extract_policy_id_ipv4(wire_pkt, wire_len, &l4pid, &l4nonce) == 0);
                        log_tcp_diag_decrypt("RX-DEC-FAIL",
                                             ds, dsp, dd, ddp,
                                             POLICY_ACTION_ENCRYPT_L3,
                                             l3ok, l3ok ? (int)l3pid : -1,
                                             l4ok, l4ok ? (int)l4pid : -1, l4nonce,
                                             -1);
                    }
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                } else {
                    uint32_t l3_pid = 0;
                    if (crypto_l3_extract_policy_id(wire_pkt, wire_len, &l3_pid) == 0) {
                        int pi = policy_index_from_action_id_current(fwd, POLICY_ACTION_ENCRYPT_L3, l3_pid);
                        if (pi >= 0)
                            inbound_policy_pi = pi;
                    }
                }

                int wan_rx_cleartext_ssh = 0;
                {
                    uint32_t cx_sip, cx_dip;
                    uint16_t cx_sport, cx_dport;
                    uint8_t cx_proto;
                    if (parse_flow(pkt, pkt_len, &cx_sip, &cx_dip, &cx_sport, &cx_dport, &cx_proto) == 0 &&
                        tcp_diag_want_log(cx_proto, cx_sport, cx_dport))
                        wan_rx_cleartext_ssh = 1;
                }

                uint16_t l4_frag_pid;
                uint8_t l4_frag_idx;
                if (frag_is_fragment_l4(pkt, pkt_len, &l4_frag_pid, &l4_frag_idx)) {
                    struct packet_crypto_ctx *l4ctx = forwarder_resolve_l4_decrypt_ctx(fwd, pkt, pkt_len);
                    if (!l4ctx) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L4_frag opid=%u idx=%u no_decrypt_ctx", l4_frag_pid,
                                 l4_frag_idx);
                        ne_rx_class_log("RX_L4_FRAG_NO_DECRYPT_CTX", wan->ifname, wan_idx, "RX_L4_FRAG",
                                        "L4_frag_no_crypto_ctx_or_policy", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    uint16_t opid2;
                    uint8_t ofidx2;
                    int nd4 = frag_decrypt_fragment_l4(l4ctx, pkt, pkt_len, &opid2, &ofidx2);
                    if (nd4 < 0) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L4_frag opid=%u idx=%u frag_decrypt rc=%d", opid2,
                                 ofidx2, nd4);
                        ne_rx_class_log("RX_L4_FRAG_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L4_FRAG",
                                        "L4_frag_decrypt_fail_key_or_corrupt", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    pkt_len = (uint32_t)nd4;
                    uint8_t reass4[4096];
                    uint32_t reass4_len = 0;
                    int rr4 = frag_try_reassemble_l4(&g_wan_frag_l4, pkt, pkt_len, opid2, ofidx2,
                                                     reass4, &reass4_len);
                    if (rr4 == 0) {
                        continue;
                    }
                    if (rr4 != 1) {
                        char detail[96];
                        snprintf(detail, sizeof(detail), "L4_frag opid=%u idx=%u rr=%d", opid2, ofidx2, rr4);
                        ne_rx_class_log("RX_L4_REASSEMBLE_FAIL", wan->ifname, wan_idx, "RX_L4_FRAG",
                                        "L4_reassemble_fail_fragment_state", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        detail);
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                    memcpy(pkt, reass4, reass4_len);
                    pkt_len = reass4_len;
                } else if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                           POLICY_ACTION_ENCRYPT_L4,
                                                           decrypt_scratch,
                                                           sizeof(decrypt_scratch)) != 0) {
                    uint32_t ds = 0, dd = 0;
                    uint16_t dsp = 0, ddp = 0;
                    uint8_t dproto = 0;
                    int pfl4 = (parse_flow(wire_pkt, wire_len, &ds, &dd, &dsp, &ddp, &dproto) == 0);
                    ne_rx_class_log("RX_L4_FULL_DECRYPT_FAIL", wan->ifname, wan_idx, "RX_L4_FULL",
                                    "L4_full_decrypt_fail_key_or_corrupt", wire_len, pfl4, ds, dsp, dd, ddp, dproto,
                                    "decrypt_packet_auto_by_action enc_l4");
                    if (pfl4 && tcp_diag_want_log(dproto, dsp, ddp)) {
                        uint32_t l3pid = 0;
                        int l4nonce = 0;
                        uint32_t l4pid = 0;
                        int l3ok = (crypto_l3_extract_policy_id(wire_pkt, wire_len, &l3pid) == 0);
                        int l4ok = (crypto_l4_extract_policy_id_ipv4(wire_pkt, wire_len, &l4pid, &l4nonce) == 0);
                        log_tcp_diag_decrypt("RX-DEC-FAIL",
                                             ds, dsp, dd, ddp,
                                             POLICY_ACTION_ENCRYPT_L4,
                                             l3ok, l3ok ? (int)l3pid : -1,
                                             l4ok, l4ok ? (int)l4pid : -1, l4nonce,
                                             -1);
                    }
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                } else if ((wire_flow_ok && tcp_diag_want_log(wire_proto, wire_src_port, wire_dst_port)) ||
                           wan_rx_cleartext_ssh) {
                    uint32_t ps = 0, pd = 0;
                    uint16_t psp = 0, pdp = 0;
                    uint8_t pp = 0;
                    int post_ok = (parse_flow(pkt, pkt_len, &ps, &pd, &psp, &pdp, &pp) == 0);
                    log_tcp_diag_decrypt_len("RX-DEC-OK",
                                             wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port,
                                             wire_len, pkt_len,
                                             post_ok, post_ok ? pp : 0,
                                             post_ok ? psp : 0, post_ok ? pdp : 0);
                    if (g_tcp_diag_enabled &&
                        is_ssh_flow(wire_proto, wire_src_port, wire_dst_port)) {
                        uint8_t tf = 0;
                        char fg[64];
                        if (tcp_ipv4_tcp_flags(pkt, pkt_len, &tf) == 0)
                            tcp_diag_flags_fmt(tf, fg, sizeof(fg));
                        else
                            snprintf(fg, sizeof(fg), "unk");
                        fprintf(stderr,
                                "[TCP-DIAG][SSH-RX-DEC] post_dec tcp=[%s] cleartext_len=%u\n",
                                fg, (unsigned)pkt_len);
                    }
                    if (!post_ok) {
                        ne_rx_class_log("RX_POST_DECRYPT_PARSE_FAIL", wan->ifname, wan_idx, "POST_DECRYPT",
                                        "cleartext_parse_fail_NE_output_corrupt", wire_len, wire_flow_ok,
                                        wire_src_ip, wire_src_port, wire_dst_ip, wire_dst_port, wire_proto,
                                        "parse_flow failed after decrypt");
                    } else if (!ne_rx_ipv4_frame_plausible(pkt, pkt_len)) {
                        ne_rx_class_log("RX_POST_DECRYPT_IPV4_SHAPE_BAD", wan->ifname, wan_idx, "POST_DECRYPT",
                                        "cleartext_IPv4_length_inconsistent", wire_len, 1,
                                        ps, psp, pd, pdp, pp,
                                        "totlen/ihl/tcp vs buffer after decrypt");
                    }
                } else if (inbound_policy_pi < 0) {
                    uint32_t l4_pid = 0;
                    int l4_nonce = 0;
                    if (crypto_l4_extract_policy_id_ipv4(wire_pkt, wire_len, &l4_pid, &l4_nonce) == 0) {
                        int pi = policy_index_from_action_id_current(fwd, POLICY_ACTION_ENCRYPT_L4, l4_pid);
                        if (pi >= 0)
                            inbound_policy_pi = pi;
                    }
                }
            }

            final_pkt = pkt;
            final_len = pkt_len;
            {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                if (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0 &&
                    tcp_diag_want_log(fp, fsp, fdp)) {
                    log_tcp_diag_decrypt("RX-TO-LOCAL",
                                         fs, fsp, fd, fdp,
                                         POLICY_ACTION_ENCRYPT_L4,
                                         0, -1, 0, -1, 0, 0);
                    if (!ne_rx_ipv4_frame_plausible((const uint8_t *)final_pkt, final_len)) {
                        ne_rx_class_log("RX_TO_LOCAL_IPV4_SHAPE_BAD", wan->ifname, wan_idx, "TO_LOCAL",
                                        "cleartext_IPv4_bad_before_inject", final_len, 1, fs, fsp, fd, fdp, fp,
                                        "frame not plausible before AF_XDP to local");
                    }
                    if (g_tcp_diag_enabled && fp == IPPROTO_TCP &&
                        is_ssh_flow(fp, fsp, fdp)) {
                        uint8_t tf = 0;
                        char fg[64];
                        if (tcp_ipv4_tcp_flags(final_pkt, final_len, &tf) == 0)
                            tcp_diag_flags_fmt(tf, fg, sizeof(fg));
                        else
                            snprintf(fg, sizeof(fg), "unk");
                        fprintf(stderr,
                                "[TCP-DIAG][SSH-RX-TO-LOCAL] tcp=[%s] len=%u\n",
                                fg, (unsigned)final_len);
                    }
                }
            }

            if (inbound_policy_pi >= 0) {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                if (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0 && fp == IPPROTO_TCP)
                    tcp_policy_pin_set(fs, fd, fsp, fdp, inbound_policy_pi);
            }


            int local_idx = local_idx_from_dst_mac(fwd, final_pkt, final_len);
            if (local_idx < 0) {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                int pf = (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0);
                if (pf && tcp_diag_want_log(fp, fsp, fdp)) {
                    fprintf(stderr, "[TCP-DIAG][DROP-NO-LOCAL] dst_mac=%02x:%02x:%02x:%02x:%02x:%02x flow=%u:%u -> %u:%u len=%u\n",
                            final_pkt[0], final_pkt[1], final_pkt[2],
                            final_pkt[3], final_pkt[4], final_pkt[5],
                            ntohl(fs), (unsigned)fsp, ntohl(fd), (unsigned)fdp, (unsigned)final_len);
                }
                ne_rx_class_log("RX_DST_MAC_NO_LOCAL", wan->ifname, wan_idx, "TO_LOCAL",
                                "dst_mac_unknown_bridge", final_len, pf, fs, fsp, fd, fdp, fp,
                                "L3L4_WAN_RX_path");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            ne_wan_rx_normalize_eth_ipv4_before_local_inject(final_pkt, final_len);
            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                uint32_t fs = 0, fd = 0;
                uint16_t fsp = 0, fdp = 0;
                uint8_t fp = 0;
                int pf = (parse_flow(final_pkt, final_len, &fs, &fd, &fsp, &fdp, &fp) == 0);
                if (pf && tcp_diag_want_log(fp, fsp, fdp)) {
                    fprintf(stderr, "[TCP-DIAG][DROP-LOCAL-TX] local=%s q=%d flow=%u:%u -> %u:%u len=%u\n",
                            local_iface->ifname, tq,
                            ntohl(fs), (unsigned)fsp, ntohl(fd), (unsigned)fdp, (unsigned)final_len);
                }
                ne_rx_class_log("RX_LOCAL_INJECT_BATCH_FAIL", wan->ifname, wan_idx, "TO_LOCAL",
                                "af_xdp_local_queue_reject", final_len, pf, fs, fsp, fd, fdp, fp,
                                "interface_send_to_local_batch_queue rejected");
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        packet_critical_leave();

    }
    return NULL;
}

static void *worker_thread(void *arg) {
    (void)arg;
    forwarder_pin_cpu();

    struct worker_ring *ring = &g_worker_ring;

    while (running) {
        struct packet_job job;
        int has_job = 0;

        pthread_mutex_lock(&ring->lock);
        if (ring->head != ring->tail) {
            job = ring->jobs[ring->head];
            ring->head = (ring->head + 1) % WORKER_RING_SIZE;
            has_job = 1;
        }
        pthread_mutex_unlock(&ring->lock);

        if (!has_job) {
            sched_yield();
            continue;
        }
        packet_critical_enter();

        struct forwarder *fwd = job.fwd;
        if (!fwd) {
            packet_critical_leave();
            continue;
        }

        uint32_t wan_tx_q[MAX_INTERFACES];
        int wan_used[MAX_INTERFACES] = {0};
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = job.tx_queue_base % fwd->wans[w].queue_count;

        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;

        int flow_ok = (parse_flow(job.pkt_ptr, job.pkt_len,
                                  &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0);
        uint8_t tcp_flags = 0;
        int tcp_flags_ok = 0;
        if (flow_ok && protocol == IPPROTO_TCP)
            tcp_flags_ok = (tcp_ipv4_tcp_flags(job.pkt_ptr, job.pkt_len, &tcp_flags) == 0);
        int profile_idx = -1;
        if (fwd->cfg && job.local_idx >= 0 && job.local_idx < fwd->cfg->local_count) {
            profile_idx = config_select_profile_for_local(fwd->cfg, job.local_idx);
            if (profile_idx >= 0 && profile_idx < MAX_PROFILES)
                __sync_fetch_and_add(&g_profile_hits[profile_idx], 1);
            else
                __sync_fetch_and_add(&g_profile_miss_hits, 1);
        }

        int wan_idx;
        if (flow_ok) {
            wan_idx = select_wan_idx_for_packet(fwd, job.local_idx,
                                                src_ip, dst_ip, src_port, dst_port,
                                                protocol, job.pkt_len);
        } else {
            wan_idx = select_wan_idx_nonip_flow(fwd, job.local_idx, job.pkt_ptr, job.pkt_len);
        }

        if (wan_idx < 0 || wan_idx >= fwd->wan_count) {
            wan_idx = 0;
        }

        uint64_t seq = __sync_add_and_fetch(&g_profile_log_seq, 1);
        if ((seq % 20000ULL) == 0 && fwd->cfg) {
            fprintf(stderr, "[PROFILE HIT] total=%llu miss=%llu",
                    (unsigned long long)seq,
                    (unsigned long long)g_profile_miss_hits);
            for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
                fprintf(stderr, " p%d(%s)=%llu",
                        pi, fwd->cfg->profiles[pi].name,
                        (unsigned long long)g_profile_hits[pi]);
            }
            fprintf(stderr, " last_sel=%d last_wan=%d\n", profile_idx, wan_idx);
        }

        struct xsk_interface *wan = &fwd->wans[wan_idx];
        int tq = wan_tx_q[wan_idx];

        uint32_t pkt_len = job.pkt_len;
        const uint32_t cleartext_len = job.pkt_len;

        if (g_tcp_diag_enabled && flow_ok && is_ssh_flow(protocol, src_port, dst_port)) {
            char fg[64];
            char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
            struct in_addr sa = { .s_addr = src_ip };
            struct in_addr da = { .s_addr = dst_ip };
            if (tcp_flags_ok)
                tcp_diag_flags_fmt(tcp_flags, fg, sizeof(fg));
            else
                snprintf(fg, sizeof(fg), "unk");
            inet_ntop(AF_INET, &sa, sip, sizeof(sip));
            inet_ntop(AF_INET, &da, dip, sizeof(dip));
            fprintf(stderr,
                    "[TCP-DIAG][SSH-TX-PRE] %s:%u -> %s:%u local_idx=%d wan=%d(%s) wan_q=%u len=%u tcp=[%s]\n",
                    sip, (unsigned)src_port, dip, (unsigned)dst_port,
                    job.local_idx, wan_idx, wan->ifname, (unsigned)tq,
                    (unsigned)cleartext_len, fg);
        }

        const struct crypto_policy *cp = NULL;
        struct packet_crypto_ctx *use_ctx = &crypto_ctx;
        int bypass_crypto = 0;
        if (crypto_enabled) {
            if (!flow_ok) {
                bypass_crypto = 1;
            } else {
                if (protocol == IPPROTO_TCP)
                    cp = tcp_policy_pin_lookup(fwd, src_ip, dst_ip, src_port, dst_port);
                if (!cp)
                    cp = select_crypto_policy_for_packet(fwd, job.local_idx,
                                                         src_ip, dst_ip,
                                                         src_port, dst_port,
                                                         protocol);
                if (cp) {
                    if (cp->action == POLICY_ACTION_BYPASS) {
                        bypass_crypto = 1;
                    } else {
                        int pi = (int)(cp - fwd->cfg->policies);
                        if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                            use_ctx = &g_policy_crypto_ctx[pi];
                        } else {
                            bypass_crypto = 1;
                        }
                        if (!bypass_crypto)
                            apply_crypto_params_from_policy(cp);
                    }
                } else {
#if !CRYPTO_POLICY_PASS_UNMATCHED
                    if (fwd->cfg && fwd->cfg->policy_count > 0) {
                        if (g_tcp_diag_enabled && flow_ok &&
                            is_ssh_flow(protocol, src_port, dst_port)) {
                            char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
                            struct in_addr sa = { .s_addr = src_ip };
                            struct in_addr da = { .s_addr = dst_ip };
                            inet_ntop(AF_INET, &sa, sip, sizeof(sip));
                            inet_ntop(AF_INET, &da, dip, sizeof(dip));
                            fprintf(stderr,
                                    "[TCP-DIAG][SSH-TX-DROP-NO-POLICY] %s:%u -> %s:%u len=%u (no cp, policy_count=%d)\n",
                                    sip, (unsigned)src_port, dip, (unsigned)dst_port,
                                    (unsigned)job.pkt_len, fwd->cfg->policy_count);
                        }
                        ne_tx_class_log("TX_NO_CRYPTO_POLICY_DROP", "WORKER_L3L4", "strict_mode_no_matching_policy",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                        protocol, job.pkt_len, "CRYPTO_POLICY_PASS_UNMATCHED=0");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        goto release_local;
                    }
#endif
                    bypass_crypto = 1;
                }
            }

            if (flow_ok && tcp_diag_want_log(protocol, src_port, dst_port)) {
                log_tcp_diag_policy_select("TX-SELECT",
                                           src_ip, src_port, dst_ip, dst_port,
                                           cp, bypass_crypto);
            }

            if (crypto_enabled && protocol == IPPROTO_TCP && flow_ok && cp) {
                int pin_pi = -1;
                int pi = (int)(cp - fwd->cfg->policies);
                if (pi >= 0 && pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES) {
                    if (cp->action == POLICY_ACTION_BYPASS)
                        pin_pi = pi;
                    else if (!bypass_crypto && g_policy_crypto_ctx_ready[pi])
                        pin_pi = pi;
                }
                if (pin_pi >= 0)
                    tcp_policy_pin_set(src_ip, dst_ip, src_port, dst_port, pin_pi);
            }

            if (bypass_crypto) {
                int send_rc = interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len);
                if (send_rc == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                    if (g_tcp_diag_enabled && flow_ok && is_ssh_flow(protocol, src_port, dst_port)) {
                        fprintf(stderr,
                                "[TCP-DIAG][SSH-TX-BYPASS-SENT] wan=%d(%s) len=%u\n",
                                wan_idx, wan->ifname, (unsigned)pkt_len);
                    }
                } else {
                    if (g_tcp_diag_enabled && flow_ok && is_ssh_flow(protocol, src_port, dst_port)) {
                        fprintf(stderr,
                                "[TCP-DIAG][SSH-TX-BYPASS-SEND-FAIL] wan=%d(%s) len=%u rc=%d\n",
                                wan_idx, wan->ifname, (unsigned)pkt_len, send_rc);
                    }
                    ne_tx_class_log("TX_BYPASS_WAN_SEND_FAIL", "WORKER_L3L4", "bypass_wan_batch_reject",
                                    job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port,
                                    protocol, pkt_len, "interface_send_batch_queue");
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                goto skip_encrypt_flush;
            }
        }

        if (!crypto_enabled) {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (interface_send_batch_queue(wan, tq, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        } else {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            int sent_split = 0;
            if (cp) {
                if (cp->action == POLICY_ACTION_ENCRYPT_L2 && frag_need_split_l2(pkt_len)) {
                    uint8_t f1[4096], f2[4096];
                    uint32_t l1, l2;
                    if (frag_split_and_encrypt_l2(use_ctx, pkt, pkt_len, f1, &l1, f2, &l2) != 0) {
                        ne_tx_class_log("TX_L2_SPLIT_ENCRYPT_FAIL", "WORKER_L3L4", "frag_split_encrypt_l2_failed",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, cleartext_len, "frag_split_and_encrypt_l2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        goto release_local;
                    }
                    sent_split = 1;
                    if (interface_send_batch_queue(wan, tq, f1, l1) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part1",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l1, "L2_split frag1");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                    if (interface_send_batch_queue(wan, tq, f2, l2) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part2",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l2, "L2_split frag2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L3 && frag_need_split(pkt_len)) {
                    uint8_t f1[4096], f2[4096];
                    uint32_t l1, l2;
                    if (frag_split_and_encrypt(use_ctx, pkt, pkt_len, f1, &l1, f2, &l2) != 0) {
                        ne_tx_class_log("TX_L3_SPLIT_ENCRYPT_FAIL", "WORKER_L3L4", "frag_split_encrypt_l3_failed",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, cleartext_len, "frag_split_and_encrypt");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        goto release_local;
                    }
                    sent_split = 1;
                    if (interface_send_batch_queue(wan, tq, f1, l1) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part1",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l1, "L3_split frag1");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                    if (interface_send_batch_queue(wan, tq, f2, l2) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part2",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l2, "L3_split frag2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L4 && frag_need_split_l4(pkt_len)) {
                    uint8_t f1[4096], f2[4096];
                    uint32_t l1, l2;
                    if (frag_split_and_encrypt_l4(use_ctx, pkt, pkt_len, f1, &l1, f2, &l2) != 0) {
                        ne_tx_class_log("TX_L4_SPLIT_ENCRYPT_FAIL", "WORKER_L3L4", "frag_split_encrypt_l4_failed",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, cleartext_len, "frag_split_and_encrypt_l4");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        goto release_local;
                    }
                    sent_split = 1;
                    if (interface_send_batch_queue(wan, tq, f1, l1) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part1",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l1, "L4_split frag1");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                    if (interface_send_batch_queue(wan, tq, f2, l2) == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_queue_reject_cipher_part2",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, l2, "L4_split frag2");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                }
            }

            if (!sent_split) {
                int new_len = -1;
                if (cp) {
                    if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
                        new_len = crypto_layer2_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                    } else if (cp->action == POLICY_ACTION_ENCRYPT_L3) {
                        new_len = crypto_layer3_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                    } else if (cp->action == POLICY_ACTION_ENCRYPT_L4) {
                        new_len = crypto_layer4_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                    }
                }

                if (new_len < 0) {
                    const char *txk = "TX_ENCRYPT_FAIL";
                    if (cp) {
                        if (cp->action == POLICY_ACTION_ENCRYPT_L2)
                            txk = "TX_L2_ENCRYPT_FAIL";
                        else if (cp->action == POLICY_ACTION_ENCRYPT_L3)
                            txk = "TX_L3_ENCRYPT_FAIL";
                        else if (cp->action == POLICY_ACTION_ENCRYPT_L4)
                            txk = "TX_L4_ENCRYPT_FAIL";
                    }
                    char dbuf[96];
                    snprintf(dbuf, sizeof(dbuf), "new_len=%d action=%s", new_len,
                             cp ? policy_action_name(cp->action) : "none");
                    ne_tx_class_log(txk, "WORKER_L3L4", "crypto_layer_encrypt_returned_neg", job.local_idx,
                                    wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip, dst_port, protocol,
                                    cleartext_len, dbuf);
                    if (g_tcp_diag_enabled && flow_ok && tcp_diag_want_log(protocol, src_port, dst_port)) {
                        fprintf(stderr,
                                "[TCP-DIAG][TX-ENC-FAIL] action=%s cleartext_len=%u new_len=%d\n",
                                cp ? policy_action_name(cp->action) : "none",
                                (unsigned)cleartext_len, new_len);
                    }
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    goto release_local;
                }
                pkt_len = (uint32_t)new_len;

                if (g_tcp_diag_enabled && flow_ok && is_ssh_flow(protocol, src_port, dst_port) && cp) {
                    char fg[64];
                    if (tcp_flags_ok)
                        tcp_diag_flags_fmt(tcp_flags, fg, sizeof(fg));
                    else
                        snprintf(fg, sizeof(fg), "unk");
                    fprintf(stderr,
                            "[TCP-DIAG][SSH-TX-ENC-OK] action=%s cleartext_len=%u onwire_len=%u wan=%d(%s) tcp=[%s]\n",
                            policy_action_name(cp->action), (unsigned)cleartext_len, (unsigned)pkt_len,
                            wan_idx, wan->ifname, fg);
                }

                {
                    int send_rc = interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len);
                    if (send_rc == 0) {
                        __sync_fetch_and_add(&fwd->local_to_wan, 1);
                        wan_used[wan_idx] = 1;
                    } else {
                        if (g_tcp_diag_enabled && flow_ok && tcp_diag_want_log(protocol, src_port, dst_port)) {
                            fprintf(stderr,
                                    "[TCP-DIAG][TX-SEND-FAIL] wan=%d(%s) enc_len=%u rc=%d\n",
                                    wan_idx, wan->ifname, (unsigned)pkt_len, send_rc);
                        }
                        ne_tx_class_log("TX_WAN_SEND_FAIL", "WORKER_L3L4", "wan_batch_queue_reject_full_packet",
                                        job.local_idx, wan->ifname, wan_idx, flow_ok, src_ip, src_port, dst_ip,
                                        dst_port, protocol, pkt_len, "interface_send_batch_queue");
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                    }
                }
            }
        }

        if (crypto_enabled && flow_ok && protocol == IPPROTO_TCP && tcp_flags_ok &&
            (tcp_flags & (TH_FIN | TH_RST)))
            tcp_policy_pin_remove(src_ip, dst_ip, src_port, dst_port);

skip_encrypt_flush:
        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

release_local:
        if (job.fwd && job.local_idx >= 0 &&
            job.local_idx < job.fwd->local_count) {
            struct xsk_interface *local = &job.fwd->locals[job.local_idx];
            interface_recv_release_single_queue(local, job.queue_idx, &job.addr, 1);
        }
        packet_critical_leave();
    }

    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    g_cfg_ptr = cfg;

    interface_xdp_detach_all_from_config(cfg);
    interface_reset_redirect_maps();

    /* Single-queue per iface: matches single-core scheduling (FORWARDER_CPU_CORE). */
    for (int i = 0; i < cfg->local_count; i++)
        cfg->locals[i].queue_count = FORWARDER_XSK_QUEUE_COUNT;
    for (int i = 0; i < cfg->wan_count; i++)
        cfg->wans[i].queue_count = FORWARDER_XSK_QUEUE_COUNT;

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    forwarder_tcp_diag_apply_env();
    if (cfg->local_count > 0) {
        if (install_local_mac_table(fwd) != 0)
            return -1;
    }
    int has_encrypt_l2 = 0;
    if (crypto_enabled) {
        if (g_active_policy_count > 0) {
            memcpy(g_prev_policy_crypto_ctx, g_policy_crypto_ctx, sizeof(g_prev_policy_crypto_ctx));
            memcpy(g_prev_policy_crypto_ctx_ready, g_policy_crypto_ctx_ready, sizeof(g_prev_policy_crypto_ctx_ready));
            memcpy(g_prev_policies, g_active_policies, sizeof(g_prev_policies));
            g_prev_policy_count = g_active_policy_count;
            g_prev_policy_grace_until_ms = monotonic_ms() + POLICY_RELOAD_GRACE_MS;
            fprintf(stderr, "[CRYPTO] policy grace window active for %llu ms\n",
                    (unsigned long long)POLICY_RELOAD_GRACE_MS);
        } else {
            memset(g_prev_policy_crypto_ctx_ready, 0, sizeof(g_prev_policy_crypto_ctx_ready));
            g_prev_policy_count = 0;
            g_prev_policy_grace_until_ms = 0;
        }

        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to initialize AES-%d encryption\n", cfg->aes_bits);
            return -1;
        }


        rebuild_crypto_runtime(cfg, &has_encrypt_l2);

        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2) {
            if (cfg->fake_ethertype_ipv4 == 0)
                cfg->fake_ethertype_ipv4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
            cfg->fake_ethertype_ipv6 = 0;
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, 0);
        }
        if (crypto_layer == 3) {
            if (cfg->fake_protocol != 0)
                packet_crypto_set_fake_protocol(cfg->fake_protocol);
            else
                packet_crypto_set_fake_protocol(99);
        }

    } else {
        g_active_policy_count = 0;
    }



    uint32_t wan_window_sizes[MAX_INTERFACES] = {0};
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        wan_window_sizes[i] = cfg->wans[i].window_size;
    compute_profile_weighted_wan_windows(cfg, wan_window_sizes, cfg->wan_count);
    flow_table_init(&g_flow_table, wan_window_sizes, cfg->wan_count);

    frag_table_init(&g_wan_frag_l2);
    frag_table_init(&g_wan_frag_l3);
    frag_table_init(&g_wan_frag_l4);
    tcp_policy_pin_init();

    int total_threads = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
        total_threads += cfg->locals[i].queue_count;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);
        total_threads += cfg->wans[i].queue_count;
    }
    total_threads += 1;

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            interface_cleanup(&fwd->locals[i]);
            goto err_locals;
        }
        fwd->local_count++;
    }


    if (interface_push_encrypt_filters(cfg) != 0) {
        fprintf(stderr, "[XDP] WARN: encrypt filter maps may be stale\n");
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t wan_fake4 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv4 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], cfg->bpf_file, wan_fake4, 0) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
    }

    return 0;

err_wans:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
err_locals:
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    tcp_policy_pin_cleanup();
    return -1;
}

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg) {
    if (!fwd || !cfg || !fwd->cfg)
        return -1;
    if (!same_topology(fwd->cfg, cfg)) {
        fprintf(stderr, "[RELOAD] topology changed; hot reload rejected\n");
        return -1;
    }
    int need_crypto_reload = crypto_runtime_changed(fwd->cfg, cfg);
    int need_forwarding_reload = forwarding_runtime_changed(fwd->cfg, cfg);
    if (!need_crypto_reload && !need_forwarding_reload) {
        fwd->cfg = cfg;
        g_cfg_ptr = cfg;
        fprintf(stderr, "[RELOAD] skipped: config is unchanged\n");
        return 0;
    }

    atomic_store_explicit(&g_reload_pause, 1, memory_order_release);
    while (atomic_load_explicit(&g_inflight_packets, memory_order_acquire) > 0)
        sched_yield();

    fwd->cfg = cfg;
    g_cfg_ptr = cfg;

    /* Keep one AF_XDP queue per iface (single-core mode). */
    for (int i = 0; i < cfg->local_count; i++)
        cfg->locals[i].queue_count = FORWARDER_XSK_QUEUE_COUNT;
    for (int i = 0; i < cfg->wan_count; i++)
        cfg->wans[i].queue_count = FORWARDER_XSK_QUEUE_COUNT;

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    if (crypto_enabled && need_crypto_reload) {
        int has_encrypt_l2 = 0;
        rebuild_crypto_runtime(cfg, &has_encrypt_l2);
        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2) {
            if (cfg->fake_ethertype_ipv4 == 0)
                cfg->fake_ethertype_ipv4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
            cfg->fake_ethertype_ipv6 = 0;
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, 0);
        }
        if (cfg->encrypt_layer == 3)
            packet_crypto_set_fake_protocol(cfg->fake_protocol ? cfg->fake_protocol : 99);
        tcp_policy_pin_clear_all();
    }

    atomic_store_explicit(&g_reload_pause, 0, memory_order_release);
    if (interface_push_encrypt_filters(cfg) != 0)
        fprintf(stderr, "[RELOAD][WARN] interface_push_encrypt_filters failed\n");
    fprintf(stderr, "[RELOAD] hot reload applied in-place (crypto=%s, forwarding=%s)\n",
            need_crypto_reload ? "yes" : "no",
            need_forwarding_reload ? "yes" : "no");
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd) {
    if (crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    flow_table_cleanup(&g_flow_table);
    tcp_policy_pin_cleanup();

    local_mac_table_clear();
    g_local_peer_macs_ready = 0;
    g_peer_mac_seed_count = 0;

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}


static void forwarder_run_no_crypto(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[NO-CRYPTO] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_no_crypto, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_no_crypto, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l2(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;


    fprintf(stderr, "[L2 DEBUG] total_local_queues=%d, total_wan_queues=%d\n",
            total_local_queues, total_wan_queues);
    for (int i = 0; i < fwd->local_count; i++) {
        fprintf(stderr, "[L2 DEBUG] local[%d] ifname=%s queue_count=%d\n",
                i, fwd->locals[i].ifname, fwd->locals[i].queue_count);
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        fprintf(stderr, "[L2 DEBUG] wan[%d] ifname=%s queue_count=%d\n",
                i, fwd->wans[i].ifname, fwd->wans[i].queue_count);
    }


    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L2] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l2, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l2, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l3(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + 1;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L3] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    g_worker_ring.head = 0;
    g_worker_ring.tail = 0;
    pthread_mutex_init(&g_worker_ring.lock, NULL);

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    pthread_create(&threads[thread_idx], NULL, worker_thread, NULL);
    thread_idx++;

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l4(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + 1;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L4] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    g_worker_ring.head = 0;
    g_worker_ring.tail = 0;
    pthread_mutex_init(&g_worker_ring.lock, NULL);

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    pthread_create(&threads[thread_idx], NULL, worker_thread, NULL);
    thread_idx++;

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}



void forwarder_run(struct forwarder *fwd) {
    running = 1;
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    fprintf(stderr,
            "[RUNTIME] single_core cpu=%d xsk_queue_id=%d queues_per_iface=%d (all worker threads pin here)\n",
            FORWARDER_CPU_CORE, FORWARDER_XSK_QUEUE_ID, FORWARDER_XSK_QUEUE_COUNT);

    if (!crypto_enabled) {
        forwarder_run_no_crypto(fwd);
    } else if (crypto_layer == 2) {
        forwarder_run_l2(fwd);
    } else if (crypto_layer == 3) {
        forwarder_run_l3(fwd);
    } else if (crypto_layer == 4) {
        forwarder_run_l4(fwd);
    } else {
        forwarder_run_l3(fwd);
    }
}

void forwarder_stop(void) {
    running = 0;
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;

    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES)
             ? fwd->locals[0].queue_count : 0;
    if (nq <= 0) nq = 1;

    uint64_t tx_wait_loops = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait_loops += fwd->locals[i].queues[q].tx_wait_loops;
    }

    fprintf(stdout,
            "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu "
            "dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu "
            "local_mac_preload_loaded=%lu",
            fwd->local_to_wan,
            fwd->wan_to_local,
            fwd->total_dropped,
            fwd->dropped_bad_ip,
            fwd->dropped_no_local_match,
            fwd->dropped_local_tx_fail,
            (unsigned long)fwd->local_mac_preload_loaded);
    for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
        fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait_loops);

}