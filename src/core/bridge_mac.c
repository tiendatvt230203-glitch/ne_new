#include "../../inc/bridge_mac.h"
#include "../../inc/forwarder.h"
#include "../../inc/packet_crypto.h"
#include "../../inc/config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#ifndef NE_DEFAULT_FAKE_ETHERTYPE_IPV4
#define NE_DEFAULT_FAKE_ETHERTYPE_IPV4 0x88B5u
#endif

static uint64_t bridge_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static int read_local_iface_hwaddr(const char *ifname, uint8_t mac[MAC_LEN], int *ioctl_errno_out);

static int bridge_mac_verbose(void) {
    const char *v = getenv("NE_BRIDGE_MAC_VERBOSE");
    return (v && v[0] == '1');
}

static void bridge_mac_log_local_hw(const char *ifname) {
    uint8_t hw[MAC_LEN];
    if (read_local_iface_hwaddr(ifname, hw, NULL) == 0) {
        fprintf(stderr,
                "[LOCAL-MAC] %s %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname, hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
    } else {
        fprintf(stderr, "[LOCAL-MAC] %s (hwaddr unavailable)\n", ifname);
    }
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

    uint64_t now = bridge_monotonic_ms();
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

    uint64_t now = bridge_monotonic_ms();
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

static void local_mac_log_iface_and_peer(const char *ifname, const uint8_t peer[MAC_LEN], uint8_t *store_src_mac);

static pthread_mutex_t g_peer_dst_mac_mu = PTHREAD_MUTEX_INITIALIZER;

static void apply_peer_dst_mac(struct forwarder *fwd, int local_idx, const uint8_t mac[MAC_LEN],
                               const char *reason) {
    if (!fwd || !fwd->cfg || !mac || local_idx < 0 || local_idx >= fwd->local_count)
        return;
    if (mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return;

    pthread_mutex_lock(&g_peer_dst_mac_mu);
    if (memcmp(fwd->cfg->locals[local_idx].dst_mac, mac, MAC_LEN) == 0) {
        pthread_mutex_unlock(&g_peer_dst_mac_mu);
        return;
    }
    local_mac_learn(local_idx, mac);
    memcpy(fwd->cfg->locals[local_idx].dst_mac, mac, MAC_LEN);
    memcpy(fwd->locals[local_idx].dst_mac, mac, MAC_LEN);
    pthread_mutex_unlock(&g_peer_dst_mac_mu);

    (void)reason;
    if (bridge_mac_verbose()) {
        fprintf(stderr,
                "[LOCAL-MAC-VERBOSE] %s learned peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                fwd->cfg->locals[local_idx].ifname,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

static void bridge_mac_learn_rx_impl(struct forwarder *fwd, int local_idx, const uint8_t *pkt,
                                uint32_t pkt_len) {
    if (!fwd || !pkt || pkt_len < sizeof(struct ether_header))
        return;
    const uint8_t *sm = pkt + 6;
    if (mac_is_zero(sm) || mac_is_broadcast(sm) || mac_is_multicast(sm))
        return;
    apply_peer_dst_mac(fwd, local_idx, sm, "rx_eth_src");
}

static int bridge_mac_local_for_dmac_impl(struct forwarder *fwd, const uint8_t *pkt, uint32_t pkt_len) {
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

static int peer_mac_from_kernel(const char *ifname, uint8_t mac_out[MAC_LEN], int quiet) {
    char cmd[384];
    FILE *fp;
    uint8_t local_hw[MAC_LEN];
    int have_local = (read_local_iface_hwaddr(ifname, local_hw, NULL) == 0);
    char brm[IFNAMSIZ];
    int have_br = (net_sysfs_bridge_master(ifname, brm) == 0);

    if (have_br) {
        int bf = peer_mac_from_full_bridge_fdb(ifname, brm, have_local ? local_hw : NULL, mac_out);
        if (bf == 0) {
            if (!quiet && bridge_mac_verbose()) {
                fprintf(stderr,
                        "[LOCAL-MAC-VERBOSE] %s peer from bridge fdb (dev %s master %s)\n",
                        ifname, ifname, brm);
            }
            return 0;
        }
        if (bf == -2) {
            if (!quiet) {
                fprintf(stderr,
                        "[LOCAL-MAC][WARN] %s: multiple MAC in `bridge fdb show` for dev %s master %s; "
                        "try NE_LOCAL_MAC_PRELOAD or reduce hosts on segment\n",
                        ifname, ifname, brm);
            }
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
            if (!quiet) {
                fprintf(stderr,
                        "[LOCAL-MAC][WARN] %s: ip neigh has multiple lladdr; trying bridge master / fdb\n",
                        ifname);
            }
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
                if (!quiet) {
                    fprintf(stderr,
                            "[LOCAL-MAC][WARN] %s: bridge %s neigh has multiple lladdr; trying bridge fdb\n",
                            ifname, brm);
                }
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
    if (r == -2 && !quiet)
        fprintf(stderr, "[FATAL][LOCAL-MAC] %s bridge fdb multiple MAC\n", ifname);

    if (have_br) {
        int ar = merge_arp_device(brm, mac_out, have_local ? local_hw : NULL);
        if (ar == 0)
            return 0;
        if (ar == -2) {
            if (!quiet) {
                fprintf(stderr,
                        "[LOCAL-MAC][WARN] %s: /proc/net/arp on %s has multiple MAC; try NE_LOCAL_MAC_PRELOAD\n",
                        ifname, brm);
            }
        }
    }
    if (merge_arp_device(ifname, mac_out, have_local ? local_hw : NULL) == 0)
        return 0;

    return -1;
}

static void local_ms_sleep(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

static void *local_peer_mac_poll_thread(void *arg) {
    struct forwarder *fwd = (struct forwarder *)arg;
    if (!fwd || !fwd->cfg || fwd->local_count <= 0)
        return NULL;

    unsigned fast_ms = 500;
    const char *ef = getenv("NE_LOCAL_MAC_POLL_MS");
    if (ef && ef[0]) {
        unsigned v = (unsigned)strtoul(ef, NULL, 10);
        if (v >= 50u && v <= 60000u)
            fast_ms = v;
    }
    unsigned slow_ms = 5000;
    const char *es = getenv("NE_LOCAL_MAC_POLL_SLOW_MS");
    if (es && es[0]) {
        unsigned v = (unsigned)strtoul(es, NULL, 10);
        if (v >= 200u && v <= 300000u)
            slow_ms = v;
    }

    if (bridge_mac_verbose()) {
        fprintf(stderr,
                "[LOCAL-MAC-POLL] active (fast=%u slow=%u ms)\n",
                fast_ms, slow_ms);
    }

    while (!forwarder_should_stop()) {
        int all_known = 1;
        for (int li = 0; li < fwd->local_count; li++) {
            if (mac_is_zero(fwd->cfg->locals[li].dst_mac))
                all_known = 0;

            uint8_t mac[MAC_LEN];
            if (peer_mac_from_kernel(fwd->cfg->locals[li].ifname, mac, 1) != 0)
                continue;
            apply_peer_dst_mac(fwd, li, mac, "kernel_sync");
        }
        local_ms_sleep(all_known ? slow_ms : fast_ms);
    }
    return NULL;
}

static int mac_load_from_kernel(struct app_config *cfg, uint64_t *out_n) {
    uint8_t macs[MAX_INTERFACES][MAC_LEN];

    fprintf(stderr, "[LOCAL-MAC] local interface hardware addresses:\n");
    for (int li = 0; li < cfg->local_count; li++) {
        uint8_t hw[MAC_LEN];
        bridge_mac_log_local_hw(cfg->locals[li].ifname);
        if (read_local_iface_hwaddr(cfg->locals[li].ifname, hw, NULL) == 0)
            memcpy(cfg->locals[li].src_mac, hw, MAC_LEN);
    }

    int n_ok = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        memset(macs[i], 0, MAC_LEN);
        if (peer_mac_from_kernel(cfg->locals[i].ifname, macs[i], 1) != 0)
            continue;
        n_ok++;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        if (!mac_is_zero(macs[i])) {
            local_mac_learn(i, macs[i]);
            memcpy(cfg->locals[i].dst_mac, macs[i], MAC_LEN);
        }
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

static int bridge_mac_prepare_impl(struct app_config *cfg) {
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

static int bridge_mac_install_impl(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return -1;
    if (bridge_mac_prepare_impl(fwd->cfg) != 0)
        return -1;
    return 0;
}
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
void bridge_wan_rx_normalize_eth_ipv4(uint8_t *pkt, uint32_t pkt_len) {
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

static pthread_t g_bridge_mac_poll_tid;
static int g_bridge_mac_poll_started;

int config_wan_bridge_mode(const struct app_config *cfg) {
    if (!cfg || cfg->wan_count <= 0)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].dst_ip == 0)
            return 1;
    }
    return 0;
}

int bridge_mac_prepare(struct app_config *cfg) {
    return bridge_mac_prepare_impl(cfg);
}

static void bridge_mac_copy_local_macs(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    for (int i = 0; i < fwd->local_count && i < fwd->cfg->local_count; i++) {
        memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
        memcpy(fwd->locals[i].dst_mac, fwd->cfg->locals[i].dst_mac, MAC_LEN);
    }
}

int bridge_mac_install(struct forwarder *fwd) {
    if (bridge_mac_install_impl(fwd) != 0)
        return -1;
    bridge_mac_copy_local_macs(fwd);
    if (!g_bridge_mac_poll_started && fwd->local_count > 0) {
        if (pthread_create(&g_bridge_mac_poll_tid, NULL, local_peer_mac_poll_thread, fwd) == 0) {
            pthread_detach(g_bridge_mac_poll_tid);
            g_bridge_mac_poll_started = 1;
        }
    }
    return 0;
}

void bridge_mac_shutdown(void) {
    g_local_peer_macs_ready = 0;
    g_peer_mac_seed_count = 0;
    local_mac_table_clear();
    g_bridge_mac_poll_started = 0;
}

void bridge_mac_learn_rx(struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len) {
    bridge_mac_learn_rx_impl(fwd, local_idx, pkt, pkt_len);
}

int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len) {
    return bridge_mac_local_for_dmac_impl(fwd, pkt, pkt_len);
}

void bridge_mac_sync_cfg_to_iface(struct forwarder *fwd) {
    bridge_mac_copy_local_macs(fwd);
}

