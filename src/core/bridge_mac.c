#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/crypto/packet_crypto.h"
#include "../../inc/core/config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef NE_DEFAULT_FAKE_ETHERTYPE_IPV4
#define NE_DEFAULT_FAKE_ETHERTYPE_IPV4 0x88B5u
#endif

#define NE_PEER_MAC_FILE_DEFAULT "/var/lib/network-encryptor/peer_mac.conf"

static int g_peer_macs_ready;

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

static int mac_is_valid_peer(const uint8_t mac[MAC_LEN]) {
    return !mac_is_zero(mac) && !mac_is_broadcast(mac) && !mac_is_multicast(mac);
}

static int local_idx_by_ifname(struct app_config *cfg, const char *name) {
    if (!cfg || !name || !name[0])
        return -1;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, name) == 0)
            return i;
    }
    return -1;
}

static int read_local_iface_hwaddr(const char *ifname, uint8_t mac[MAC_LEN]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if ((unsigned int)ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    return 0;
}

static void log_local_peer_mac(const char *ifname, const uint8_t peer[MAC_LEN]) {
    uint8_t loc[MAC_LEN];
    if (read_local_iface_hwaddr(ifname, loc) == 0) {
        fprintf(stderr,
                "[LOCAL-MAC] %s local %02x:%02x:%02x:%02x:%02x:%02x peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                loc[0], loc[1], loc[2], loc[3], loc[4], loc[5],
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    } else {
        fprintf(stderr,
                "[LOCAL-MAC] %s peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    }
}

static const char *peer_mac_file_path(void) {
    const char *p = getenv("NE_PEER_MAC_FILE");
    if (p && p[0])
        return p;
    return NE_PEER_MAC_FILE_DEFAULT;
}

static int mac_set_peer(struct app_config *cfg, int li, const uint8_t mac[MAC_LEN]) {
    if (!cfg || li < 0 || li >= cfg->local_count || !mac_is_valid_peer(mac))
        return -1;
    memcpy(cfg->locals[li].dst_mac, mac, MAC_LEN);
    log_local_peer_mac(cfg->locals[li].ifname, mac);
    return 0;
}

static int mac_load_from_file(struct app_config *cfg) {
    const char *path = peer_mac_file_path();
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char line[256];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        char a[64], b[64];
        if (sscanf(p, "%63[^=]=%63s", a, b) == 2) {
            uint8_t mac[MAC_LEN];
            int li = local_idx_by_ifname(cfg, a);
            if (li >= 0 && parse_mac(b, mac) == 0 && mac_set_peer(cfg, li, mac) == 0)
                loaded++;
            continue;
        }

        char mac_tok[48], if_tok[64];
        if (sscanf(p, "%47s %63s", mac_tok, if_tok) == 2) {
            uint8_t mac[MAC_LEN];
            int li = local_idx_by_ifname(cfg, if_tok);
            if (li < 0) {
                char *end = NULL;
                long idx = strtol(if_tok, &end, 10);
                if (end && *end == '\0' && idx >= 0 && idx < cfg->local_count)
                    li = (int)idx;
            }
            if (li >= 0 && parse_mac(mac_tok, mac) == 0 && mac_set_peer(cfg, li, mac) == 0)
                loaded++;
        }
    }
    fclose(f);
    return loaded;
}

static int mac_save_to_file(struct app_config *cfg) {
    const char *path = peer_mac_file_path();
    const char *dir = "/var/lib/network-encryptor";
    struct stat st;

    if (stat(dir, &st) != 0)
        (void)mkdir(dir, 0755);

    FILE *f = fopen(path, "w");
    if (!f)
        return -1;

    for (int i = 0; i < cfg->local_count; i++) {
        if (mac_is_zero(cfg->locals[i].dst_mac))
            continue;
        fprintf(f, "%s=%02x:%02x:%02x:%02x:%02x:%02x\n",
                cfg->locals[i].ifname,
                cfg->locals[i].dst_mac[0], cfg->locals[i].dst_mac[1],
                cfg->locals[i].dst_mac[2], cfg->locals[i].dst_mac[3],
                cfg->locals[i].dst_mac[4], cfg->locals[i].dst_mac[5]);
    }
    fclose(f);
    return 0;
}

static int mac_wait_first_packet(const char *ifname, uint8_t mac_out[MAC_LEN]) {
    int ifindex = (int)if_nametoindex(ifname);
    if (!ifindex)
        return -1;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    uint8_t buf[2048];
    fprintf(stderr, "[LOCAL-MAC] waiting traffic on %s\n", ifname);
    for (;;) {
        if (forwarder_should_stop()) {
            close(fd);
            return -1;
        }
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < (ssize_t)sizeof(struct ether_header))
            continue;
        struct ether_header *eth = (struct ether_header *)buf;
        if (!mac_is_valid_peer(eth->ether_shost))
            continue;
        memcpy(mac_out, eth->ether_shost, MAC_LEN);
        close(fd);
        return 0;
    }
}

static int mac_load_from_preload_env(struct app_config *cfg) {
    const char *cmd = getenv("NE_LOCAL_MAC_PRELOAD");
    if (!cmd || !cmd[0])
        return 0;

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "[LOCAL-MAC] NE_LOCAL_MAC_PRELOAD failed: %s\n", cmd);
        return -1;
    }

    int loaded = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        char mac_tok[48], if_tok[64];
        if (sscanf(p, "%47s %63s", mac_tok, if_tok) != 2)
            continue;

        uint8_t mac[MAC_LEN];
        if (parse_mac(mac_tok, mac) != 0 || !mac_is_valid_peer(mac))
            continue;

        int li = local_idx_by_ifname(cfg, if_tok);
        if (li < 0) {
            char *end = NULL;
            long idx = strtol(if_tok, &end, 10);
            if (end && *end == '\0' && idx >= 0 && idx < cfg->local_count)
                li = (int)idx;
        }
        if (li >= 0 && mac_set_peer(cfg, li, mac) == 0)
            loaded++;
    }
    pclose(fp);
    return loaded;
}

static int bridge_mac_prepare_impl(struct app_config *cfg) {
    if (!cfg || cfg->local_count <= 0)
        return 0;
    if (g_peer_macs_ready)
        return 0;

    for (int i = 0; i < cfg->local_count; i++)
        (void)read_local_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);

    (void)mac_load_from_file(cfg);
    (void)mac_load_from_preload_env(cfg);

    for (int i = 0; i < cfg->local_count; i++) {
        if (!mac_is_zero(cfg->locals[i].dst_mac))
            continue;
        uint8_t mac[MAC_LEN];
        if (mac_wait_first_packet(cfg->locals[i].ifname, mac) != 0)
            return -1;
        if (mac_set_peer(cfg, i, mac) != 0)
            return -1;
        (void)mac_save_to_file(cfg);
    }

    g_peer_macs_ready = 1;
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

void bridge_wan_rx_normalize_eth_ipv4(uint8_t *pkt, uint32_t pkt_len) {
    if (!pkt || pkt_len < 14 + 20)
        return;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800 || et == 0x8100)
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
    if (pkt[12] != (uint8_t)(fake4 >> 8))
        return;

    pkt[12] = 0x08;
    pkt[13] = 0x00;
}

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
    if (!fwd || !fwd->cfg)
        return -1;
    bridge_mac_copy_local_macs(fwd);
    return 0;
}

void bridge_mac_shutdown(void) {
    g_peer_macs_ready = 0;
}

void bridge_mac_learn_rx(struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len) {
    (void)fwd;
    (void)local_idx;
    (void)pkt;
    (void)pkt_len;
}

int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len) {
    if (!fwd || !fwd->cfg || !pkt || pkt_len < sizeof(struct ether_header))
        return -1;

    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (!mac_is_valid_peer(eth->ether_dhost))
        return -1;

    for (int i = 0; i < fwd->cfg->local_count; i++) {
        if (mac_is_zero(fwd->cfg->locals[i].dst_mac))
            continue;
        if (memcmp(eth->ether_dhost, fwd->cfg->locals[i].dst_mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

void bridge_mac_sync_cfg_to_iface(struct forwarder *fwd) {
    bridge_mac_copy_local_macs(fwd);
}
