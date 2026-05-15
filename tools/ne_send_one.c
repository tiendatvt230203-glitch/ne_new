/*
 * Tool test — build & chạy trên CLIENT (dưới firewall), không chạy trên SEP.
 *
 * Đường đi:  Client [ens35] -> FW (LAN) -> FW [enp5s0...] -> SEP [enp5s0/enp6s0] -> WAN ...
 *
 * Gửi 1 gói UDP 1500B: 192.168.9.2 -> 192.168.180.2 (policy 421 encrypt_l2).
 *   make ne_send_one && sudo ./bin/ne_send_one
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NE_IFACE   "ens35"
#define NE_SMAC    0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xf4
#define NE_DMAC    0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x06
#define NE_SRC_IP  "192.168.9.2"
#define NE_DST_IP  "192.168.180.2"
#define NE_FRAME   1500
#define NE_SPORT   45000
#define NE_DPORT   45000

#define NE_MAGIC "NE1UDP_v1_9.2_to_180.2___"

static uint16_t csum16(const void *buf, int len) {
    const uint16_t *p = buf;
    uint32_t s = 0;
    while (len > 1) {
        s += *p++;
        len -= 2;
    }
    if (len)
        s += *(const uint8_t *)buf;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s);
}

static uint16_t udp_csum(uint32_t src, uint32_t dst, const void *seg, int len) {
    uint8_t ph[12];
    memcpy(ph + 0, &src, 4);
    memcpy(ph + 4, &dst, 4);
    ph[8] = 0;
    ph[9] = IPPROTO_UDP;
    ph[10] = (uint8_t)(len >> 8);
    ph[11] = (uint8_t)len;

    uint32_t s = 0;
    for (int i = 0; i < 6; i++)
        s += ((uint16_t *)ph)[i];
    const uint16_t *w = seg;
    while (len > 1) {
        s += *w++;
        len -= 2;
    }
    if (len)
        s += *(const uint8_t *)w;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s);
}

int main(void) {
    const uint8_t smac[] = { NE_SMAC };
    const uint8_t dmac[] = { NE_DMAC };
    const int frame_len = NE_FRAME;

    uint8_t *f = calloc(1, frame_len);
    if (!f)
        return 1;

    memcpy(f, dmac, 6);
    memcpy(f + 6, smac, 6);
    f[12] = 0x08;
    f[13] = 0x00;

    struct iphdr *ip = (struct iphdr *)(f + 14);
    ip->version = 4;
    ip->ihl = 5;
    ip->id = htons(0x4e45);
    ip->frag_off = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, NE_SRC_IP, &ip->saddr);
    inet_pton(AF_INET, NE_DST_IP, &ip->daddr);

    const int ip_len = frame_len - 14;
    const int udp_len = ip_len - 20;
    const int pay_len = udp_len - 8;
    ip->tot_len = htons((uint16_t)ip_len);

    struct udphdr *udp = (struct udphdr *)(f + 34);
    memset(udp, 0, sizeof(*udp));
    udp->source = htons(NE_SPORT);
    udp->dest = htons(NE_DPORT);
    udp->len = htons((uint16_t)udp_len);

    uint8_t *pay = f + 42;
    memcpy(pay, NE_MAGIC, strlen(NE_MAGIC));
    for (int i = (int)strlen(NE_MAGIC); i < pay_len; i++)
        pay[i] = (uint8_t)(0xa5 ^ i);

    udp->check = 0;
    udp->check = udp_csum(ip->saddr, ip->daddr, udp, udp_len);
    if (udp->check == 0)
        udp->check = 0xffff;
    ip->check = csum16(ip, 20);

    int ifi = if_nametoindex(NE_IFACE);
    if (!ifi) {
        perror(NE_IFACE);
        free(f);
        return 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("socket");
        free(f);
        return 1;
    }

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifi;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, dmac, 6);

    if (sendto(fd, f, frame_len, 0, (struct sockaddr *)&sa, sizeof(sa)) != frame_len) {
        perror("sendto");
        close(fd);
        free(f);
        return 1;
    }
    close(fd);
    free(f);

    fprintf(stderr, "OK: 1 UDP frame %dB %s -> %s on %s (policy 421 encrypt_l2)\n",
            frame_len, NE_SRC_IP, NE_DST_IP, NE_IFACE);
    return 0;
}
