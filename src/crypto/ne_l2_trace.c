#include "../../inc/ne_l2_trace.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ne_l2_trace = -1;

int ne_l2_trace_enabled(void) {
    if (g_ne_l2_trace < 0) {
#if NE_L2_TRACE_DEFAULT_ON
        const char *e = getenv("NE_L2_DIAG");
        if (!e || !e[0])
            e = getenv("NE_L2_TRACE");
        /* Mặc định BẬT; chỉ tắt khi NE_L2_DIAG=0 hoặc NE_L2_TRACE=0 */
        g_ne_l2_trace = (e && e[0] == '0') ? 0 : 1;
#else
        const char *e = getenv("NE_L2_DIAG");
        if (!e || !e[0])
            e = getenv("NE_L2_TRACE");
        g_ne_l2_trace = (e && e[0] && e[0] != '0') ? 1 : 0;
#endif
    }
    return g_ne_l2_trace;
}

static void trace_flow_tail(const uint8_t *pkt, uint32_t len) {
    if (len < 14U + 20U)
        return;
    const uint8_t *ip = pkt + 14U;
    if ((ip[0] >> 4) != 4)
        return;
    int ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || len < (uint32_t)(14 + ihl + 4))
        return;

    char sb[32], db[32];
    inet_ntop(AF_INET, ip + 12, sb, sizeof(sb));
    inet_ntop(AF_INET, ip + 16, db, sizeof(db));
    uint8_t proto = ip[9];
    const char *pn = (proto == 6) ? "tcp" : (proto == 17) ? "udp" : "ip";

    if (proto == 6 || proto == 17) {
        const uint8_t *l4 = ip + ihl;
        uint16_t sp = (uint16_t)((l4[0] << 8) | l4[1]);
        uint16_t dp = (uint16_t)((l4[2] << 8) | l4[3]);
        fprintf(stderr, " %s:%u->%s:%u %s", sb, (unsigned)sp, db, (unsigned)dp, pn);
    } else {
        fprintf(stderr, " %s->%s %s", sb, db, pn);
    }
}

void ne_l2_trace_event(const char *stage, const char *iface,
                       const uint8_t *pkt, uint32_t len, const char *detail) {
    if (!ne_l2_trace_enabled() || !stage)
        return;

    fprintf(stderr, "[L2] %-14s", stage);
    if (iface && iface[0])
        fprintf(stderr, " if=%s", iface);

    if (pkt && len >= 14U) {
        uint16_t et = (uint16_t)(((uint16_t)pkt[12] << 8) | pkt[13]);
        fprintf(stderr, " len=%u et=0x%04x", (unsigned)len, (unsigned)et);
        if (pkt[12] == 0x88U && len >= 17U) {
            uint32_t pid = ((uint32_t)pkt[13] << 24) | ((uint32_t)pkt[14] << 16) |
                           ((uint32_t)pkt[15] << 8) | (uint32_t)pkt[16];
            fprintf(stderr, " policy=%u", (unsigned)pid);
        }
        if (et == 0x0800U)
            trace_flow_tail(pkt, len);
    } else if (len) {
        fprintf(stderr, " len=%u", (unsigned)len);
    }

    if (detail && detail[0])
        fprintf(stderr, " | %s", detail);
    fprintf(stderr, "\n");
}

void ne_l2_trace_plain(const char *stage, const char *iface, const char *detail) {
    ne_l2_trace_event(stage, iface, NULL, 0, detail);
}

void ne_l2_trace_frag(const char *stage, const char *iface,
                      uint16_t opid, uint8_t frag_idx, int frag_idx_valid,
                      const uint8_t *pkt, uint32_t len, const char *extra) {
    if (!ne_l2_trace_enabled() || !stage)
        return;

    char detail[96];
    if (frag_idx_valid)
        snprintf(detail, sizeof(detail), "opid=%u idx=%u%s%s",
                 (unsigned)opid, (unsigned)frag_idx,
                 (extra && extra[0]) ? " " : "", (extra && extra[0]) ? extra : "");
    else
        snprintf(detail, sizeof(detail), "opid=%u%s%s",
                 (unsigned)opid, (extra && extra[0]) ? " " : "",
                 (extra && extra[0]) ? extra : "");

    ne_l2_trace_event(stage, iface, pkt, len, detail);
}
