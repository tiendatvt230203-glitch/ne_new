#ifndef NE_L2_TRACE_H
#define NE_L2_TRACE_H

#include <stdint.h>

/* DEBUG TẠM: log L2 luôn bật → stderr. Xóa cả module khi xong debug.
 * Tắt tạm: NE_L2_DIAG=0
 *
 * Pipeline (một dòng / bước):
 *  S1-LOCAL-IN … S9-TX-PFSENSE — xem ne_l2_trace.c */

#ifndef NE_L2_TRACE_DEFAULT_ON
#define NE_L2_TRACE_DEFAULT_ON 1
#endif

int ne_l2_trace_enabled(void);

void ne_l2_trace_event(const char *stage, const char *iface,
                       const uint8_t *pkt, uint32_t len, const char *detail);

void ne_l2_trace_plain(const char *stage, const char *iface, const char *detail);

void ne_l2_trace_frag(const char *stage, const char *iface,
                      uint16_t opid, uint8_t frag_idx, int frag_idx_valid,
                      const uint8_t *pkt, uint32_t len, const char *extra);

#endif
