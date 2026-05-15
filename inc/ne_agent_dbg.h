#ifndef NE_AGENT_DBG_H
#define NE_AGENT_DBG_H

#include <stdint.h>

/* NDJSON debug log for agent sessions. Set NE_DEBUG_LOG to override path. */
void ne_agent_dbg(const char *hypothesis_id, const char *location, const char *message,
                  const char *run_id, const char *json_kv);

#endif
