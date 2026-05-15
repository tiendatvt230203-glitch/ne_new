#include "../../inc/ne_agent_dbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *ne_agent_dbg_path(void) {
    const char *p = getenv("NE_DEBUG_LOG");
    if (p && p[0])
        return p;
    return "/home/tiendat/CODE/network-encryptor/.cursor/debug-eefb96.log";
}

void ne_agent_dbg(const char *hypothesis_id, const char *location, const char *message,
                  const char *run_id, const char *json_kv) {
    if (!hypothesis_id || !location || !message)
        return;

    FILE *f = fopen(ne_agent_dbg_path(), "a");
    if (!f)
        return;

    long long ts = (long long)time(NULL) * 1000LL;
    fprintf(f,
            "{\"sessionId\":\"eefb96\",\"timestamp\":%lld,\"hypothesisId\":\"%s\","
            "\"location\":\"%s\",\"message\":\"%s\",\"runId\":\"%s\",\"data\":{%s}}\n",
            ts, hypothesis_id, location, message, run_id ? run_id : "pre-fix",
            json_kv ? json_kv : "");
    fclose(f);
}
