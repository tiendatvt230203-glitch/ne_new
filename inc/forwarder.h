#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"

#ifndef FORWARDER_CPU_CORE
#define FORWARDER_CPU_CORE 0
#endif

struct forwarder {
    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;

    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    struct app_config *cfg;

    int current_wan;
    uint64_t wan_bytes[MAX_INTERFACES];

    uint64_t local_to_wan;
    uint64_t wan_to_local;
    uint64_t total_dropped;


    uint64_t dropped_bad_ip;
    uint64_t dropped_no_local_match;
    uint64_t dropped_local_tx_fail;
#define FORWARDER_MAX_LOCAL_QUEUES 16
    uint64_t dropped_local_tx_fail_by_queue[FORWARDER_MAX_LOCAL_QUEUES];
};

void forwarder_pin_cpu(void);

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
int forwarder_should_stop(void);
void forwarder_print_stats(struct forwarder *fwd);

#endif
