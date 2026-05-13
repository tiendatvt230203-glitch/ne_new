#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include "config.h"

int config_load_from_db(struct app_config *cfg, int config_id, const char *conn_str);

int app_config_apply_crypto_from_policies(struct app_config *cfg);

#endif
