CREATE TABLE IF NOT EXISTS xdp_configs (
    id SERIAL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS xdp_local_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS xdp_wan_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    dst_ip VARCHAR(32) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS xdp_profiles (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    profile_name VARCHAR(64) NOT NULL,
    enabled INT NOT NULL DEFAULT 1,
    description TEXT,
    CONSTRAINT xdp_profiles_enabled_chk CHECK (enabled IN (0, 1)),
    CONSTRAINT xdp_profiles_config_name_uniq UNIQUE (config_id, profile_name)
);

CREATE TABLE IF NOT EXISTS xdp_profile_locals (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    CONSTRAINT xdp_profile_locals_uniq UNIQUE (profile_id, ifname)
);

CREATE TABLE IF NOT EXISTS xdp_profile_wans (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    bandwidth_weight_percent INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT xdp_profile_wans_uniq UNIQUE (profile_id, ifname),
    CONSTRAINT xdp_profile_wans_weight_chk CHECK (bandwidth_weight_percent >= 0 AND bandwidth_weight_percent <= 100)
);

CREATE TABLE IF NOT EXISTS xdp_profile_crypto_policies (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    priority INT NOT NULL DEFAULT 100,
    action VARCHAR(32) NOT NULL,
    protocol VARCHAR(16) NOT NULL DEFAULT 'ANY',
    crypto_mode VARCHAR(16) NOT NULL DEFAULT 'gcm',
    aes_bits INT NOT NULL DEFAULT 128,
    nonce_size INT NOT NULL DEFAULT 12,
    crypto_key TEXT,
    CONSTRAINT xdp_profile_crypto_policies_action_chk
        CHECK (lower(action) IN ('bypass', 'encrypt_l2', 'encrypt l2', 'encrypt_l3', 'encrypt l3', 'encrypt_l4', 'encrypt l4')),
    CONSTRAINT xdp_profile_crypto_policies_mode_chk
        CHECK (lower(crypto_mode) IN ('gcm', 'ctr')),
    CONSTRAINT xdp_profile_crypto_policies_aes_bits_chk
        CHECK (aes_bits IN (128, 256)),
    CONSTRAINT xdp_profile_crypto_policies_nonce_chk
        CHECK (nonce_size >= 4 AND nonce_size <= 16)
);

CREATE TABLE IF NOT EXISTS xdp_profile_crypto_policy_matches (
    id SERIAL PRIMARY KEY,
    policy_id INT NOT NULL REFERENCES xdp_profile_crypto_policies(id) ON DELETE CASCADE,
    src_cidr TEXT NOT NULL DEFAULT 'ANY',
    src_port VARCHAR(32) NOT NULL DEFAULT 'ANY',
    dst_cidr TEXT NOT NULL DEFAULT 'ANY',
    dst_port VARCHAR(32) NOT NULL DEFAULT 'ANY'
);

CREATE INDEX IF NOT EXISTS idx_local_config_id ON xdp_local_configs(config_id);
CREATE INDEX IF NOT EXISTS idx_wan_config_id ON xdp_wan_configs(config_id);
CREATE INDEX IF NOT EXISTS idx_profiles_config_id ON xdp_profiles(config_id);
CREATE INDEX IF NOT EXISTS idx_profile_locals_profile_id ON xdp_profile_locals(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_wans_profile_id ON xdp_profile_wans(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_policies_profile_id ON xdp_profile_crypto_policies(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_policy_matches_policy_id ON xdp_profile_crypto_policy_matches(policy_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'xdp_local_configs_unique_per_config'
    ) THEN
        ALTER TABLE xdp_local_configs
            ADD CONSTRAINT xdp_local_configs_unique_per_config UNIQUE (config_id, ifname);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'xdp_wan_configs_unique_per_config'
    ) THEN
        ALTER TABLE xdp_wan_configs
            ADD CONSTRAINT xdp_wan_configs_unique_per_config UNIQUE (config_id, ifname);
    END IF;
END $$;

ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_enabled;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_key;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS encrypt_layer;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS fake_protocol;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_mode;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS aes_bits;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS nonce_size;

ALTER TABLE xdp_local_configs DROP COLUMN IF EXISTS network;
ALTER TABLE xdp_local_configs DROP COLUMN IF EXISTS ingress_mbps;

ALTER TABLE xdp_wan_configs ADD COLUMN IF NOT EXISTS dst_ip VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS window_size_kb;
ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS src_ip;
ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS next_hop_ip;

ALTER TABLE xdp_profile_wans
    ADD COLUMN IF NOT EXISTS bandwidth_weight_percent INTEGER NOT NULL DEFAULT 0;

ALTER TABLE xdp_profiles DROP COLUMN IF EXISTS channel_bonding;
ALTER TABLE xdp_profile_crypto_policies DROP COLUMN IF EXISTS src_cidr;
ALTER TABLE xdp_profile_crypto_policies DROP COLUMN IF EXISTS src_port;
ALTER TABLE xdp_profile_crypto_policies DROP COLUMN IF EXISTS dst_cidr;
ALTER TABLE xdp_profile_crypto_policies DROP COLUMN IF EXISTS dst_port;

ALTER TABLE xdp_profiles DROP COLUMN IF EXISTS channel_bonding_id;

DROP TABLE IF EXISTS xdp_channel_bonding_wans CASCADE;
DROP TABLE IF EXISTS xdp_channel_bondings CASCADE;