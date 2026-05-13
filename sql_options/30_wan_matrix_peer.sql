DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profiles WHERE config_id = 30;

DELETE FROM xdp_local_configs WHERE config_id = 30;
DELETE FROM xdp_wan_configs   WHERE config_id = 30;
DELETE FROM xdp_configs       WHERE id = 30;

INSERT INTO xdp_configs (id) VALUES (30);

INSERT INTO xdp_local_configs (config_id, ifname) VALUES
(30, 'enp5s0'),
(30, 'enp6s0');

INSERT INTO xdp_wan_configs (config_id, ifname) VALUES
(30, 'enp7s0'),
(30, 'enp8s0');

INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES
(30, 'wan_enp7s0_enp8s0_50_50', 1, 'bridge mode: local enp5s0/enp6s0, wan enp7s0/enp8s0');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp5s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp6s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp7s0', 50
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp8s0', 50
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_crypto_policies (
    profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT p.id, 10, 'bypass', 'ANY', 'gcm', 128, 12, '00000000000000000000000000000000'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_crypto_policies (
    profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT p.id, 20, 'encrypt_l2', 'ANY', 'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_crypto_policies (
    profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT p.id, 21, 'encrypt_l3', 'ANY', 'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_crypto_policies (
    profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT p.id, 22, 'encrypt_l4', 'ANY', 'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50';

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port)
SELECT cp.id, '192.168.182.1/32', 'ANY', '192.168.9.1/32', 'ANY'
FROM xdp_profile_crypto_policies cp
JOIN xdp_profiles p ON p.id = cp.profile_id
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50' AND cp.priority = 10;

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port)
SELECT cp.id, '192.168.182.1/32', 'ANY', '192.168.9.1/32', 'ANY'
FROM xdp_profile_crypto_policies cp
JOIN xdp_profiles p ON p.id = cp.profile_id
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50' AND cp.priority = 20;

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port)
SELECT cp.id, '192.168.182.1/32', 'ANY', '192.168.9.1/32', 'ANY'
FROM xdp_profile_crypto_policies cp
JOIN xdp_profiles p ON p.id = cp.profile_id
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50' AND cp.priority = 21;

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port)
SELECT cp.id, '192.168.182.1/32', 'ANY', '192.168.9.1/32', 'ANY'
FROM xdp_profile_crypto_policies cp
JOIN xdp_profiles p ON p.id = cp.profile_id
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_50_50' AND cp.priority = 22;
