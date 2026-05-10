DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profiles                WHERE config_id = 31;

DELETE FROM xdp_local_configs WHERE config_id = 31;
DELETE FROM xdp_wan_configs   WHERE config_id = 31;
DELETE FROM xdp_configs       WHERE id = 31;

INSERT INTO xdp_configs (id) VALUES (31);

INSERT INTO xdp_local_configs (config_id, ifname) VALUES
(31, 'eno2');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(31, 'enp4s0', '192.168.11.1/32'),
(31, 'enp5s0', '192.168.131.1/32');

INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES
(31, 'wan_enp4s0_enp5s0_70_30', 1, 'peer symmetric');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'eno2'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp4s0', 70
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp5s0', 30
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 399, p.id, 50, 'bypass', 'UDP', 'gcm', 128, 12, '00000000000000000000000000000000'
FROM xdp_profiles p WHERE p.config_id = 31;

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 400, p.id, 100, 'encrypt_l4', 'TCP', 'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 401, p.id, 101, 'encrypt_l4', 'TCP', 'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 402, p.id, 102, 'encrypt_l4', 'TCP', 'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 403, p.id, 110, 'encrypt_l4', 'UDP', 'gcm', 128, 12, '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 404, p.id, 111, 'encrypt_l4', 'UDP', 'ctr', 128, 12, 'fedcba9876543210fedcba9876543210'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 405, p.id, 112, 'encrypt_l4', 'UDP', 'gcm', 128, 12, '0123456789abcdef0123456789abcdef'
FROM xdp_profiles p WHERE p.config_id = 31 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(399, 'ANY', 'Any', 'ANY', '5203'),
(399, 'ANY', '5203', 'ANY', 'Any'),
(400, '192.168.180.2/32', 'Any', '192.168.10.2/32', '443'),
(401, '192.168.180.2/32', 'Any', '192.168.10.2/32', '22'),
(402, '192.168.180.2/32', 'Any', '192.168.10.2/32', '8080'),
(403, '192.168.180.2/32', 'Any', '192.168.10.2/32', '53'),
(404, '192.168.180.2/32', 'Any', '192.168.10.2/32', '6009'),
(405, '192.168.180.2/32', 'Any', '192.168.10.2/32', '123');
