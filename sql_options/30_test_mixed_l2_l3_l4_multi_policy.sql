DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profiles                WHERE config_id = 30;

DELETE FROM xdp_local_configs WHERE config_id = 30;
DELETE FROM xdp_wan_configs   WHERE config_id = 30;
DELETE FROM xdp_configs       WHERE id = 30;

INSERT INTO xdp_configs (id) VALUES (30);

INSERT INTO xdp_local_configs (config_id, ifname) VALUES
(30, 'enp7s0');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(30, 'enp6s0', '192.168.203.2/32');

INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES
(30, 'wan_enp6s0_single', 1, '');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp7s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp6s0', 100
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

/* Bypass UDP 5203 — một policy / profile, priority thấp hơn encrypt để áp trước */
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 299, p.id, 50, 'bypass', 'UDP', 'gcm', 128, 12, '00000000000000000000000000000000'
FROM xdp_profiles p WHERE p.config_id = 30;

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 300, p.id, 100, 'encrypt_l4', 'TCP', 'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 301, p.id, 101, 'encrypt_l4', 'TCP', 'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 302, p.id, 102, 'encrypt_l4', 'TCP', 'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 303, p.id, 110, 'encrypt_l4', 'UDP', 'gcm', 128, 12, '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 304, p.id, 111, 'encrypt_l4', 'UDP', 'ctr', 128, 12, 'fedcba9876543210fedcba9876543210'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 305, p.id, 112, 'encrypt_l4', 'UDP', 'gcm', 128, 12, '0123456789abcdef0123456789abcdef'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp6s0_single';

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(299, 'ANY', 'Any', 'ANY', '5203'),
(299, 'ANY', '5203', 'ANY', 'Any'),
(300, '192.168.9.2/32', 'Any', '192.168.182.2/32', '443'),
(301, '192.168.9.2/32', 'Any', '192.168.182.2/32', '22'),
(302, '192.168.9.2/32', 'Any', '192.168.182.2/32', '8080'),
(303, '192.168.9.2/32', 'Any', '192.168.182.2/32', '53'),
(304, '192.168.9.2/32', 'Any', '192.168.182.2/32', '6009'),
(305, '192.168.9.2/32', 'Any', '192.168.182.2/32', '123');
