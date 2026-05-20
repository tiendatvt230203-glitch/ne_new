DELETE FROM xdp_profile_crypto_policy_matches
 WHERE policy_id IN (
     SELECT cp.id FROM xdp_profile_crypto_policies cp
     JOIN xdp_profiles p ON p.id = cp.profile_id
     WHERE p.config_id = 30);
DELETE FROM xdp_profile_crypto_policies
 WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
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
INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES (
    30,
    'bridge_enp7_enp8_70_30',
    1,
    'Bridge L2: 421 UDP any-any; 422 C1->C2 SSH 22-ANY; 423 C2->C1 SSH 22-ANY.'
);
INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, l.ifname
FROM xdp_profiles p
JOIN xdp_local_configs l ON l.config_id = p.config_id
WHERE p.config_id = 30 AND p.profile_name = 'bridge_enp7_enp8_70_30';
INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent) VALUES
    ((SELECT id FROM xdp_profiles WHERE config_id = 30 AND profile_name = 'bridge_enp7_enp8_70_30'),
     'enp7s0', 70),
    ((SELECT id FROM xdp_profiles WHERE config_id = 30 AND profile_name = 'bridge_enp7_enp8_70_30'),
     'enp8s0', 30);
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 421, p.id, 20, 'encrypt_l2', 'udp', 'gcm', 128, 12,
       '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'bridge_enp7_enp8_70_30';
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 422, p.id, 10, 'encrypt_l2', 'tcp', 'gcm', 128, 12,
       '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'bridge_enp7_enp8_70_30';
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 423, p.id, 10, 'encrypt_l2', 'tcp', 'gcm', 128, 12,
       '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'bridge_enp7_enp8_70_30';
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
    (421, '192.168.9.2/32',   'ANY', '192.168.180.2/32', 'ANY');
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
    (422, '192.168.9.2/32',   '22',  '192.168.180.2/32', 'ANY');
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
    (423, '192.168.180.2/32', '22',  '192.168.9.2/32',   'ANY');
SELECT setval(
    pg_get_serial_sequence('xdp_profile_crypto_policies', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM xdp_profile_crypto_policies), 1),
    true);
