DELETE FROM xdp_profile_crypto_policy_matches
 WHERE policy_id IN (
     SELECT cp.id FROM xdp_profile_crypto_policies cp
     JOIN xdp_profiles p ON p.id = cp.profile_id
     WHERE p.config_id = 31);
DELETE FROM xdp_profile_crypto_policies
 WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_locals WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_wans   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profiles WHERE config_id = 31;
DELETE FROM xdp_local_configs WHERE config_id = 31;
DELETE FROM xdp_wan_configs   WHERE config_id = 31;
DELETE FROM xdp_configs       WHERE id = 31;
INSERT INTO xdp_configs (id) VALUES (31);
INSERT INTO xdp_local_configs (config_id, ifname) VALUES (31, 'enp5s0');
INSERT INTO xdp_wan_configs (config_id, ifname) VALUES (31, 'enp7s0');
INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES (
    31, 'ssh_port_demo', 1, 'Peer demo: ANY-22 port mirror.'
);
INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp5s0' FROM xdp_profiles p WHERE p.config_id = 31;
INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp7s0', 100 FROM xdp_profiles p WHERE p.config_id = 31;
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 501, p.id, 10, 'encrypt_l2', 'tcp', 'gcm', 128, 12,
       '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 31;
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 502, p.id, 10, 'encrypt_l2', 'tcp', 'gcm', 128, 12,
       '00112233445566778899aabbccddeeff'
FROM xdp_profiles p WHERE p.config_id = 31;
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
    (501, '192.168.9.2/32',   'ANY', '192.168.180.2/32', '22'),
    (502, '192.168.180.2/32', 'ANY', '192.168.9.2/32',   '22');
SELECT setval(
    pg_get_serial_sequence('xdp_profile_crypto_policies', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM xdp_profile_crypto_policies), 1),
    true);
