DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profiles WHERE config_id = 30;

DELETE FROM xdp_local_configs WHERE config_id = 30;
DELETE FROM xdp_wan_configs   WHERE config_id = 30;
DELETE FROM xdp_configs       WHERE id = 30;

INSERT INTO xdp_configs (id) VALUES (30);

INSERT INTO xdp_local_configs (config_id, ifname) VALUES
(30, 'eno2'),
(30, 'eno3');

INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip) VALUES
(30, 'enp4s0', '192.168.11.2/32'),
(30, 'enp5s0', '192.168.131.2/32');

INSERT INTO xdp_profiles (config_id, profile_name, enabled, description) VALUES
(30, 'wan_enp4s0_enp5s0_70_30', 1, '');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'eno2'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'eno3'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp4s0', 70
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp5s0', 30
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 420, p.id, 10, 'bypass', 'ANY', 'gcm', 128, 12, '00000000000000000000000000000000'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 421, p.id, 20, 'encrypt_l2', 'ANY', 'gcm', 128, 12, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 422, p.id, 21, 'encrypt_l3', 'ANY', 'gcm', 128, 12, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT 423, p.id, 22, 'encrypt_l4', 'ANY', 'gcm', 128, 12, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp4s0_enp5s0_70_30';

-- Site A (WAN next-hop .2): rows list src = local LAN hosts (192.168.9.x / 10.x), dst = peer (180.x / 182.x).
-- CRYPTO_POLICY_MATCH_IP_ONLY + code also tries reversed tuple; WAN decrypt uses embedded policy id, not these IPs.
INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(421, '192.168.9.2/32',  'ANY', '192.168.180.2/32', 'ANY'),
(422, '192.168.10.2/32', 'ANY', '192.168.182.2/32', 'ANY'),
(423, '192.168.9.2/32',  'ANY', '192.168.182.2/32', 'ANY'),
(420, '192.168.10.2/32', 'ANY', '192.168.180.2/32', 'ANY');
