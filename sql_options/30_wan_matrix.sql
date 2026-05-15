-- Config 30: bonding + weighted WAN split. Stable policy_id (421 UDP, 422 TCP) + matches only; action=bypass
-- (no crypto_mode / aes / nonce / key in INSERT — unused). => no encrypt_* => crypto_enabled=0, plain forward.

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
(30, 'wan_enp7s0_enp8s0_70_30', 1, 'Bonding baseline: policy_id 421/422 bypass (id+matches only); crypto_enabled=0.');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp5s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, 'enp6s0'
FROM xdp_profiles p
WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp7s0', 70
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
SELECT p.id, 'enp8s0', 30
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_crypto_policies (id, profile_id, priority, action, protocol)
SELECT 421, p.id, 20, 'bypass', 'udp'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_crypto_policies (id, profile_id, priority, action, protocol)
SELECT 422, p.id, 20, 'bypass', 'tcp'
FROM xdp_profiles p WHERE p.config_id = 30 AND p.profile_name = 'wan_enp7s0_enp8s0_70_30';

INSERT INTO xdp_profile_crypto_policy_matches (policy_id, src_cidr, src_port, dst_cidr, dst_port) VALUES
(421, '192.168.9.2/32', 'ANY', '192.168.180.2/32', 'ANY'),
(422, '192.168.9.2/32', 'ANY', '192.168.180.2/32', 'ANY');

SELECT setval(
    pg_get_serial_sequence('xdp_profile_crypto_policies', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM xdp_profile_crypto_policies), 1),
    true);
