-- NE1: bypass only, 2 VLAN LANs, shared WAN bonding (profile 40).
--   enp7s0.9   192.168.9.2   -> 192.168.182.2
--   enp7s0.10  192.168.10.2  -> 192.168.180.2

BEGIN;

DELETE FROM ne_policies WHERE profile_id = 40;
DELETE FROM ne_lan WHERE profile_id = 40;
DELETE FROM ne_wan WHERE profile_id = 40;
DELETE FROM ne_profiles WHERE id = 40;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    40,
    'bypass_bond_dual_vlan',
    'Bypass VLAN9+VLAN10, WAN weight bonding only',
    TRUE,
    FALSE,
    FALSE,
    'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES
(
    50, 40, 1, 'bypass', NULL,
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.182.2/32']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['ANY']::text[],
    NULL, NULL, NULL,
    'seed'
),
(
    52, 40, 2, 'bypass', NULL,
    ARRAY['192.168.10.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['ANY']::text[],
    NULL, NULL, NULL,
    'seed'
);

INSERT INTO ne_lan (interface, profile_id, created_by) VALUES
    ('enp7s0.9', 40, 'seed'),
    ('enp7s0.10', 40, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp4s0', 40, '192.168.11.2', 50, 'seed'),
    ('enp5s0', 40, '192.168.131.2', 50, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
