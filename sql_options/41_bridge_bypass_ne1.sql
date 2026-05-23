-- NE1 bridge: single bypass policy (cleartext), WAN without dst_ip.
-- Test path: 192.168.9.2 <-> 192.168.180.2 (reverse match also applies).

BEGIN;

DELETE FROM ne_policies WHERE profile_id = 41;
DELETE FROM ne_lan WHERE profile_id = 41;
DELETE FROM ne_wan WHERE profile_id = 41;
DELETE FROM ne_profiles WHERE id = 41;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    41, 'bridge_bypass_ne1',
    'Bridge bypass only: cleartext 9.2 <-> 180.2',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES (
    410, 41, 1, 'bypass', 'any',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['ANY']::text[],
    NULL, NULL, NULL, 'seed'
);

INSERT INTO ne_lan (interface, profile_id, created_by) VALUES
    ('enp5s0', 41, 'seed'),
    ('enp6s0', 41, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 41, NULL, 70, 'seed'),
    ('enp8s0', 41, NULL, 30, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
