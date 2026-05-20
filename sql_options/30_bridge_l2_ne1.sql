-- NE1 bridge: WAN without dst_ip (transparent L2), MAC learn on LAN.
-- Policy CIDRs are client/firewall IPs beyond the bridge (not SEP interface IPs).

BEGIN;

DELETE FROM ne_policies WHERE profile_id = 30;
DELETE FROM ne_lan WHERE profile_id = 30;
DELETE FROM ne_wan WHERE profile_id = 30;
DELETE FROM ne_profiles WHERE id = 30;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    30, 'bridge_l2_ne1',
    'Bridge L2: UDP any-any; SSH 9.2->180.2 ANY->22; peer 180.2->9.2 22->ANY on NE2',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES
(
    421, 30, 20, 'L2', 'udp',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['ANY']::text[],
    'aes-gcm-128', 12, '00112233445566778899aabbccddeeff', 'seed'
),
(
    422, 30, 10, 'L2', 'tcp',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.180.2/32']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['22']::text[],
    'aes-gcm-128', 12, '00112233445566778899aabbccddeeff', 'seed'
);

INSERT INTO ne_lan (interface, profile_id, created_by) VALUES
    ('enp5s0', 30, 'seed'),
    ('enp6s0', 30, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 30, NULL, 70, 'seed'),
    ('enp8s0', 30, NULL, 30, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
