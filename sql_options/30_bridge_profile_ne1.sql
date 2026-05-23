-- NE1 bridge profile 30: multi-layer demo (top-down SST 1..4).
--   1 L2 UDP 7002   9.2 -> 182.2
--   2 L3 TCP 7003   9.2 -> 182.2
--   3 L4 UDP 7004   9.2 -> 182.2
--   4 bypass any    (plaintext fallback, SST last)

BEGIN;

DELETE FROM ne_policies WHERE profile_id = 30;
DELETE FROM ne_lan WHERE profile_id = 30;
DELETE FROM ne_wan WHERE profile_id = 30;
DELETE FROM ne_profiles WHERE id = 30;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (
    30, 'profile30',
    'L2 UDP 7002, L3 TCP 7003, L4 UDP 7004, bypass any',
    TRUE, FALSE, FALSE, 'seed'
);

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES
(
    301, 30, 1, 'L2', 'udp',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.182.2/32']::text[], FALSE,
    ARRAY['7002']::text[], ARRAY['7002']::text[],
    'aes-gcm-128', 12, '87e3855f04321a1a7c661a283570b5bd', 'seed'
),
(
    302, 30, 2, 'L3', 'tcp',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.182.2/32']::text[], FALSE,
    ARRAY['7003']::text[], ARRAY['7003']::text[],
    'aes-gcm-128', 12, '87e3855f04321a1a7c661a283570b5bd', 'seed'
),
(
    303, 30, 3, 'L4', 'udp',
    ARRAY['192.168.9.2/32']::text[], FALSE,
    ARRAY['192.168.182.2/32']::text[], FALSE,
    ARRAY['7004']::text[], ARRAY['7004']::text[],
    'aes-gcm-128', 12, '87e3855f04321a1a7c661a283570b5bd', 'seed'
),
(
    304, 30, 4, 'bypass', 'any',
    ARRAY['ANY']::text[], FALSE,
    ARRAY['ANY']::text[], FALSE,
    ARRAY['ANY']::text[], ARRAY['ANY']::text[],
    NULL, NULL, NULL, 'seed'
);

INSERT INTO ne_lan (interface, profile_id, created_by) VALUES
    ('enp5s0', 30, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('enp7s0', 30, NULL, 50, 'seed'),
    ('enp8s0', 30, NULL, 50, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
