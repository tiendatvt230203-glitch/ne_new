BEGIN;

DELETE FROM ne_policies WHERE profile_id = 1;
DELETE FROM ne_lan WHERE profile_id = 1;
DELETE FROM ne_wan WHERE profile_id = 1;
DELETE FROM ne_profiles WHERE id = 1;

INSERT INTO ne_profiles (id, name, description, weight_enable, latency_enable, loss_enable, created_by)
VALUES (1, 'Profile-IP-Minimal', 'Minimal NE-IP profile', FALSE, FALSE, FALSE, 'seed');

INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, invert_src_ip, dst_ip, invert_dst_ip,
    src_port, dst_port, method, nonce, encryption_key, created_by
) VALUES (
    100, 1, 10, 'L3', 'tcp',
    ARRAY['192.168.1.0/24']::text[], FALSE,
    ARRAY['10.0.0.0/8']::text[], FALSE,
    NULL, NULL,
    'aes-gcm-128', 12,
    '00112233445566778899aabbccddeeff',
    'seed'
);

INSERT INTO ne_lan (interface, profile_id, created_by) VALUES ('eth0', 1, 'seed');

INSERT INTO ne_wan (interface, profile_id, dst_ip, weight, created_by) VALUES
    ('wan0', 1, '203.0.113.1', 100, 'seed');

SELECT setval(pg_get_serial_sequence('ne_profiles', 'id')::regclass,
    COALESCE((SELECT MAX(id) FROM ne_profiles), 1), true);

COMMIT;
