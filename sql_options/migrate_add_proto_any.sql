-- Existing DB (already has encryption_protocol_enum): add literal 'any'.
-- Run once: psql ... -f sql_options/migrate_add_proto_any.sql
-- Fresh install via schema.sql already includes 'any'.

DO $$ BEGIN
    ALTER TYPE encryption_protocol_enum ADD VALUE 'any';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

UPDATE ne_policies SET proto = 'any' WHERE proto IS NULL;
