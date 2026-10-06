-- Test fixture for the iron-proxy postgres integration tests.
--
-- Sets up two non-superuser roles and an `items` table with row-level
-- security scoped by `current_role`. The proxy is configured to SET ROLE
-- tenant_role at session start; once that happens the upstream user
-- (a superuser, which would normally bypass RLS) is replaced for permission
-- checks by tenant_role (no BYPASSRLS), and the RLS policy applies.
--
-- The test asserts that a client connecting through the proxy can only
-- read/write its own rows — the actual point of building this feature.

CREATE ROLE tenant_role;
CREATE ROLE other_role;

CREATE TABLE items (
  id    serial PRIMARY KEY,
  owner text NOT NULL,
  data  text NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON items TO tenant_role, other_role;
GRANT USAGE ON SEQUENCE items_id_seq TO tenant_role, other_role;

ALTER TABLE items ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_items ON items
  FOR ALL
  USING      (owner = current_role)
  WITH CHECK (owner = current_role);

INSERT INTO items (owner, data) VALUES
  ('tenant_role', 'mine-1'),
  ('tenant_role', 'mine-2'),
  ('other_role',  'theirs-1'),
  ('other_role',  'theirs-2'),
  ('other_role',  'theirs-3');

-- A second database so the multi-upstream test can route to two distinct
-- databases. The proxy requires each upstream's routing database to match the
-- database its DSN connects to, so testing more than one upstream needs more
-- than one real database. Roles are cluster-global, so tenant_role/other_role
-- are usable here too.
CREATE DATABASE otherdb;
