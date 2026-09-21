-- Agentic AI - PostgreSQL init
-- Mounted by docker-compose.prod.yaml into /docker-entrypoint-initdb.d/.
-- The database itself is created by the POSTGRES_DB=agentic_ai env var;
-- add schema/seed statements here as the app grows.

CREATE EXTENSION IF NOT EXISTS pgcrypto;