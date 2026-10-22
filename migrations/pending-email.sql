-- Upgrade an existing database: a changed email is held until the new address is confirmed.
-- $ sqlite3 threadbare.db < migrations/pending-email.sql
ALTER TABLE users ADD COLUMN "pending_email" TEXT;
ALTER TABLE users ADD COLUMN "pending_email_code" TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_pending_email_code ON users(pending_email_code);
