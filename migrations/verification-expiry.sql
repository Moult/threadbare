-- Upgrade an existing database: verification codes now record their purpose and age.
-- Codes issued before the upgrade stop working; users can request a new email.
-- $ sqlite3 threadbare.db < migrations/verification-expiry.sql
ALTER TABLE verifications ADD COLUMN "purpose" TEXT NOT NULL DEFAULT '';
ALTER TABLE verifications ADD COLUMN "ts_created" INTEGER NOT NULL DEFAULT 0;
