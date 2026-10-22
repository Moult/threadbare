-- Upgrade an existing database: posts by new users are held until an admin approves the user.
-- Users who have already posted are approved; accounts that never posted are treated as new.
-- $ sqlite3 threadbare.db < migrations/post-approval.sql
ALTER TABLE users ADD COLUMN "is_approved" INTEGER NOT NULL DEFAULT 0;
UPDATE users SET is_approved = 1 WHERE id IN (SELECT user_id FROM posts);
ALTER TABLE posts ADD COLUMN "is_approved" INTEGER NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS posts_pending ON posts(is_approved) WHERE is_approved = 0;
