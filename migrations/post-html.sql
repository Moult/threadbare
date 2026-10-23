-- Upgrade an existing database: posts keep their rendered HTML. Existing posts are rendered as they're next shown.
-- $ sqlite3 threadbare.db < migrations/post-html.sql
ALTER TABLE posts ADD COLUMN "html" TEXT;
