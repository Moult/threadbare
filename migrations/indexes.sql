-- Upgrade an existing database: add the indexes now in db.sql.
-- $ sqlite3 threadbare.db < migrations/indexes.sql
CREATE INDEX IF NOT EXISTS posts_thread_id ON posts(thread_id);
CREATE INDEX IF NOT EXISTS posts_user_id ON posts(user_id);
CREATE INDEX IF NOT EXISTS votes_post_id ON votes(post_id);
