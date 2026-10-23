-- Upgrade an existing database: add the indexes that keep a big forum quick.
-- $ sqlite3 threadbare.db < migrations/performance-indexes.sql
CREATE INDEX IF NOT EXISTS threads_ts_updated ON threads(ts_updated);
CREATE INDEX IF NOT EXISTS posts_thread_approved ON posts(thread_id, is_approved);
CREATE INDEX IF NOT EXISTS users_username_lower ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS votes_flags ON votes(post_id) WHERE value = -1;
