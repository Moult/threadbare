-- Upgrade an existing database: add the indexes that keep lists of threads quick on a big forum.
-- $ sqlite3 threadbare.db < migrations/performance-indexes.sql
CREATE INDEX IF NOT EXISTS threads_ts_updated ON threads(ts_updated);
CREATE INDEX IF NOT EXISTS posts_thread_approved ON posts(thread_id, is_approved);
