-- Upgrade an existing database: record who uploaded each file, so an account's files
-- can be removed with it. Files uploaded before this have no owner and are left alone.
-- $ sqlite3 threadbare.db < migrations/uploads.sql
CREATE TABLE IF NOT EXISTS "uploads" (
	"path"	TEXT NOT NULL UNIQUE,
	"user_id"	INTEGER NOT NULL,
	"ts_created"	INTEGER NOT NULL,
	PRIMARY KEY("path")
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
