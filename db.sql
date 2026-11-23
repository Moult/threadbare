CREATE TABLE "users" (
	"id"	INTEGER NOT NULL UNIQUE,
	"username"	TEXT NOT NULL UNIQUE,
	"password"	TEXT NOT NULL,
	"email"	TEXT NOT NULL UNIQUE,
	"is_verified"	INTEGER NOT NULL,
	"notifications"	INTEGER NOT NULL DEFAULT 1,
	"session_token"	TEXT,
	"bio"	TEXT,
	"pending_email"	TEXT,
	"pending_email_code"	TEXT UNIQUE,
	"pending_email_ts"	INTEGER,
	"is_approved"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "verifications" (
	"code"	TEXT NOT NULL UNIQUE,
	"user_id"	INTEGER NOT NULL,
	"purpose"	TEXT NOT NULL DEFAULT '',
	"ts_created"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("code")
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE TABLE "threads" (
	"id"	INTEGER NOT NULL UNIQUE,
	"title"	TEXT NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"last_user_id"	INTEGER,
	"ts_created"	INTEGER NOT NULL,
	"ts_updated"	INTEGER NOT NULL,
	"tags"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
    FOREIGN KEY("last_user_id") REFERENCES "users"("id") ON DELETE SET NULL
);

CREATE TABLE "posts" (
	"id"	INTEGER NOT NULL UNIQUE,
	"thread_id"	INTEGER NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"content"	TEXT NOT NULL,
	"html"	TEXT,
	"ts_created"	INTEGER NOT NULL,
	"ts_updated"	INTEGER NOT NULL,
	"is_approved"	INTEGER NOT NULL DEFAULT 1,
	PRIMARY KEY("id" AUTOINCREMENT)
    FOREIGN KEY("thread_id") REFERENCES "threads"("id") ON DELETE CASCADE,
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE TABLE "uploads" (
	"path"	TEXT NOT NULL UNIQUE,
	"user_id"	INTEGER NOT NULL,
	"ts_created"	INTEGER NOT NULL,
	PRIMARY KEY("path")
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE TABLE "thread_reads" (
	"user_id"	INTEGER NOT NULL,
	"thread_id"	INTEGER NOT NULL,
	"last_read_at"	INTEGER NOT NULL,
    PRIMARY KEY ("user_id", "thread_id")
);

CREATE TABLE votes (
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    value INTEGER NOT NULL CHECK(value IN (-1, 1)),
    PRIMARY KEY (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE INDEX posts_thread_id ON posts(thread_id);
CREATE INDEX posts_user_id ON posts(user_id);
CREATE INDEX votes_post_id ON votes(post_id);
CREATE INDEX posts_pending ON posts(is_approved) WHERE is_approved = 0;
CREATE INDEX threads_ts_updated ON threads(ts_updated);
CREATE INDEX posts_thread_approved ON posts(thread_id, is_approved);
CREATE INDEX users_username_lower ON users(LOWER(username));
CREATE INDEX votes_flags ON votes(post_id) WHERE value = -1;
