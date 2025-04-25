CREATE TABLE "users" (
	"id"	INTEGER NOT NULL UNIQUE,
	"username"	TEXT NOT NULL UNIQUE,
	"password"	TEXT NOT NULL,
	"email"	TEXT NOT NULL UNIQUE,
	"is_verified"	INTEGER NOT NULL,
	"notifications"	INTEGER NOT NULL DEFAULT 1,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "verifications" (
	"code"	TEXT NOT NULL UNIQUE,
	"user_id"	INTEGER NOT NULL,
	PRIMARY KEY("code")
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE TABLE "threads" (
	"id"	INTEGER NOT NULL UNIQUE,
	"title"	TEXT NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"ts_created"	INTEGER NOT NULL,
	"ts_updated"	INTEGER NOT NULL,
    "views"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT)
    FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE TABLE "posts" (
	"id"	INTEGER NOT NULL UNIQUE,
	"thread_id"	INTEGER NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"content"	TEXT NOT NULL,
	"ts_created"	INTEGER NOT NULL,
	"ts_updated"	INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
    FOREIGN KEY("thread_id") REFERENCES "threads"("id") ON DELETE CASCADE,
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
