# Threadbare

Threadbare is a [frugal](https://idlewords.com/talks/website_obesity.htm) PHP + SQLite based forum.

Threadbare is:

 - Free software (AGPL-3.0-or-later)
 - A single PHP (i.e. easy to host) file about a thousand lines long with zero boilerplate or design patterns.
 - Uses SQLite. Unless you have a thousand new posts a day, you're not going to notice.
 - 100% works without [JavaScript](https://tonsky.me/blog/js-bloat/). Conservatively optionally enhanced with up to 70KB (before gzip) on the heaviest page.
 - Very semantic HTML. Best viewed in [elinks](https://thinkmoult.com/using-elinks-browse-web.html).
 - Heaviest page load in 25 milliseconds. 2ms if cached. Basically like a static website.
 - Opinionated. There are no settings.
 - Relies on SendGrid for email and hCaptcha / Akismet for bots.
 - Secure. I think. I hope. Let me know if it isn't.

Threadbare is not:

 - It isn't a fully featured forum. If you're looking for plugins, themes, and a hundred dials, this isn't it.
 - No logging and community metrics.
 - Non-hierarchical. It's just threads and posts. No categories or subcategories.
 - No private messages, profiles, or gamification. Take a deep breath. Enjoy the open-air prose.
 - Not tested. Let me know if you find any issues.

Features:

 - Threads! Posts! Add, edit, delete.
 - Kudos +1 or -1 on posts.
 - Coloured automatic avatar without images (unless you really want 25 extra HTTP requests to Gravatar on the homepage with leaked email hashes, eh?).
 - Decoupled UI with mustache. Have whatever theme you want I guess?
 - File uploads.
 - Live post preview.
 - Auto embed video links. Lazy load images.
 - Markdown formatting in posts.
 - Email notifications on new replies.
 - User mentions with tab autocomplete and email notifications.
 - Login, sign up, reset password, validation emails.
 - Captcha and Akismet.
 - Admins can edit / delete others and bypass rate limits. Trusted users bypass spam filters.
 - Aggressive caching for guests (using APCu cache).
 - Pagination.
 - Last read stats, views, last reply.

## Setup

Your PHP needs:

 - curl
 - SQLite
 - apcu\_cache

Set up dependencies, database, and website URL:

```
$ composer install
$ sqlite3 threadbare.db < db.sql
$ cp config.php.template config.php
$ vim config.php # Add your API keys
$ vim app.php # Edit http://localhost
$ vim www/style.css # Edit http://localhost
$ vim www/post.js # Edit http://localhost
```

Nginx:

```
server {
    listen       80;
    server_name  example.com;
    root         /path/to/threadbare/www;
    index index.html index.htm index.php;

    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        include fastcgi.conf;
    }

    location ~ ^/files/([a-zA-Z0-9/_-]+\.(jpg|jpeg|png|gif|pdf|txt|zip|ifc|webm|ogg|mp4))$ {
        alias /path/to/threadbare/uploads/$1;
        add_header Cache-Control "public, max-age=604800";
    }
}
```
