Please confirm that your commit message(s) follow these guidelines:

1. First line is a commit title, a descriptive one-liner for the change
2. Empty second line
3. Commit message body that explains why the change is useful. Break lines that
   aren't something like a URL at 72-74 chars.
4. Empty line
5. Signed-off-by: Real Name <real@email.com>

Reminders:

1. If you modify struct thread_options, also make corresponding changes in
   cconv.c and bump FIO_SERVER_VER in server.h
2. If you change the ioengine interface (hooks, flags, etc), remember to bump
   FIO_IOOPS_VERSION in ioengines.h.
