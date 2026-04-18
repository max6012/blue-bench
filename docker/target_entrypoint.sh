#!/bin/sh
set -e

# Start sshd (background).
/usr/sbin/sshd

# Start nginx (background).
nginx

# Start python http on 8080 in foreground (keeps container alive).
cd /srv && exec python3 -m http.server 8080
