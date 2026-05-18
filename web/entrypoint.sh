#!/bin/sh
set -e

# Entrypoint now uses the Node.js server implementation.
# The Node server handles regeneration and file watching (chokidar).
exec npm start
