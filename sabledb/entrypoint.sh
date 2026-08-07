#!/bin/sh
set -eu

chown -R sabledb:sabledb /var/lib/sabledb
exec gosu sabledb "$@"
