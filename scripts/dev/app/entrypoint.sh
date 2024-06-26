#!/bin/bash

# if any of the commands in your code fails for any reason, the entire script fails
set -o errexit
# fail exit if one of your pipe command fails
set -o pipefail
# exits if any of your variables is not set
set -o nounset

# Postgres
postgres_ready() {
python << END
import sys

import psycopg

try:
    psycopg.connect(
        dbname="${DATABASE_NAME}",
        user="${DATABASE_USER}",
        password="${DATABASE_PASSWORD}",
        host="${DATABASE_HOST}",
        port="${DATABASE_PORT}",
    )
except psycopg.OperationalError:
    sys.exit(-1)
sys.exit(0)

END
}
until postgres_ready; do
    >&2 echo "Waiting for PostgreSQL to become available..."
    sleep 1
done
>&2 echo "PostgreSQL is available"

# RabbitMQ
if [ "$BROKER" = "rabbitmq" ]
then
    >&2 echo "Waiting for RabbitMQ to become available..."

    while ! nc -z $BROKER_HOST $BROKER_PORT; do
        sleep 0.1
    done

    >&2 echo "RabbitMQ started"
fi

exec "$@"
