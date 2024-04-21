from django.core.management.base import BaseCommand

import environ
import psycopg2


class Command(BaseCommand):
    help = "Check if Postgres server is up and running."

    def handle(self, *args, **kwargs):
        # Load environment variables from os.environ
        env = environ.Env()

        postgres_host = env("DATABASE_HOST")
        postgres_port = env("DATABASE_PORT")
        postgres_dbname = env("DATABASE_NAME")
        postgres_user = env("DATABASE_USER")
        postgres_password = env("DATABASE_PASSWORD")

        try:
            psycopg2.connect(
                dbname=postgres_dbname,
                user=postgres_user,
                password=postgres_password,
                host=postgres_host,
                port=postgres_port,
            )
            self.stdout.write(self.style.SUCCESS("Postgres server is up and running."))
        except psycopg2.OperationalError:
            self.stdout.write(self.style.ERROR("Failed to connect to Postgres server."))
