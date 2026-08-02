from __future__ import annotations

import logging
from contextlib import suppress
from pathlib import Path
from sqlite3 import connect as sqlite3_connect
from sys import stdout
from time import sleep

try:
    from psycopg import connect as psycopg_connect, sql
except ImportError:
    psycopg_connect = None
    sql = None

logger = logging.getLogger("honeybash.error")


class PostgresClass:
    def __init__(
        self,
        path=None,
        host=None,
        port=None,
        username=None,
        password=None,
        db=None,
        drop=False,
        uuid=None,
    ):
        self.path = path
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db
        self.uuid = uuid
        self.mapped_tables = ["errors", "servers", "sniffer", "system"]
        self.wait_until_up()
        if drop:
            self.con = psycopg_connect(conninfo=self.path, autocommit=True)
            self.cur = self.con.cursor()
            self.drop_db()
            self.drop_tables()
            self.create_db()
            self.con.close()
        else:
            self.con = psycopg_connect(conninfo=self.path, autocommit=True)
            self.cur = self.con.cursor()
            if not self.check_db_if_exists():
                self.create_db()
            self.con.close()
        self.con = psycopg_connect(conninfo=self.path + "/" + self.db, autocommit=True)
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            with suppress(Exception):
                logger.info(f"{self.uuid} - Waiting on postgres connection")
                stdout.flush()
                conn = psycopg_connect(conninfo=self.path + "?connect_timeout=1")
                conn.close()
                test = False
            sleep(1)
        logger.info(f"{self.uuid} - postgres connection is good")

    def addattr(self, x, val):
        self.__dict__[x] = val

    def check_db_if_exists(self):
        exists = False
        with suppress(Exception):
            self.cur.execute(
                "SELECT exists(SELECT 1 from pg_catalog.pg_database where datname = %s)",
                (self.db,),
            )
            if self.cur.fetchone()[0]:
                exists = True
        return exists

    def drop_db(self):
        with suppress(Exception):
            logger.warning(f"Dropping {self.db} db")
            if self.check_db_if_exists():
                self.cur.execute(
                    sql.SQL("drop DATABASE IF EXISTS {}").format(sql.Identifier(self.db))
                )
                sleep(2)
            self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))

    def create_db(self):
        logger.info("Creating PostgreSQL database")
        self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))

    def drop_tables(self):
        for x in self.mapped_tables:
            self.cur.execute(
                sql.SQL("drop TABLE IF EXISTS {}").format(sql.Identifier(x + "_table"))
            )

    def create_tables(self):
        for table in self.mapped_tables:
            self.cur.execute(
                sql.SQL(
                    "CREATE TABLE IF NOT EXISTS {} "
                    "(id SERIAL NOT NULL,date timestamp with time zone DEFAULT now(),data json)"
                ).format(sql.Identifier(table + "_table"))
            )

    def insert_into_data_safe(self, table, obj):
        with suppress(Exception):
            self.cur.execute(
                sql.SQL("INSERT INTO {} (id,date, data) VALUES (DEFAULT ,now(), %s)").format(
                    sql.Identifier(table + "_table")
                ),
                [obj],
            )


class SqliteClass:
    def __init__(self, file=None, drop=False, uuid=None):
        self.file = file
        self.uuid = uuid
        self.mapped_tables = ["servers"]
        self.servers_table_template = {
            "server": "servers_table",
            "action": None,
            "status": None,
            "src_ip": None,
            "src_port": None,
            "username": None,
            "password": None,
            "dest_ip": None,
            "dest_port": None,
            "data": None,
            "error": None,
        }
        self.wait_until_up()
        if drop:
            self.con = sqlite3_connect(
                self.file, timeout=1, isolation_level=None, check_same_thread=False
            )
            self.cur = self.con.cursor()
            self.drop_db()
            self.drop_tables()
            self.con.close()
        self.con = sqlite3_connect(
            self.file, timeout=1, isolation_level=None, check_same_thread=False
        )
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            with suppress(Exception):
                logger.info(f"{self.uuid} - Waiting on sqlite connection")
                conn = sqlite3_connect(self.file, timeout=1, check_same_thread=False)
                conn.close()
                test = False
            sleep(1)
        logger.info(f"{self.uuid} - sqlite connection is good")

    def drop_db(self):
        with suppress(Exception):
            file = Path(self.file)
            file.unlink(missing_ok=False)

    def drop_tables(self):
        with suppress(Exception):
            for table in self.mapped_tables:
                self.cur.execute(f"DROP TABLE IF EXISTS '{table:s}'")

    def create_tables(self):
        with suppress(Exception):
            self.cur.execute(
                "CREATE TABLE IF NOT EXISTS 'servers_table' (id INTEGER PRIMARY KEY,"
                "date DATETIME DEFAULT CURRENT_TIMESTAMP,server text, action text, "
                "status text, src_ip text, src_port text,dest_ip text, dest_port text, "
                "username text, password text, data text, error text)"
            )

    def insert_into_data_safe(self, obj):
        with suppress(Exception):
            parsed = {k: v for k, v in obj.items() if v is not None}
            dict_ = {**self.servers_table_template, **parsed}
            self.cur.execute(
                "INSERT INTO servers_table ("
                "server, action, status, src_ip, src_port, dest_ip, dest_port, username, "
                "password, data, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dict_["server"],
                    dict_["action"],
                    dict_["status"],
                    dict_["src_ip"],
                    dict_["src_port"],
                    dict_["dest_ip"],
                    dict_["dest_port"],
                    dict_["username"],
                    dict_["password"],
                    dict_["data"],
                    dict_["error"],
                ),
            )
