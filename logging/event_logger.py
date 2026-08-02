from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import datetime
from json import JSONEncoder
import os
import sys
import importlib.util

_stdlib_dir = os.path.dirname(os.__file__)

if "logging" in sys.modules and hasattr(sys.modules["logging"], "DEBUG"):
    _stdlib_logging = sys.modules["logging"]
else:
    _spec = importlib.util.spec_from_file_location("logging", os.path.join(_stdlib_dir, "logging", "__init__.py"))
    _stdlib_logging = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_stdlib_logging)
    sys.modules["logging"] = _stdlib_logging

DEBUG = _stdlib_logging.DEBUG
Formatter = _stdlib_logging.Formatter
getLogger = _stdlib_logging.getLogger
Handler = _stdlib_logging.Handler
LogRecord = _stdlib_logging.LogRecord

if "logging.handlers" in sys.modules and hasattr(sys.modules["logging.handlers"], "RotatingFileHandler"):
    _stdlib_handlers = sys.modules["logging.handlers"]
else:
    _hspec = importlib.util.spec_from_file_location("logging.handlers", os.path.join(_stdlib_dir, "logging", "handlers.py"))
    _stdlib_handlers = importlib.util.module_from_spec(_hspec)
    _hspec.loader.exec_module(_stdlib_handlers)

RotatingFileHandler = _stdlib_handlers.RotatingFileHandler
SysLogHandler = _stdlib_handlers.SysLogHandler
from pathlib import Path
from sys import stdout
from tempfile import gettempdir
from typing import Any, MutableMapping
from urllib.parse import urlparse

from honeybash.storage.storage_backends import PostgresClass, SqliteClass


def set_up_error_logging():
    _logger = logging.getLogger("honeybash.error")
    if not _logger.handlers:
        _logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        _logger.addHandler(handler)
    return _logger


logger = set_up_error_logging()


def _serialize_message(
    record: LogRecord,
    custom_filter: dict | None,
) -> dict | str | None:
    try:
        if custom_filter:
            filters = custom_filter.get("honeypots", {})
            options = filters.get("options", [])
            if "remove_errors" in options and "error" in record.msg:
                return None
            if isinstance(record.msg, MutableMapping):
                if "remove_init" in options and record.msg.get("action") == "process":
                    return None
                if "remove_word_server" in options and "server" in record.msg:
                    record.msg["server"] = record.msg["server"].replace("_server", "")
                for old_key, new_key in filters.get("change", {}).items():
                    if old_key in record.msg:
                        record.msg[new_key] = record.msg.pop(old_key)
                for key in filters.get("remove", []):
                    record.msg.pop(key, None)
                if "contains" in filters and any(k not in record.msg for k in filters["contains"]):
                    return None
        if isinstance(record.msg, Mapping):
            return serialize_object({"timestamp": datetime.utcnow().isoformat(), **record.msg})
        return serialize_object(record.msg)
    except Exception as error:
        return serialize_object({"name": record.name, "error": repr(error)})


def _parse_record(record: LogRecord, custom_filter: dict | None, type_: str) -> LogRecord | None:
    serialized_msg = _serialize_message(record, custom_filter)
    if not serialized_msg:
        return None
    try:
        if type_ == "file":
            if custom_filter:
                options = custom_filter.get("honeypots", {}).get("options", [])
                if "dump_json_to_file" in options:
                    record.msg = json.dumps(serialized_msg, sort_keys=True, cls=ComplexEncoder)
        elif type_ == "db_postgres":
            pass
        elif type_ == "db_sqlite":
            for item in ["data", "error"]:
                if item in serialized_msg and not isinstance(serialized_msg[item], str):
                    serialized_msg[item] = repr(serialized_msg[item]).replace("\x00", " ")
        else:
            record.msg = json.dumps(serialized_msg, sort_keys=True, cls=ComplexEncoder)
    except Exception:
        pass
    return record


def setup_logger(name: str, temp_name: str, config: str | None, drop: bool = False):
    logs = "terminal"
    logs_location = ""
    config_data = {}
    custom_filter = None
    if config:
        try:
            config_data = json.loads(Path(config).read_text())
            logs = config_data.get("logs", logs)
            logs_location = config_data.get("logs_location", logs_location)
            custom_filter = config_data.get("custom_filter", custom_filter)
        except json.JSONDecodeError as error:
            logger.error(f"Could not parse config '{config}' as JSON: {error}")
        except OSError as error:
            logger.error(f"Could not read config file '{config}': {error}")

    logs_path = Path(logs_location) if logs_location else Path(gettempdir()) / "logs"
    logs_path.mkdir(parents=True, exist_ok=True)

    ret_logs_obj = getLogger(temp_name)
    ret_logs_obj.setLevel(DEBUG)
    if "db_postgres" in logs or "db_sqlite" in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter, config_data, drop))
    elif "terminal" in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter))
    if "file" in logs:
        server = name[1:].lower().replace("server", "")
        server_config = config_data.get("honeypots", {}).get(server, {})
        file_handler = CustomHandlerFileRotate(
            str(logs_path / server_config.get("log_file_name", temp_name)),
            logs=logs,
            custom_filter=custom_filter,
            maxBytes=server_config.get("max_bytes", 10000),
            backupCount=server_config.get("backup_count", 10),
        )
        ret_logs_obj.addHandler(file_handler)
    if "syslog" in logs:
        syslog_handler = _set_up_syslog_handler(
            config_data.get("syslog_address"),
            config_data.get("syslog_facility"),
        )
        if syslog_handler:
            ret_logs_obj.addHandler(syslog_handler)
    return ret_logs_obj


def _set_up_syslog_handler(address: str | None, facility: int | None) -> Handler | None:
    if not address:
        address = ("localhost", 514)
    else:
        url = urlparse(address)
        if not url.hostname or not url.port:
            logger.error(f"Could not parse syslog address '{address}': host or port not found")
            return None
        address = (url.hostname, url.port)
    handler = SysLogHandler(address=address, facility=facility)
    formatter = Formatter("[%(name)s] [%(levelname)s] - %(message)s")
    handler.setFormatter(formatter)
    return handler


class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        return repr(obj).replace("\x00", " ")


def serialize_object(obj: Any) -> dict | list | str:
    if isinstance(obj, Mapping):
        return {k: serialize_object(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_object(v) for v in obj]
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, bytes):
        obj = obj.decode("utf-8", "ignore")
    elif not isinstance(obj, str):
        obj = repr(obj)
    return obj.replace("\x00", " ")


class CustomHandlerFileRotate(RotatingFileHandler):
    def __init__(self, *args, logs="", custom_filter=None, **kwargs):
        self.logs = logs
        self.custom_filter = custom_filter
        super().__init__(*args, **kwargs)

    def emit(self, record):
        _record = _parse_record(record, self.custom_filter, "file")
        if _record:
            super().emit(_record)


class CustomHandler(Handler):
    def __init__(
        self,
        uuid: str = "",
        logs: str = "",
        custom_filter: dict | None = None,
        config: dict | None = None,
        drop: bool = False,
    ):
        self.db = {"db_postgres": None, "db_sqlite": None}
        self.logs = logs
        self.uuid = uuid
        self.custom_filter = custom_filter
        if config and "db_postgres" in self.logs:
            self.db["db_postgres"] = PostgresClass(
                path="postgresql://{}:{}@{}:{}".format(
                    config["postgres"]["username"],
                    config["postgres"]["password"],
                    config["postgres"]["hostname"],
                    config["postgres"]["port"],
                ),
                host=config["postgres"]["hostname"],
                port=config["postgres"]["port"],
                username=config["postgres"]["username"],
                password=config["postgres"]["password"],
                db=config["postgres"]["db"],
                uuid=self.uuid,
                drop=drop,
            )
        if config and "db_sqlite" in self.logs:
            self.db["db_sqlite"] = SqliteClass(
                file=config["sqlite_file"], drop=drop, uuid=self.uuid
            )
        super().__init__()

    def emit(self, record: LogRecord):
        try:
            if "db_postgres" in self.logs and self.db["db_postgres"]:
                if isinstance(record.msg, list):
                    if record.msg[0] in {"sniffer", "errors"}:
                        self.db["db_postgres"].insert_into_data_safe(
                            record.msg[0],
                            json.dumps(serialize_object(record.msg[1]), cls=ComplexEncoder),
                        )
                elif isinstance(record.msg, Mapping) and "server" in record.msg:
                    self.db["db_postgres"].insert_into_data_safe(
                        "servers",
                        json.dumps(serialize_object(record.msg), cls=ComplexEncoder),
                    )
            if "db_sqlite" in self.logs:
                _record = _parse_record(record, self.custom_filter, "db_sqlite")
                if _record:
                    self.db["db_sqlite"].insert_into_data_safe(_record.msg)
            if "terminal" in self.logs:
                _record = _parse_record(record, self.custom_filter, "terminal")
                if _record:
                    stdout.write(_record.msg + "\n")
            if "syslog" in self.logs:
                _record = _parse_record(record, self.custom_filter, "terminal")
                if _record:
                    stdout.write(_record.msg + "\n")
        except Exception as error:
            if (
                self.custom_filter is not None
                and "honeypots" in self.custom_filter
                and "remove_errors" in self.custom_filter["honeypots"].get("options", [])
            ):
                return
            log_entry = {"error": repr(error), "logger": repr(record)}
            stdout.write(f"{json.dumps(log_entry, sort_keys=True, cls=ComplexEncoder)}\n")
        stdout.flush()
