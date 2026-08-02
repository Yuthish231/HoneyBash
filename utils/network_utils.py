from __future__ import annotations

import os
import sys
from argparse import ArgumentParser
from contextlib import contextmanager, suppress
from os import scandir
from pathlib import Path
from signal import SIGTERM
from socket import AF_INET, SOCK_STREAM, socket
from tempfile import _get_candidate_names, NamedTemporaryFile
from time import sleep, time
from typing import Any, Iterator

import psutil
from OpenSSL import crypto
from psutil import process_iter

# Re-export logger, storage, config utilities for backwards compatibility within package
from honeybash.config.config_manager import set_local_vars
from honeybash.logging.event_logger import (
    ComplexEncoder,
    CustomHandler,
    CustomHandlerFileRotate,
    logger,
    serialize_object,
    set_up_error_logging,
    setup_logger,
)
from honeybash.storage.storage_backends import PostgresClass, SqliteClass


def is_privileged():
    with suppress(Exception):
        return getattr(os, "getuid", lambda: -1)() == 0
    with suppress(Exception):
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return False


def clean_all():
    for entry in scandir("."):
        if entry.is_file() and entry.name.endswith("_server.py"):
            kill_servers(entry.name)


def kill_servers(name: str):
    with suppress(Exception):
        for process in process_iter():
            cmdline = " ".join(process.cmdline())
            if "--custom" in cmdline and name in cmdline:
                process.send_signal(SIGTERM)
                process.kill()


def get_free_port() -> int:
    port = 0
    with suppress(Exception):
        tcp = socket(AF_INET, SOCK_STREAM)
        tcp.bind(("", 0))
        _addr, port = tcp.getsockname()
        tcp.close()
    return port


def server_arguments():
    _server_parser = ArgumentParser(prog="HoneyBashServer")
    _server_parsergroupdeq = _server_parser.add_argument_group("Initialize Server")
    _server_parsergroupdeq.add_argument(
        "--ip",
        type=str,
        help="Change server ip, current is 0.0.0.0",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--port", type=int, help="Change port", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--username", type=str, help="Change username", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--password", type=str, help="Change password", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--resolver_addresses",
        type=str,
        help="Change resolver address",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--domain", type=str, help="A domain to test", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--folders",
        type=str,
        help="folders for smb as name:target,name:target",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--options", type=str, help="Extra options", metavar="", default=""
    )
    _server_parsergroupdes = _server_parser.add_argument_group("Sniffer options")
    _server_parsergroupdes.add_argument(
        "--filter", type=str, help="setup the Sniffer filter", required=False
    )
    _server_parsergroupdes.add_argument(
        "--interface", type=str, help="sniffer interface E.g eth0", required=False
    )
    _server_parsergroupdef = _server_parser.add_argument_group("Initialize Logging")
    _server_parsergroupdef.add_argument(
        "--config",
        type=str,
        help="config file for logs and database",
        required=False,
        default="",
    )
    _server_parsergroupdea = _server_parser.add_argument_group("Auto Configuration")
    _server_parsergroupdea.add_argument(
        "--docker", action="store_true", help="Run project in docker", required=False
    )
    _server_parsergroupdea.add_argument(
        "--aws", action="store_true", help="Run project in aws", required=False
    )
    _server_parsergroupdea.add_argument(
        "--test", action="store_true", help="Test current server", required=False
    )
    _server_parsergroupdea.add_argument(
        "--custom", action="store_true", help="Run custom server", required=False
    )
    _server_parsergroupdea.add_argument(
        "--auto",
        action="store_true",
        help="Run auto configured with random port",
        required=False,
    )
    _server_parsergroupdef.add_argument("--uuid", type=str, help="unique id", required=False)
    return _server_parser.parse_args()


@contextmanager
def create_certificate() -> Iterator[tuple[str, str]]:
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)
    certificate = crypto.X509()
    certificate.get_subject().C = "US"
    certificate.get_subject().ST = "OR"
    certificate.get_subject().L = "None"
    certificate.get_subject().O = "None"
    certificate.get_subject().OU = "None"
    certificate.get_subject().CN = next(_get_candidate_names())
    certificate.set_serial_number(0)
    before, after = (0, 60 * 60 * 24 * 365 * 2)
    certificate.gmtime_adj_notBefore(before)
    certificate.gmtime_adj_notAfter(after)
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(pk)
    certificate.sign(pk, "sha256")
    with NamedTemporaryFile(delete=False) as cert, NamedTemporaryFile(delete=False) as key:
        cert_name = cert.name
        key_name = key.name
        cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
        key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk))
        cert.close()
        key.close()
        try:
            yield cert_name, key_name
        finally:
            with suppress(Exception):
                os.unlink(cert_name)
                os.unlink(key_name)


def check_bytes(string: Any) -> str:
    if isinstance(string, bytes):
        return string.decode("utf-8", errors="replace")
    return str(string)


def load_template(filename: str) -> str:
    file_path = Path(__file__).parent.parent / "data" / filename
    return file_path.read_bytes()


def get_headers_and_ip_from_request(request, options):
    headers = {}
    client_ip = ""
    with suppress(Exception):
        for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
            headers.update({check_bytes(item): ",".join(map(check_bytes, value))})
        headers.update({"method": check_bytes(request.method)})
        headers.update({"uri": check_bytes(request.uri)})
    if "fix_get_client_ip" in options:
        with suppress(Exception):
            raw_headers = dict(request.requestHeaders.getAllRawHeaders())
            if b"X-Forwarded-For" in raw_headers:
                client_ip = check_bytes(raw_headers[b"X-Forwarded-For"][0])
            elif b"X-Real-IP" in raw_headers:
                client_ip = check_bytes(raw_headers[b"X-Real-IP"][0])
    if client_ip == "":
        client_ip = request.getClientAddress().host
    return client_ip, headers


def service_has_started(port: int) -> bool:
    try:
        wait_for_service(port)
        return True
    except TimeoutError:
        return False


def wait_for_service(port: int, interval: float = 0.1, timeout: float = 15.0):
    start_time = time()
    while True:
        if _service_runs(port):
            return
        sleep(interval)
        if time() - start_time > timeout:
            raise TimeoutError()


def _service_runs(port: int) -> bool:
    with suppress(Exception):
        for service in psutil.net_connections():
            laddr_port = getattr(getattr(service, "laddr", None), "port", None)
            status = getattr(service, "status", "")
            if laddr_port == port and status in ("LISTEN", "NONE"):
                return True
    with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
        s.settimeout(0.2)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            return True
    return False


@contextmanager
def hide_stderr():
    stderr = sys.stderr
    try:
        with Path(os.devnull).open("w") as devnull:
            sys.stderr = devnull
            yield
    finally:
        sys.stderr = stderr


__all__ = [
    "ComplexEncoder",
    "CustomHandler",
    "CustomHandlerFileRotate",
    "PostgresClass",
    "SqliteClass",
    "check_bytes",
    "clean_all",
    "create_certificate",
    "get_free_port",
    "get_headers_and_ip_from_request",
    "hide_stderr",
    "is_privileged",
    "kill_servers",
    "load_template",
    "logger",
    "serialize_object",
    "server_arguments",
    "service_has_started",
    "set_local_vars",
    "set_up_error_logging",
    "setup_logger",
    "wait_for_service",
]
