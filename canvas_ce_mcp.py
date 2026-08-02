from __future__ import annotations

import argparse
import asyncio
import atexit
import ipaddress
import logging
import os
import socket
import struct
import sys
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.utilities.logging import configure_logging, get_logger


CMD_GETVERSION = 0
CMD_OPENPROCESS = 3
CMD_CREATETOOLHELP32SNAPSHOT = 4
CMD_PROCESS32FIRST = 5
CMD_PROCESS32NEXT = 6
CMD_CLOSEHANDLE = 7
CMD_READPROCESSMEMORY = 9
CMD_CREATETOOLHELP32SNAPSHOTEX = 35
CMD_VIRTUALQUERYEXFULL = 31
CMD_AOBSCAN = 200

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
ALL_ACCESSIBLE_PROTECTIONS = (
    PAGE_READONLY
    | PAGE_READWRITE
    | PAGE_WRITECOPY
    | PAGE_EXECUTE
    | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE
)

MAX_READ_SIZE = 64 * 1024
MAX_REGION_COUNT = 250_000
MAX_MODULE_COUNT = 32_768
MAX_PROCESS_COUNT = 65_536
MAX_AOB_PATTERN_SIZE = 1024
MAX_AOB_SCAN_SPAN = 512 * 1024 * 1024
MAX_AOB_RESULTS = 4096
CESERVER_DISCOVERY_PORT = 3296

PROCESS_ENTRY = struct.Struct("<iii")
MODULE_ENTRY = struct.Struct("<iqiiIi")
REGION_INFO = struct.Struct("<QQII")
LOGGER = get_logger("canvas_ce_mcp")


def _configure_console_colors() -> bool:
    if os.name != "nt":
        return sys.stderr.isatty()
    try:
        import ctypes
        import msvcrt
    except ImportError:
        return False
    enabled = False
    for stream in (sys.stdout, sys.stderr):
        try:
            handle = msvcrt.get_osfhandle(stream.fileno())
            mode = ctypes.c_ulong()
            if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                if ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                    enabled = True
        except (OSError, ValueError):
            pass
    return enabled


def _configure_console_logging(level: int) -> None:
    configure_logging(level=level)
    handlers = list(logging.getLogger("fastmcp").handlers)
    root_logger = logging.getLogger()
    root_logger.handlers = handlers
    root_logger.setLevel(level)
    for name in ("mcp", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(level)


def _configure_event_loop() -> None:
    if os.name == "nt":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@dataclass(frozen=True)
class BridgeConfig:
    host: str
    port: int
    timeout: float
    broadcast: str = "auto"


class CEServerError(RuntimeError):
    pass


def discover_canvas_servers(
    timeout_seconds: float = 2.0,
    broadcast_address: str = "auto",
) -> list[dict[str, Any]]:
    if not 0.1 <= timeout_seconds <= 10.0:
        raise ValueError("timeout_seconds must be between 0.1 and 10")
    checksum = 0x13579BDF
    expected_checksum = (checksum * 0xCE) & 0xFFFFFFFF
    request = struct.pack("<IH", checksum, 0)
    found: dict[tuple[str, int], dict[str, Any]] = {}
    targets = {"255.255.255.255"}
    if broadcast_address.casefold() != "auto":
        targets = {broadcast_address}
    else:
        try:
            local_addresses = socket.gethostbyname_ex(socket.gethostname())[2]
        except OSError:
            local_addresses = []
        for address in local_addresses:
            try:
                parsed = ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError:
                continue
            if parsed.is_loopback or parsed.is_unspecified:
                continue
            network = ipaddress.IPv4Network(f"{address}/24", strict=False)
            targets.add(str(network.broadcast_address))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout_seconds)
        sock.bind(("", 0))
        sent = False
        for target in sorted(targets):
            try:
                sock.sendto(request, (target, CESERVER_DISCOVERY_PORT))
                sent = True
            except OSError:
                continue
        if not sent:
            raise CEServerError("Unable to send a CEServer discovery packet")
        while True:
            try:
                response, sender = sock.recvfrom(64)
            except socket.timeout:
                break
            if len(response) != 6:
                continue
            response_checksum, port = struct.unpack("<IH", response)
            if response_checksum != expected_checksum or not 1 <= port <= 65535:
                continue
            key = (sender[0], port)
            found[key] = {"host": sender[0], "port": port}
    finally:
        sock.close()
    return sorted(found.values(), key=lambda item: (item["host"], item["port"]))


def _parse_address(value: str | int) -> int:
    if isinstance(value, int):
        result = value
    else:
        text = value.strip().replace("_", "")
        if not text:
            raise ValueError("Address must not be empty")
        result = int(text, 0)
    if not 0 <= result <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Address is outside uint64: {value!r}")
    return result


def _decode_name(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").rstrip("\x00")


def _protection_name(value: int) -> str:
    names = {
        PAGE_NOACCESS: "NOACCESS",
        PAGE_READONLY: "R",
        PAGE_READWRITE: "RW",
        PAGE_WRITECOPY: "WRITECOPY",
        PAGE_EXECUTE: "X",
        PAGE_EXECUTE_READ: "RX",
        PAGE_EXECUTE_READWRITE: "RWX",
    }
    return names.get(value, f"0x{value:X}")


class CEServerConnection(AbstractContextManager["CEServerConnection"]):
    def __init__(self, config: BridgeConfig):
        self._config = config
        self._socket: socket.socket | None = None
        self._resolved_host = config.host
        self._resolved_port = config.port

    def _discover_endpoint(self) -> None:
        servers: dict[tuple[str, int], dict[str, Any]] = {}
        for _ in range(3):
            for server in discover_canvas_servers(
                timeout_seconds=min(self._config.timeout, 2.0),
                broadcast_address=self._config.broadcast,
            ):
                if server["port"] == self._config.port:
                    servers[(server["host"], server["port"])] = server
            if servers:
                break
        if not servers:
            raise CEServerError(
                "Canvas CEServer was not discovered on the local Wi-Fi. "
                "Check that Canvas Cheat Engine Server is enabled and that "
                "client isolation is disabled on the access point."
            )
        if len(servers) > 1:
            addresses = ", ".join(f"{host}:{port}" for host, port in servers)
            raise CEServerError(
                f"Multiple Canvas CEServers were discovered: {addresses}. "
                "Set --host explicitly to select one device."
            )
        self._resolved_host, self._resolved_port = next(iter(servers))
        LOGGER.info(
            "Discovered Canvas CEServer at %s:%d",
            self._resolved_host,
            self._resolved_port,
        )

    def _connect(self) -> None:
        self._socket = socket.create_connection(
            (self._resolved_host, self._resolved_port),
            timeout=self._config.timeout,
        )
        self._socket.settimeout(self._config.timeout)
        LOGGER.info(
            "Connected to Canvas CEServer at %s:%d",
            self._resolved_host,
            self._resolved_port,
        )

    def __enter__(self) -> "CEServerConnection":
        if self._config.host.casefold() == "auto":
            self._discover_endpoint()
        try:
            self._connect()
        except OSError as exc:
            raise CEServerError(
                f"Cannot connect to Canvas ceserver at "
                f"{self._resolved_host}:{self._resolved_port}: {exc}."
            ) from exc
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._socket is not None:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._socket.close()
            self._socket = None
            LOGGER.info("Disconnected from Canvas CEServer")

    @property
    def socket(self) -> socket.socket:
        if self._socket is None:
            raise CEServerError("CEServer connection is not open")
        return self._socket

    def send(self, data: bytes) -> None:
        try:
            self.socket.sendall(data)
        except OSError as exc:
            raise CEServerError(f"CEServer send failed: {exc}") from exc

    def recv_exact(self, size: int) -> bytes:
        if size < 0:
            raise CEServerError(f"Negative receive size: {size}")
        data = bytearray()
        try:
            while len(data) < size:
                chunk = self.socket.recv(size - len(data))
                if not chunk:
                    raise CEServerError(
                        f"CEServer disconnected after {len(data)} of {size} bytes"
                    )
                data.extend(chunk)
        except socket.timeout as exc:
            raise CEServerError(
                f"CEServer response timed out after {self._config.timeout:.1f}s"
            ) from exc
        except OSError as exc:
            raise CEServerError(f"CEServer receive failed: {exc}") from exc
        return bytes(data)

    def server_info(self) -> dict[str, Any]:
        self.send(bytes((CMD_GETVERSION,)))
        version, text_size = struct.unpack("<iB", self.recv_exact(5))
        if text_size > 240:
            raise CEServerError(f"Invalid CEServer banner size: {text_size}")
        banner = _decode_name(self.recv_exact(text_size))
        return {
            "host": self._resolved_host,
            "port": self._resolved_port,
            "protocol_version": version,
            "banner": banner,
            "expected_canvas_protocol_version": 6,
            "compatible": version == 6 and "CHEATENGINE" in banner.upper(),
        }

    def close_handle(self, handle: int) -> None:
        if handle == 0:
            return
        self.send(bytes((CMD_CLOSEHANDLE,)) + struct.pack("<I", handle))
        result = struct.unpack("<i", self.recv_exact(4))[0]
        if result == 0:
            raise CEServerError(f"CEServer failed to close handle {handle}")

    def close_handle_best_effort(self, handle: int) -> None:
        try:
            self.close_handle(handle)
        except CEServerError:
            pass

    def create_snapshot(self, flags: int, pid: int = 0) -> int:
        self.send(
            bytes((CMD_CREATETOOLHELP32SNAPSHOT,))
            + struct.pack("<II", flags, pid)
        )
        return struct.unpack("<I", self.recv_exact(4))[0]

    def list_processes(self) -> list[dict[str, Any]]:
        snapshot = self.create_snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == 0:
            raise CEServerError("CreateToolhelp32Snapshot(processes) returned 0")
        processes: list[dict[str, Any]] = []
        try:
            command = CMD_PROCESS32FIRST
            while len(processes) < MAX_PROCESS_COUNT:
                self.send(bytes((command,)) + struct.pack("<I", snapshot))
                result, pid, name_size = PROCESS_ENTRY.unpack(
                    self.recv_exact(PROCESS_ENTRY.size)
                )
                if not result:
                    break
                if not 0 <= name_size <= 64 * 1024:
                    raise CEServerError(f"Invalid process name size: {name_size}")
                name = _decode_name(self.recv_exact(name_size))
                processes.append({"pid": pid, "name": name})
                command = CMD_PROCESS32NEXT
            else:
                raise CEServerError(
                    f"Process list exceeded safety limit {MAX_PROCESS_COUNT}"
                )
        finally:
            self.close_handle_best_effort(snapshot)
        return processes

    def open_process(self, pid: int) -> int:
        if pid <= 0 or pid > 0x7FFFFFFF:
            raise ValueError(f"Invalid PID: {pid}")
        self.send(bytes((CMD_OPENPROCESS,)) + struct.pack("<i", pid))
        handle = struct.unpack("<I", self.recv_exact(4))[0]
        if handle == 0:
            raise CEServerError(f"CEServer could not open PID {pid}")
        return handle

    def list_modules(self, pid: int) -> list[dict[str, Any]]:
        self.send(
            bytes((CMD_CREATETOOLHELP32SNAPSHOTEX,))
            + struct.pack("<II", TH32CS_SNAPMODULE, pid)
        )
        modules: list[dict[str, Any]] = []
        while len(modules) < MAX_MODULE_COUNT:
            result, base, part, size, file_offset, name_size = MODULE_ENTRY.unpack(
                self.recv_exact(MODULE_ENTRY.size)
            )
            if not result:
                break
            if not 0 <= name_size <= 64 * 1024:
                raise CEServerError(f"Invalid module name size: {name_size}")
            name = _decode_name(self.recv_exact(name_size))
            modules.append(
                {
                    "name": name,
                    "base": f"0x{base & 0xFFFFFFFFFFFFFFFF:X}",
                    "size": size & 0xFFFFFFFF,
                    "end": f"0x{(base + (size & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF:X}",
                    "part": part,
                    "file_offset": file_offset,
                }
            )
        else:
            raise CEServerError(f"Module list exceeded safety limit {MAX_MODULE_COUNT}")
        return modules

    def list_memory_regions(self, pid: int, flags: int = 0) -> list[dict[str, Any]]:
        handle = self.open_process(pid)
        try:
            self.send(
                bytes((CMD_VIRTUALQUERYEXFULL,))
                + struct.pack("<IB", handle, flags & 0xFF)
            )
            count = struct.unpack("<I", self.recv_exact(4))[0]
            if count > MAX_REGION_COUNT:
                raise CEServerError(
                    f"Region count {count} exceeds safety limit {MAX_REGION_COUNT}"
                )
            regions: list[dict[str, Any]] = []
            for _ in range(count):
                base, size, protection, region_type = REGION_INFO.unpack(
                    self.recv_exact(REGION_INFO.size)
                )
                regions.append(
                    {
                        "base": f"0x{base:X}",
                        "end": f"0x{base + size:X}",
                        "size": size,
                        "protection": protection,
                        "protection_name": _protection_name(protection),
                        "type": region_type,
                    }
                )
            return regions
        finally:
            self.close_handle_best_effort(handle)

    def read_memory(self, pid: int, address: int, size: int) -> bytes:
        if not 1 <= size <= MAX_READ_SIZE:
            raise ValueError(f"size must be between 1 and {MAX_READ_SIZE}")
        handle = self.open_process(pid)
        try:
            self.send(
                bytes((CMD_READPROCESSMEMORY,))
                + struct.pack("<IQIB", handle, address, size, 0)
            )
            read_size = struct.unpack("<i", self.recv_exact(4))[0]
            if not 0 <= read_size <= size:
                raise CEServerError(
                    f"Invalid read size {read_size}; requested {size}"
                )
            return self.recv_exact(read_size)
        finally:
            self.close_handle_best_effort(handle)

    def aob_scan(
        self,
        pid: int,
        pattern: bytes,
        mask: bytes,
        start: int,
        end: int,
        increment: int,
        protection: int,
    ) -> list[int]:
        if not pattern or len(pattern) != len(mask):
            raise ValueError("AOB pattern and mask must have the same non-zero size")
        if len(pattern) > MAX_AOB_PATTERN_SIZE:
            raise ValueError(
                f"AOB pattern exceeds {MAX_AOB_PATTERN_SIZE} byte safety limit"
            )
        if start >= end:
            raise ValueError("AOB start must be lower than end")
        if end - start > MAX_AOB_SCAN_SPAN:
            raise ValueError(
                f"AOB span exceeds {MAX_AOB_SCAN_SPAN // (1024 * 1024)} MiB; "
                "scan one module or a smaller memory range"
            )
        if not 1 <= increment <= 4096:
            raise ValueError("increment must be between 1 and 4096")

        handle = self.open_process(pid)
        try:
            request = struct.pack(
                "<IQQiii",
                handle,
                start,
                end,
                increment,
                protection,
                len(pattern),
            )
            self.send(bytes((CMD_AOBSCAN,)) + request + pattern + mask)
            result_count = struct.unpack("<i", self.recv_exact(4))[0]
            if result_count < 0:
                raise CEServerError("Canvas AOB scanner returned an error")
            if result_count > MAX_AOB_RESULTS:
                raise CEServerError(
                    f"AOB scan returned {result_count} hits, above the MCP safety "
                    f"limit {MAX_AOB_RESULTS}; use a more specific pattern"
                )
            if result_count == 0:
                return []
            return list(
                struct.unpack(
                    f"<{result_count}Q",
                    self.recv_exact(result_count * 8),
                )
            )
        finally:
            self.close_handle_best_effort(handle)


def _parse_aob_pattern(text: str) -> tuple[bytes, bytes]:
    pattern = bytearray()
    mask = bytearray()
    tokens = text.replace(",", " ").split()
    if not tokens:
        raise ValueError("AOB pattern is empty")
    for token in tokens:
        if token in {"?", "??", "*"}:
            pattern.append(0)
            mask.append(ord("?"))
            continue
        if len(token) != 2:
            raise ValueError(
                f"Invalid token {token!r}; use hex bytes such as '48 8B ?? FF'"
            )
        try:
            pattern.append(int(token, 16))
        except ValueError as exc:
            raise ValueError(f"Invalid hex byte {token!r}") from exc
        mask.append(ord("x"))
    return bytes(pattern), bytes(mask)


def _hex_rows(data: bytes, base_address: int, width: int = 16) -> list[str]:
    rows: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        rows.append(
            f"{base_address + offset:016X}  {hex_part:<{width * 3 - 1}}  {ascii_part}"
        )
    return rows


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only MCP bridge for Canvas Cheat Engine Server"
    )
    parser.add_argument(
        "--host",
        default="auto",
        help="Device Wi-Fi IP, 'auto', or 127.0.0.1 when adb forward is active",
    )
    parser.add_argument("--port", type=int, default=52736)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--broadcast",
        default="auto",
        help="Broadcast address or 'auto' to detect local /24 networks",
    )
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8765)
    parser.add_argument(
        "--log-level",
        choices=("debug", "info", "warning", "error"),
        default="info",
    )
    return parser


ARGS = _build_parser().parse_args()
if not 1 <= ARGS.port <= 65535:
    raise SystemExit("--port must be between 1 and 65535")
if not 0.1 <= ARGS.timeout <= 120.0:
    raise SystemExit("--timeout must be between 0.1 and 120 seconds")
if not 1 <= ARGS.mcp_port <= 65535:
    raise SystemExit("--mcp-port must be between 1 and 65535")

CONFIG = BridgeConfig(
    host=ARGS.host,
    port=ARGS.port,
    timeout=ARGS.timeout,
    broadcast=ARGS.broadcast,
)


class PersistentCEServer:
    def __init__(self, config: BridgeConfig):
        self._config = config
        self._connection: CEServerConnection | None = None
        self._lock = threading.Lock()

    def _close_unlocked(self) -> None:
        if self._connection is not None:
            self._connection.__exit__(None, None, None)
            self._connection = None

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def execute(self, operation: Any) -> Any:
        with self._lock:
            for attempt in range(2):
                try:
                    if self._connection is None:
                        connection = CEServerConnection(self._config)
                        self._connection = connection.__enter__()
                    return operation(self._connection)
                except (CEServerError, OSError) as exc:
                    LOGGER.warning("CEServer operation failed: %s", exc)
                    self._close_unlocked()
                    if attempt == 1:
                        raise
        raise CEServerError("CEServer operation failed")


CONNECTION = PersistentCEServer(CONFIG)
atexit.register(CONNECTION.close)

mcp = FastMCP(
    "Canvas CEServer",
    version="1.0.0",
    instructions=(
        "Read-only access to the user's Canvas Cheat Engine Server. "
        "Use server_info first. Never infer that a runtime address remains valid "
        "after a process restart. This bridge intentionally exposes no memory "
        "write, debugger, server termination, or remote file tools."
    ),
)


@mcp.tool(
    description="Discover Canvas CEServer instances through UDP broadcast on port 3296.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def discover_servers(
    timeout_seconds: float = 2.0,
    broadcast_address: str = "auto",
) -> dict[str, Any]:
    servers = discover_canvas_servers(timeout_seconds, broadcast_address)
    return {
        "count": len(servers),
        "servers": servers,
        "note": (
            "Discovery may be blocked by guest Wi-Fi/AP isolation or a host firewall. "
            "In that case read the device IP in Android Wi-Fi settings."
        ),
    }


@mcp.tool(
    description="Check connectivity and return the Canvas CEServer protocol banner.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def server_info() -> dict[str, Any]:
    return CONNECTION.execute(lambda connection: connection.server_info())


@mcp.tool(
    description="List Android processes visible to Canvas CEServer, optionally filtering names.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def list_processes(name_filter: str = "") -> dict[str, Any]:
    processes = CONNECTION.execute(lambda connection: connection.list_processes())
    needle = name_filter.casefold().strip()
    if needle:
        processes = [p for p in processes if needle in p["name"].casefold()]
    return {"count": len(processes), "processes": processes}


@mcp.tool(
    description="List loaded modules and base addresses for an Android process ID.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def list_modules(pid: int, name_filter: str = "") -> dict[str, Any]:
    modules = CONNECTION.execute(lambda connection: connection.list_modules(pid))
    needle = name_filter.casefold().strip()
    if needle:
        modules = [m for m in modules if needle in m["name"].casefold()]
    return {"pid": pid, "count": len(modules), "modules": modules}


@mcp.tool(
    description="List mapped memory regions and optionally filter by protection bits.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def list_memory_regions(
    pid: int,
    protection_filter: int = 0,
    max_results: int = 4096,
) -> dict[str, Any]:
    if not 1 <= max_results <= 16384:
        raise ValueError("max_results must be between 1 and 16384")
    regions = CONNECTION.execute(lambda connection: connection.list_memory_regions(pid))
    if protection_filter:
        regions = [
            region
            for region in regions
            if region["protection"] & protection_filter
        ]
    truncated = len(regions) > max_results
    return {
        "pid": pid,
        "count": min(len(regions), max_results),
        "total_matching": len(regions),
        "truncated": truncated,
        "regions": regions[:max_results],
    }


@mcp.tool(
    description="Read up to 64 KiB from a process and return hex plus a formatted hex dump.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def read_memory(pid: int, address: str, size: int = 256) -> dict[str, Any]:
    numeric_address = _parse_address(address)
    data = CONNECTION.execute(
        lambda connection: connection.read_memory(pid, numeric_address, size)
    )
    return {
        "pid": pid,
        "address": f"0x{numeric_address:X}",
        "requested": size,
        "read": len(data),
        "hex": data.hex(" ").upper(),
        "hexdump": "\n".join(_hex_rows(data, numeric_address)),
    }


@mcp.tool(
    description="Scan one explicit address range for bytes such as '48 8B ?? FF'.",
    annotations={"readOnlyHint": True, "destructiveHint": False},
)
def aob_scan(
    pid: int,
    pattern: str,
    start: str,
    end: str,
    increment: int = 1,
    protection: int = ALL_ACCESSIBLE_PROTECTIONS,
) -> dict[str, Any]:
    pattern_bytes, mask = _parse_aob_pattern(pattern)
    start_address = _parse_address(start)
    end_address = _parse_address(end)
    matches = CONNECTION.execute(
        lambda connection: connection.aob_scan(
            pid=pid,
            pattern=pattern_bytes,
            mask=mask,
            start=start_address,
            end=end_address,
            increment=increment,
            protection=protection,
        )
    )
    return {
        "pid": pid,
        "pattern": pattern,
        "start": f"0x{start_address:X}",
        "end": f"0x{end_address:X}",
        "count": len(matches),
        "matches": [f"0x{address:X}" for address in matches],
    }


def main() -> None:
    _configure_event_loop()
    use_colors = _configure_console_colors()
    log_level = getattr(logging, ARGS.log_level.upper())
    _configure_console_logging(log_level)
    mcp.add_middleware(
        LoggingMiddleware(
            log_level=log_level,
            include_payloads=True,
            max_payload_length=512,
            methods=["tools/call"],
        )
    )
    try:
        mcp.run(
            transport="streamable-http",
            host=ARGS.mcp_host,
            port=ARGS.mcp_port,
            path="/mcp",
            stateless_http=False,
            uvicorn_config={
                "log_config": None,
                "use_colors": use_colors,
                "timeout_graceful_shutdown": 5,
            },
            show_banner=True,
        )
    except KeyboardInterrupt:
        LOGGER.info("Canvas CEServer MCP stopped")


if __name__ == "__main__":
    main()
