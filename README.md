<div align="center">

# Canvas Cheat Engine Server MCP

[![Русский](https://img.shields.io/badge/lang-Русский-blue)](README_ru.md)
[![License MIT](https://badgen.net/github/license/HinnliDev/Canvas-CEServer-MCP)](LICENSE)

Read-only Streamable HTTP bridge for [Canvas](https://github.com/skyprotocol/Canvas-Open-Source), an Android mod loader for Sky: Children of the Light.

It connects MCP clients to the Cheat Engine Server built into Canvas.
</div>

## Requirements

- Python 3.11 or newer
- Canvas CEServer protocol 6
- Device and computer on the same local network

```bash
python -m pip install "fastmcp>=3.1,<4"
```

## Run

Enable Cheat Engine Server in Canvas, then start the bridge:

```powershell
python canvas_ce_mcp.py --host auto --port 52736 --mcp-host 127.0.0.1 --mcp-port 8765
```

Keep the terminal open. The server remains available between MCP client sessions and logs requests, tool arguments, execution time, connection events, and errors. Stop it with `Ctrl+C`.

## MCP client configuration

Connect the MCP client to `http://127.0.0.1:8765/mcp` using Streamable HTTP.

Codex example for `~/.codex/config.toml`:

```toml
[mcp_servers.canvas_ce]
url = "http://127.0.0.1:8765/mcp"
enabled = true
tool_timeout_sec = 120
enabled_tools = [
  "discover_servers",
  "server_info",
  "list_processes",
  "list_modules",
  "list_memory_regions",
  "read_memory",
  "aob_scan"
]
```

Restart the MCP client after changing its configuration. Start the bridge before opening a session that uses it.

## Tools

| Tool | Purpose |
| --- | --- |
| `discover_servers` | Find Canvas CEServer on the local network |
| `server_info` | Read the protocol version and server banner |
| `list_processes` | List visible Android processes |
| `list_modules` | List loaded modules and runtime addresses |
| `list_memory_regions` | List mapped memory regions and protection flags |
| `read_memory` | Read up to 64 KiB from a process |
| `aob_scan` | Search an address range with wildcard support |

Process IDs and addresses must be resolved again after restarting the game. The bridge does not expose memory writes, debugging, remote files, or server termination. Use it only on a trusted local network.

## License

MIT License. Copyright (c) 2026 Hinnli. See [LICENSE](LICENSE).
