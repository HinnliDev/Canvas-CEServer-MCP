<div align="center">

# Canvas Cheat Engine Server MCP

[![English](https://img.shields.io/badge/lang-English-red)](README.md)
[![License MIT](https://badgen.net/github/license/HinnliDev/Canvas-CEServer-MCP)](LICENSE)


Streamable HTTP-мост с доступом только для чтения предназначен для [Canvas](https://github.com/skyprotocol/Canvas-Open-Source), Android-модлоадера для игры Sky: Children of the Light. Он подключает MCP-клиенты к Cheat Engine Server, встроенному в Canvas.
</div>

## Требования

- Python 3.11 или новее
- Canvas CEServer с протоколом 6
- Устройство должно находиться в одной Wi-Fi сети с компьютером

```bash
python -m pip install "fastmcp>=3.1,<4"
```

## Запуск

Включите Cheat Engine Server в Canvas, затем запустите мост:

```powershell
py -3.11 canvas_ce_mcp.py --host auto --port 52736 --mcp-host 127.0.0.1 --mcp-port 8765
```

Не закрывайте консоль. Сервер продолжает работать между сессиями MCP-клиентов и показывает запросы, аргументы инструментов, время выполнения, подключения и ошибки. Для остановки нажмите `Ctrl+C`.

## Настройка MCP-клиента

Подключите MCP-клиент к `http://127.0.0.1:8765/mcp` через Streamable HTTP.

Пример для Codex в `~/.codex/config.toml`:

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

После изменения конфигурации перезапустите MCP-клиент. Мост необходимо запустить до открытия сессии, которая будет его использовать.

## Инструменты

| Инструмент | Назначение |
| --- | --- |
| `discover_servers` | Поиск Canvas CEServer в локальной сети |
| `server_info` | Получение версии протокола и строки сервера |
| `list_processes` | Список доступных процессов Android |
| `list_modules` | Список загруженных модулей и runtime-адресов |
| `list_memory_regions` | Список регионов памяти и флагов защиты |
| `read_memory` | Чтение до 64 КиБ памяти процесса |
| `aob_scan` | Поиск сигнатуры с поддержкой wildcard в заданном диапазоне |

PID и адреса необходимо получать заново после перезапуска игры. Мост не предоставляет запись памяти, отладчик, доступ к удалённым файлам или остановку сервера. Используйте его только в доверенной локальной сети.

## Лицензия

MIT License. Copyright (c) 2026 Hinnli. Полный текст находится в файле [LICENSE](LICENSE).
