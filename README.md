# DoSP Protocol Specification
![PyPI - Version](https://img.shields.io/pypi/v/DoSP)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/RandNameOfOrg/DataOverSocketProtocol/python-publish.yml)

**DoSP** (Data over socket Protocol) — TCP-протокол, работающий по умолчанию на порту `7744`. Используется для маршрутизации и пересылки сообщений между клиентами через сервера.

## Для чего он нужен? (Why use this?)
> Для удаленного доступа к удаленным серверам и создания mesh-сетей между ними.

---

## 📦 Packet Wire Format

```
[1B TYPE] [4B LENGTH (big-endian)] [PAYLOAD]
```

- `TYPE`: тип пакета (1 байт)
- `LENGTH`: длина payload (сжатого, если compression включён)
- `PAYLOAD`: полезная нагрузка

**S2C (0x03)** payload: `[4B dst_ip][4B src_ip][compressed user data]`
**Все остальные типы** payload: `[compressed user data]`

Сжатие (zlib) включается runtime через `protocol.set_compression()`.
Сервер рекламирует поддержку сжатия в HSK-пакете; клиент включает автоматически.

---

## 🔤 Message Types

| Name         | Hex   | Description                      |
|--------------|-------|----------------------------------|
| `MSG`        | `x01` | Сообщение                        |
| `PING`       | `x02` | Ping                             |
| `S2C`        | `x03` | Send to client (роутинг)         |
| `GCL`        | `x04` | Get clients list                 |
| `FN`         | `x05` | Run function                     |
| `SD`         | `x06` | Server Data (peer advertisement) |
| `RQIP`       | `x07` | Request IP                       |
| `GSI`        | `x08` | Get self-info                    |
| `SA`         | `x10` | Server answer                    |
| `EXIT`       | `x11` | Exit / disconnect                |
| `ERR`        | `x12` | Error                            |
| `AIP`        | `x13` | Assign IP                        |
| `HSK`        | `x14` | Handshake (config exchange)      |
| `HC2C`       | `x15` | C2C handshake marker             |
| `BCST`       | `x16` | Broadcast (admin only)           |
| `AUTH`       | `x17` | Admin authentication             |
| `ADMIN`      | `x18` | Admin command / response         |
| `CLIENT_INFO`| `x19` | Client identity hash             |
| `MPAK`       | `x1A` | Multi-packet aggregation         |

Types before 0x20 are reserved for built-in functions.
Types 0x20+ are available for custom use.
---

## 🌐 vIPv4 — Virtual IP v4

Каждому клиенту сервер присваивает виртуальный IPv4-адрес по шаблону:

`"7.10.0.x"  # x начинается с 2`

* Адрес назначается при подключении (`AIP`)
* Используется для маршрутизации в `S2C`
* IP может быть задан как `10.0.0.x`, `192.168.1.x` и т.д.

---

## 🧠 Assign IP example

При старте сервера:

```python
import dosp.server as dosp_server
server = dosp_server.DoSP(ip_template="10.0.0.x")
server.start() # <- will lock execution by defualt
```

To start server 

Клиенты получат IP вида `10.0.0.2`, `10.0.0.3`, …

---
## Credits

### Interactive Client (IMC)
Interactive Message Client is client (made by [__themaster1970sf__](https://github.com/themaster1970sf)), partly rewritten
---

## TODO

- Federation: cross-server peer routing via advertisements
- E2E encryption for C2C tunnels (DH + MAC + replay protection) — done
- Admin CLI (`dosp-admin`) — done
- WebSocket transport (WSS/WS) — done
- MPAK (multi-packet aggregation) — done