# DoSP Protocol Specification
![PyPI - Version](https://img.shields.io/pypi/v/DoSP)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/RandNameOfOrg/DataOverSocketProtocol/python-publish.yml)

**DoSP** (Data over socket Protocol) — TCP-протокол, работающий по умолчанию на порту `7744`. Используется для маршрутизации и пересылки сообщений между клиентами через центральный сервер.

---

## 📦 Message Format

```
B = Byte(s)
b = bit(s)  
[2B TYPE] [4B LENGTH] [optional 4B DST_IP] [PAYLOAD]
````

- `TYPE`: Тип сообщения (1 байт)
- `LENGTH`: Длина пакета, включая payload и DST_IP (если присутствует)
- `DST_IP`: Адрес получателя (если требуется)
- `PAYLOAD`: Полезная нагрузка

---

## 🔤 Message Types

| Name   | Hex   | Description        |
|--------|-------|--------------------|
| `MSG`  | `x01` | Сообщение          |
| `PING` | `x02` | Ping               |
| `S2C`  | `x03` | Отправка другому   |
| `GCL`  | `x04` | Получения клиентов |
| `FN`   | `x05` | Запустить функцию  |
| `SD`   | `x06` | Server Data        | 
| `RQIP` | `x07` | Запрос IP          |
| `GSI`  | `x08` | Получить self-info |
| `SA`   | `x10` | Ответ сервера      |
| `EXIT` | `x11` | Выход              |
| `ERR`  | `x12` | Ошибка             |
| `AIP`  | `x13` | Назначенный IP     |
| `HSK`  | `x14` | HandShake          |

types before 0x20 are reserved for build-in functions
other types are reserved for future use
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

- Make EXIT work fine on both client and server
- make check_conection() working at client.py
- add ip parsing at base.py (server)