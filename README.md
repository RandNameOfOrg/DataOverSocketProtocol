# DoSP Protocol Specification

**DoSP** (Default or Simple Protocol) — TCP-протокол, работающий по умолчанию на порту **7744**. Используется для маршрутизации и пересылки сообщений между клиентами через центральный сервер.

---

## 📦 Message Format

```

\[1 byte TYPE] \[4 bytes LENGTH] \[optional 4 bytes DST\_IP] \[PAYLOAD]

````

- `TYPE`: Тип сообщения (1 байт)
- `LENGTH`: Длина пакета, включая payload и DST_IP (если присутствует)
- `DST_IP`: Адрес получателя (если требуется)
- `PAYLOAD`: Полезная нагрузка

---

## 🔤 Message Types

| Hex    | Назначение              | Mnemonic* |
|--------|-------------------------|-----------|
| `0x01` | Сообщение               | `MSG`     |
| `0x02` | Ping                    | `PING`    |
| `0x03` | Отправка другому        | `S2C`     |
| `0x04` | Получения клиентов      | `GCL`     |
| `0x05` | Запустить функцию       | `FN`      |
| `0x06` | Save/Load data          | `SD`      |
| `0x07` | Запрос IP               | `RQIP`    |
| `0x0F` | Получен отв. от клиента | `R4C`     |
| `0x10` | Ответ сервера           | `SA`      |
| `0x11` | Переданное сообщение    | `EXIT`    |
| `0x12` | Ошибка                  | `ERR`     |
| `0x13` | Назначенный IP          | `AIP`     |
| `0x14` | HandShake               | `HSK`     |

types before 0x20 are reserved for build-in functions
other types are reserved for future use
---

## 🌐 VIPv4 — Virtual IP v4

Каждому клиенту сервер присваивает виртуальный IPv4-адрес по шаблону:

`"7.10.0.{x}"  # x начинается с 2`

* Адрес назначается при подключении (`AIP`)
* Используется для маршрутизации в `S2C`
* IP может быть задан как `10.0.0.{x}`, `192.168.1.{x}` и т.д.

---

## 🧠 Assign IP example

При старте сервера:

```python
server = Server(ip_template="10.0.0.{x}")
server.start()
```

Клиенты получат IP вида `10.0.0.2`, `10.0.0.3`, …

---

## TODO

- [ ] allow `SD` (Save/Load data) in server
- [ ] encrypt messages between 2 clients