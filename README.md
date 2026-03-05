# remnawave-vyos-subscription

Сервис для VyOS, который синхронизирует конфиги VPN-нод с панели [Remnawave](https://github.com/remnawave), запускает sing-box как прозрачный TUN-прокси и автоматически переключает ноды при падении связи.

## Возможности

- Получает список нод по ссылке-подписке (VLESS / VMess / Trojan)
- Генерирует конфиг sing-box с TUN-интерфейсом и GeoIP/GeoSite-маршрутизацией
- Автоматически скачивает sing-box и geo-базы при первом запуске
- Heartbeat: при N последовательных неудачах переключается на следующую ноду
- Textual TUI для управления прямо из терминала

## Режимы запуска

### Вариант A — Docker-контейнер на VyOS

**1. Настроить `config.env`** (положить в `/config/remnawave/config.env`):

```bash
SUBSCRIPTION_URL=https://panel.example.com/sub/TOKEN
```

Остальные параметры см. в `config.env.example`.

**2. Запустить контейнер:**

```
set container name remnawave image 'ghcr.io/CyanLunaris/remnawave-vyos-subscription:latest'
set container name remnawave cap-add 'net-admin'
set container name remnawave device tun source '/dev/net/tun' destination '/dev/net/tun'
set container name remnawave volume config source '/config/remnawave' destination '/etc/remnawave'
set container name remnawave volume singbox source '/config/sing-box' destination '/etc/sing-box'
set container name remnawave volume logs source '/config/remnawave/logs' destination '/var/log/remnawave'
commit ; save
```

**3. Установить команду управления:**

```bash
sudo bash container-setup.sh
```

После этого TUI вызывается просто:

```bash
remnaproxy-tui
```

---

### Вариант B — Прямая установка на VyOS (systemd)

```bash
sudo bash install.sh
```

Скрипт установит файлы в `/usr/local/lib/remnawave/`, создаст systemd-юниты и запустит первый синк.

---

## TUI — управление

```
F2       — список нод, переключение вручную
F3       — редактировать sub-link, интервалы, geo-настройки
s        — форс-синк прямо сейчас
q        — выход
```

Главный экран показывает текущую ноду, протокол, счётчик ошибок heartbeat и последние строки логов sync/heartbeat.

---

## Конфигурация

Все параметры описаны в [`config.env.example`](config.env.example).

Ключевые:

| Параметр | По умолчанию | Описание |
|---|---|---|
| `SUBSCRIPTION_URL` | — | Ссылка-подписка (обязательно) |
| `SYNC_INTERVAL` | `10min` | Интервал синхронизации |
| `HEARTBEAT_INTERVAL` | `30s` | Интервал проверки связи |
| `HEARTBEAT_FAIL_THRESHOLD` | `2` | Неудач подряд до смены ноды |
| `GEO_DIRECT_IP` | `private,ru` | GeoIP-коды для прямого маршрута |
| `GEO_DIRECT_SITE` | `ru` | GeoSite-коды для прямого маршрута |
