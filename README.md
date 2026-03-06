# remnawave-vyos-subscription

Сервис для VyOS, который синхронизирует конфиги VPN-нод с панели [Remnawave](https://github.com/remnawave), запускает sing-box как прозрачный TUN-прокси и автоматически переключает ноды при падении связи.

## Возможности

- Получает список нод по ссылке-подписке (VLESS / VMess / Trojan)
- Генерирует конфиг sing-box с TUN-интерфейсом и GeoIP/GeoSite-маршрутизацией
- Автоматически скачивает sing-box и geo-базы при первом запуске
- Heartbeat: при N последовательных неудачах переключается на следующую ноду
- Textual TUI для управления прямо из терминала

## Режимы запуска

### Вариант A — Podman-контейнер на VyOS

**1. Настроить `config.env`** (положить в `/config/remnaproxy/config.env`):

```bash
SUBSCRIPTION_URL=https://panel.example.com/sub/TOKEN
```

Остальные параметры см. в `config.env.example`.

**2. Запустить контейнер через VyOS CLI:**

```
set container name remnaproxy image 'ghcr.io/cyanlunaris/remnawave-vyos-subscription:latest'
set container name remnaproxy capability net-admin
set container name remnaproxy allow-host-networks
set container name remnaproxy device tun source '/dev/net/tun'
set container name remnaproxy device tun destination '/dev/net/tun'
set container name remnaproxy volume config source '/config/remnaproxy'
set container name remnaproxy volume config destination '/etc/remnaproxy'
set container name remnaproxy volume singbox source '/config/sing-box'
set container name remnaproxy volume singbox destination '/etc/sing-box'
set container name remnaproxy volume logs source '/config/remnaproxy/logs'
set container name remnaproxy volume logs destination '/var/log/remnaproxy'

commit ; save
```

**3. Установить команду управления (TUI):**

```bash
sudo bash container-setup.sh
```

Скрипт устанавливает обёртку в `/config/scripts/remnaproxy-tui` (переживает обновления VyOS)
и создаёт симлинк в `/usr/local/bin/remnaproxy-tui`.

После этого TUI вызывается просто:

```bash
remnaproxy-tui
```

---

### Вариант B — Прямая установка на VyOS (systemd)

```bash
sudo bash install.sh
```

Скрипт установит файлы в `/usr/local/lib/remnaproxy/`, создаст systemd-юниты и запустит первый синк.

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
| `GEO_DIRECT_SITE` | `category-ru` | GeoSite-коды для прямого маршрута |
