# AntiZapret VPN для Windows 11

Клиентская часть AntiZapret VPN, портированная с Linux (upstream
[shax0491/AntiZapret-VPN_new](https://github.com/shax0491/AntiZapret-VPN_new))
на Windows 11.

Upstream — серверный установщик для Ubuntu/Debian. Этот порт даёт то же
самое, но для машины под Windows 11: fake-IP-резолвер, split-маршрутизацию,
генерацию клиентских профилей и диагностику.

---

## ⚠️ Обязательные условия

Для корректной работы AntiZapret VPN на Windows 11 нужно:

1. **Отключить безопасный (Secure DNS / DoH) DNS** в Windows и в браузерах.
   Windows 11 умеет DoH сам — если он включён, DNS AntiZapret игнорируется
   и трафик уходит мимо туннеля. Установщик выключает системный DoH
   (`DNSCache\Enabled=0`), но в браузере его нужно отключить вручную:
   * Chrome/Edge: `chrome://settings/security` → «Использовать безопасный DNS-сервер» → **Выключено**;
   * Firefox: `about:preferences#general` → «Включить DNS-over-HTTPS» → **Защита от отслеживания → Только когда выбран**.

2. **Отключить IPv6.** На Windows 11 IPv6 включён по умолчанию, и он
   обходит split-маршрутизацию: IPv6-трафик уйдёт напрямую, мимо туннеля.
   Установщик отключает IPv6 системно (`Tcpip6\Parameters\DisabledComponents`);
   после этого **нужна перезагрузка**.

3. **Отключить NRDOT** (RFC 7817) — иначе Windows дописывает к имени
   домена `.mDNS` и запросы уходят не туда. Установщик выключает его.

4. **Отключить WPAD** — автоопределение прокси может увести трафик мимо
   туннеля. Установщик выключает `ProxySettingsPerUser`.

5. **В браузере отключить Local Network Access Checks:**
   `chrome://flags/#local-network-access-check` → **Disabled**.

6. Если используется AmneziaWG 3 — нужен **AmneziaWG для Windows 3.1.0+**.
   Старые версии AmneziaWG и обычный WireGuard такой конфиг не примут.

---

## Установка

```powershell
# PowerShell от имени администратора
cd windows
.\setup.ps1 -ServerHost 203.0.113.10 -ClientName home
```

Аргументы:

| Параметр | Назначение |
|---|---|
| `-ServerHost` | IP или домен зарубежного сервера AntiZapret |
| `-ClientName` | Имя клиента (влияет на имена файлов профилей) |
| `-Root` | Каталог данных, по умолчанию `C:\ProgramData\AntiZapret` |
| `-TunnelInterface` | Имя адаптера туннеля (для маршрутов) |
| `-NoProfiles` | Не создавать клиентские профили |
| `-NoDisableIpv6` | Не отключать IPv6 |
| `-SkipUpdate` | Не обновлять списки |

Требуется Python 3.11+ (с python.org, с галочкой PATH). Внешних
зависимостей нет — ни dnspython, ни dnslib не нужны.

### Что делает установщик

1. Готовит каталоги (`download/`, `config/`, `result/`, `client/`, `logs/`).
2. Обновляет автоматические списки доменов и адблока.
3. Пересобирает маршруты и списки.
4. Отключает IPv6 системно.
5. Выключает Secure DNS, NRDOT и WPAD.
6. Регистрирует локальный DNS-резолвер как задачу планировщика
   (запуск при старте, от SYSTEM, перезапуск при сбое).
7. Создаёт клиентские профили.

---

## Как это работает

Механизм AntiZapret — «поддельные» IP-адреса (fake-IP):

```
браузер → DNS AntiZapret → поддельный IP 198.18.x.x
                              ↓
                     маршрут fake-пула → туннель
                              ↓
                    на сервере: подмена на настоящий IP
```

1. Локальный резолвер получает запрос к заблокированному домену.
2. Вместо настоящего адреса он выдаёт адрес из пула `198.18.0.0/15`
   (или `10.30.0.0/15` при `FAKE_IP_CIDR=10.30.0.0/15`).
3. Windows отправляет трафик на поддельный адрес; маршрут на fake-пул
   направляет его в туннель.
4. На сервере настоящий адрес подставляется, соединение идёт из-за рубежа.

Российские домены при этом резолвятся **напрямую** через российские
резолверы (Яндекс, MSK-IX, ТрансТелеКом) — то есть `.ru`, `.su`, `.рф`
идут напрямую, без туннеля. Если российский резолвер не ответил,
переспрашивается **тоже российский**, а не Cloudflare.

### Режимы DNS

| Режим | Что резолвит | Когда нужен |
|---|---|---|
| `split` | РФ — по РФ-резолверам, блокированные — по зарубежным | обычный AntiZapret VPN |
| `full` | всё по зарубежным | полный VPN |
| `proxy` | только заблокированные — по зарубежным | прокси-режим (kresd@3) |

### Переключатели в файле настроек

`C:\ProgramData\AntiZapret\setup` — обычный текст `KEY=VALUE`:

| Ключ | Значения | Назначение |
|---|---|---|
| `SERVER_HOST` | IP или домен | адрес зарубежного сервера |
| `MODE` | `split` / `full` / `proxy` | режим DNS-резолвера |
| `FAKE_IP_CIDR` | `198.18.0.0/15` | пул поддельных адресов |
| `TUNNEL_INTERFACE` | имя адаптера | куда направлять маршруты |
| `TUNNEL_GATEWAY` | IP | шлюз туннеля |
| `DNS_IPS` | список IP | адреса DNS AntiZapret (они тоже идут в туннель) |
| `IPV6_MODE` | `a` / `b` / `c` | режим IPv6 (по умолчанию `a` — AAAA пустые) |
| `ADBLOCK` | `y` / `n` | блокировка рекламы по спискам AdGuard и OISD |

После правки настроек: `azwin up` (маршруты) или перезапуск задачи
`AntiZapret DNS` (резолвер).

---

## Команды

```powershell
azwin setup                    # настройка (или .\setup.ps1)
azwin update                   # обновить списки доменов и адблока
azwin parse                    # пересобрать списки и маршруты
azwin up                       # включить split-маршрутизацию
azwin down                     # выключить split-маршрутизацию
azwin up --dry-run             # показать команды без применения
azwin client create <имя>      # создать профили клиента
azwin client delete <имя>      # удалить профили клиента
azwin client list              # список клиентов
azwin status                   # состояние: DNS, адаптеры, маршруты
azwin doctor                   # диагностика типовых проблем
azwin dns example.com --type A # разовый DNS-запрос
```

### Что попадает в туннель

`azwin up` добавляет маршруты:

* весь fake-пул (`198.18.0.0/15`);
* все адреса из `result/route-ips.txt` (Discord, Telegram, WhatsApp,
  Roblox, Cloudflare и прочие из реестра РКН);
* адреса DNS AntiZapret — иначе DNS утечёт мимо туннеля.

Остальной трафик идёт напрямую, как и задумано в split-режиме.

---

## Протоколы

Порты и запасные порты — как в upstream.

| Протокол | Файл | Порт | Запасные |
|---|---|---|---|
| OpenVPN UDP | `*-antizapret-udp.ovpn` | 50443 | 504, 443 |
| OpenVPN TCP | `*-antizapret-tcp.ovpn` | 50443 | 504, 443 |
| OpenVPN оба | `*-antizapret.ovpn` | 50443 | 504, 443 |
| OpenVPN (полный VPN) | `*-vpn*.ovpn` | 50080 | 508, 80 |
| WireGuard | `*-antizapret.conf` | 51443 | 540, 580 |
| AmneziaWG 1.5 | `*-antizapret-am.conf` | 52443 | — |
| AmneziaWG 2 | `*-antizapret-am2.conf` | 53443 | 544, 584 |
| AmneziaWG 3 | `*-antizapret-awg3.conf` | 51821 | — |

Клиентские VPN-профили OpenVPN и WireGuard содержат `block-ipv6` и
`AllowedIPs` с fake-пулом и маршрутами.

### Особенности Windows

* **Имя файла профиля** — не длиннее 32 символов и без скобок
  (ограничение клиентов Windows). Имя клиента приводится к безопасному виду
  автоматически.
* **AmneziaWG 3** требует AmneziaWG для Windows 3.1.0+; обычный WireGuard
  и старые версии AmneziaWG такой конфиг не примут.
* **AmneziaWG 2** — MTU 1280 (минимальный, гарантированно проходит по
  любому маршруту, в том числе через CGNAT). Остальные протоколы — 1420.
* **AmneziaVPN** использовать нельзя: он подменяет DNS AntiZapret на свой,
  и из-за этого AntiZapret VPN не работает. Нужен именно AmneziaWG.
* Если клиент не поддерживает AmneziaWG 1.5 — удалите из `*-am.conf`
  строку `I1 = <b...`.
* Шифрование по умолчанию — AES-128-GCM. Если на процессоре нет AES-NI,
  замените в `.ovpn` на `CHACHA20-POLY1305`.

---

## Списки доменов и адресов

Как в upstream: автоматически обновляемые списки лежат в `download/`,
ручные надстройки — в `config/`. Правки в `config/` не затираются обновлением.

| Файл | Назначение |
|---|---|
| `config/include-hosts.txt` | добавить свой домен в AntiZapret |
| `config/exclude-hosts.txt` | исключить домен из AntiZapret |
| `config/remove-hosts.txt` | убрать домен отовсюду (и из включения, и из исключения) |
| `config/include-ips.txt` | добавить свои подсети |
| `config/exclude-ips.txt` | исключить подсети |
| `config/include-adblock-hosts.txt` | домены в адблок |
| `config/exclude-adblock-hosts.txt` | исключить из адблока |
| `config/include-warp-hosts.txt` | домены, чей исходящий трафик идёт через WARP/Proton |

Формат — обычный текст, одна запись на строку, `#` и `;` — комментарии.

После правки обязательно:

```powershell
azwin parse
```

Для клиентов OpenVPN достаточно переподключиться. Клиентам
WireGuard/AmneziaWG новые адреса нужно добавить в строку `AllowedIPs`
в конфиге через запятую.

---

## Диагностика

```powershell
azwin doctor
```

Проверяет права, IPv6, загруженность списков и наличие туннеля.

Типовые проблемы:

| Симптом | Причина | Что делать |
|---|---|---|
| Часть сайтов открывается напрямую | включён Secure DNS (DoH) | выключить DoH в Windows и браузере |
| Утечка IPv6 | IPv6 не отключён | `azwin setup` + перезагрузка |
| DNS работает, сайты не открываются | не настроены маршруты | `azwin up` |
| Профиль не импортируется | имя файла длиннее 32 символов или есть скобки | переименовать (генерируется корректно автоматически) |
| AmneziaWG 3 не подключается | старый клиент | обновить до 3.1.0+ |
| YouTube показывает регион «Россия» | адрес Cloudflare WARP помечен как RU | сменить провайдера на Proton (раздел WARP в upstream README) |

Проверка блокировок с клиента (не с сервера):

```powershell
curl.exe https://censorcheck.vrnt.xyz --output -
```

---

## Отличие от upstream

| Аспект | Upstream (Linux) | Этот порт (Windows 11) |
|---|---|---|
| Установка | `setup.sh` | `setup.ps1` |
| Списки | `download/` + `config/` | те же пути, `C:\ProgramData\AntiZapret` |
| DNS-резолвер | knot-resolver (kresd@1/2/3) | `azwin.dnsd` на чистом Python |
| Кодек DNS | knot-resolver | свой, без зависимостей |
| Маршруты | iptables / nftables | `netsh interface ipv4 add route` |
| Подмена fake-IP | nftables-карта `mapping` | делается на сервере; на клиенте — маршрут fake-пула |
| Служба | systemd-юниты | задача планировщика Windows (запуск при старте, SYSTEM) |
| Firewall | nftables / iptables | `New-NetFirewallRule` |
| IPv6 | отключается на сервере | отключается на клиенте (иначе утечка) |
| Клиентские профили | `client.sh` | `azwin client create` |

Серверная часть (OpenVPN/WireGuard/AmneziaWG-серверы, WARP/Proton-выход,
Egress-Guard, Reverse-Tunnel, админ-панель) остаётся на Linux-сервере
upstream — на Windows её не портировали.

---

## Структура

```
windows/
  setup.ps1              установщик
  azwin/
    dnswire.py           DNS-кодек (RFC 1035) без зависимостей
    lists.py             списки доменов и IP, слияние и исключения
    resolver.py          fake-IP-резолвер и политика выбора резолвера
    winnet.py            маршруты, DNS, IPv6, firewall, утечки
    profiles.py          генерация профилей всех протоколов
    cli.py               командный интерфейс
    dnsd.py              локальный DNS-сервер (служба)
  tests/
    test_azwin.py        тесты
```

## Тесты

```powershell
cd windows
python -m unittest discover -s tests -v
```

Требуется только стандартная библиотека Python.
