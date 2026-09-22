### Русский вариант (Russian)
# nftop — Терминальный монитор сетевых сокетов, правил nftables и Docker-портов
**nftop** — это легковесная консольная утилита с текстовым интерфейсом (TUI), написанная на Go и предназначенная для аудита сетевой безопасности, отслеживания открытых портов и инспекции правил межсетевого экрана `nftables` в реальном времени. Инструмент агрегирует сетевую телеметрию из низкоуровневых сокетов ядра, метаданных Docker-демона и таблиц Netfilter, предоставляя системным администраторам и DevOps-инженерам прозрачную картину сетевого периметра сервера.

---

#### Решаемая проблема
В современных дистрибутивах Linux (Debian, Ubuntu, RHEL) контейнеры Docker часто модифицируют таблицы трансляции адресов (NAT) в обход стандартных пользовательских правил фаервола, публикуя порты наружу без явного ведома администратора. Утилиты вроде `netstat` или `ss` показывают лишь факт прослушивания порта, а `nft` выводит сложные многостраничные конфигурации. `nftop` решает эту проблему: сопоставляет процесс, физический сокет, контейнер и применяемое правило фильтрации в едином интерактивном окне.

#### Ключевые возможности
* **Анализ сетевой экспозиции (Firewall Exposure Detection):** автоматическая маркировка сокетов статусами `ALLOWED` (порт защищен правилом), `SAFE` (локальный loopback или внутренняя подсеть) и `▲ EXPOSED` (порт открыт в мир без фильтрации или опубликован через Docker).
* **Единый контекст сокетов и контейнеров:** объединение данных из `ss -tulpn`, контейнеров `docker ps` и правил `nftables`.
* **Телеметрия трафика в реальном времени:** расчет пропускной способности (байт/сек, пакеты) по счетчикам правил `counter` в `nftables`.
* **Детальный инспектор сервиса (Service Inspector):** правая панель отображает PID, путь процесса, внутренний IP контейнера, имя цепочки, handle правила и сырые счетчики пакетов.
* **Режимы отображения и навигация:** переключение между детальным (4 строки) и компактным (2 строки) видами, фильтрация Docker-трафика (`d`), выборка неприкрытых портов (`e`) и мгновенный поиск (`/`).
* **Экспорт диагностических данных:** копирование полной сводки о выбранном сокете прямо в буфер обмена хоста через протокол терминала OSC 52 по нажатию `y`.
* **Экстремальная легковесность:** потребление ~10 МБ оперативной памяти, нулевые внешние C-зависимости, нативная компиляция под архитектуры x86_64 и ARM64.

#### SEO-ключевые слова (Keywords)
`мониторинг сети Linux`, `nftables TUI`, `сетевой монитор консоль`, `аудит открытых портов`, `безопасность Docker`, `проверка фаервола Linux`, `утилита Go Bubbletea`, `sysadmin tools`, `демоны сокеты ss`, `просмотр трафика терминал`, `devops cli tools`, `альтернатива iptables`, `сетевая безопасность сервера`.

---

### English Version

# nftop — Real-Time Linux Network, nftables Firewall & Docker Exposure Monitor (TUI)
**nftop** is an open-source, read-only terminal monitoring tool (TUI) written in Go, engineered to bridge the visibility gap between raw network sockets, container port bindings, and packet-filtering firewall rules. Designed for Linux systems running `nftables`, `nftop` correlates real-time connection states with Netfilter rulesets and Docker metadata to deliver an instant security posture overview directly inside your terminal.

---

#### The Problem It Solves
On modern Linux infrastructure, container runtimes (such as Docker) often manipulate Netfilter NAT tables directly, silently bypassing host firewall configurations and exposing internal services to public interfaces. Standard tools like `ss` or `lsof` disclose listening ports but provide zero firewall context, while inspecting `nft ruleset` manually is tedious. `nftop` fuses these data layers into a unified diagnostic dashboard, revealing exactly which processes are exposed, protected, or isolated.

#### Key Features
* **Zero-Trust Exposure Auditing:** instant visual tagging with `ALLOWED` (explicit firewall rule match), `SAFE` (loopback / private network), and `▲ EXPOSED` (publicly bound without firewall protection or bypassed via container proxy).
* **Tri-Source Telemetry Merging:** seamlessly queries `ss`, `docker inspect`, and `nft -j list ruleset` asynchronously without stalling the rendering loop.
* **Live Socket Throughput Calculation:** computes real-time ingress bandwidth from `nftables` rule counters (`bytes` / `packets`).
* **Interactive Split-Pane Inspector:** deep dive into socket PID, container internal IP addresses, rule handles, specific chain mappings, and raw packet metrics.
* **Optimized Workflows:** detailed (4-line) vs. compact (2-line) layouts, instant full-text filtering (`/`), dedicated Docker isolation mode (`d`), exposed-only view (`e`), and selectable sort algorithms.
* **Remote Clipboard Support:** diagnostic summaries copy directly to your local workstation clipboard across SSH sessions using ANSI OSC 52 sequences (`y`).
* **Resource-Efficient Architecture:** sub-15 MB RAM footprint, minimal CPU overhead (~1%), single static binary deployment, native ARM64 & AMD64 support.
* 
#### SEO Keywords & Metadata

`Linux network monitor`, `nftables firewall TUI`, `Docker port exposure audit`, `terminal UI Go`, `open ports scanner Linux`, `socket telemetry tool`, `DevOps terminal tools`, `sysadmin CLI utility`, `Netfilter monitor`, `network security terminal`, `Charmbracelet Bubbletea`, `lightweight server monitoring`, `ss port inspection`.
