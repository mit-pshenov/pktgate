# pktgate Production Scenarios

10 реалистичных сценариев использования пакетного фильтра pktgate для типичных production-задач.
For config format reference see [CONFIG.md](../CONFIG.md). For project overview see [README.md](../README.md).

## Сценарии

### 01 — DDoS Protection (`01_ddos_protection.json`)

Защита серверной инфраструктуры от DDoS-атак. Блокировка известных ботнет-сетей на L3, rate-limiting DNS/NTP amplification на L4, общий rate-limit на входящий трафик к защищаемым серверам.

### 02 — VLAN Segmentation (`02_vlan_segmentation.json`)

Сегментация корпоративной сети по VLAN: корпоративный (100), гостевой (200), управление (999). Гостевая сеть не может достучаться до management-сегмента, её трафик ограничен по bandwidth.

### 03 — Traffic Mirroring for IDS/DLP (`03_traffic_mirroring.json`)

Зеркалирование трафика для систем обнаружения вторжений (IDS) и предотвращения утечек данных (DLP). Подозрительные подсети и honeypot-трафик зеркалируются на L3, трафик к базам данных и SSH-сессии — на L4.

### 04 — PCI DSS Compliance (`04_compliance_pci_dss.json`)

Изоляция Cardholder Data Environment (CDE) в соответствии с PCI DSS. Только авторизованные MAC-адреса коммутаторов на L2, доступ к CDE только с jump-хостов через SSH и HTTPS, зеркалирование офисного трафика к CDE для аудита.

### 05 — API Rate Limiting (`05_api_rate_limiting.json`)

Многоуровневый rate-limiting для API-платформы. Внутренние сервисы — без ограничений, premium-клиенты — 5 Gbps, free tier — 500 Mbps. QoS-тегирование для gRPC, rate-limit для metrics-scraping (Prometheus).

### 06 — VRF Multi-tenancy (`06_vrf_routing_multitenancy.json`)

Мультитенантная маршрутизация через VRF. Каждый тенант на своём VLAN и в своём VRF, cross-tenant трафик заблокирован. Общие сервисы (DNS, HTTPS) доступны из обоих VRF.

### 07 — IPv6 Dual-Stack Migration (`07_ipv6_dual_stack_migration.json`)

Переход на dual-stack IPv4/IPv6. Фильтрация по ethertype на L2, блокировка известных IPv6-сканеров, QoS-тегирование корпоративного IPv6, поддержка legacy IPv4-серверов. Rate-limit SMTP для защиты от спама.

### 08 — IoT/OT Isolation (`08_iot_ot_isolation.json`)

Изоляция IoT-сенсоров и SCADA-сети от корпоративного LAN. MAC-фильтрация одобренных устройств на L2, строгая микросегментация на L3 (сенсоры только к шлюзу, инженерные станции к SCADA). Протоколы MQTT, Modbus TCP, OPC-UA на L4.

### 09 — Datacenter QoS (`09_datacenter_qos.json`)

QoS-политики для датацентра на 100G линке. Lossless-класс для storage fabric (iSCSI, NFS, RoCEv2), высокий приоритет для vMotion, VXLAN overlay. DSCP/CoS маркировка на всех уровнях pipeline, rate-limit для backup-трафика.

### 10 — Port Scan Detection & DMZ Protection (`10_port_scan_detection.json`)

Защита DMZ от сканирования портов. MAC-фильтрация от периметрового файрвола, блокировка threat-intel фидов на L3, зеркалирование DMZ-трафика на IDS. Легитимные сервисы (HTTP/HTTPS, почта) разрешены, трафик к типичным целям сканирования (FTP, Telnet, SMB, RDP) зеркалируется для анализа.

## Валидация

Все конфиги соответствуют `config-schema.json`:
- Каждое L2-правило содержит ровно одно match-поле
- L4-правила содержат и `protocol`, и `dst_port`
- `action_params` соответствуют выбранному `action`
- `rule_id` уникальны в рамках каждого слоя
- `device_info.interface` указан во всех конфигах с правилами
