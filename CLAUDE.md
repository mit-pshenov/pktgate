# pktgate

eBPF/XDP line-rate L2/L3/L4 packet filter для GGSN-Gi. C++23 control
plane, XDP+TC hybrid с tail calls, double-buffered maps, JSON config с
hot reload. Проект на паузе, main — shippable.

**Точка входа для любой работы: `_review/HANDOVER.md`** — текущее
состояние, открытые задачи, anti-checklist. Канонический каталог
findings: `_review/99_REPORT.md` (inline `[RESOLVED]` маркеры).

## Контекст use case

Заказчик: line-rate фильтрация 40 Gbps GGSN-Gi (бриф в `_.txt`).
Реальное применение — **pre-filter перед DPI-анализатором WhatsApp
трафика** в мобильной сети: из 10-100 Gbps Gi-трафика передать на
дорогой DPI только потенциально-WhatsApp (~5-15%). Этого контекста в
брифе нет; решения по фичам оценивать через эту призму. Сам pktgate
DPI не делает (см. бриф: no DPI/L7).

## Правила работы

- **Backward compatibility НЕ требуется** — pre-release, внешних
  потребителей нет. Структуры, формат конфига, map layouts можно
  менять свободно.
- **Тесты:** functional suite — sudo + namespaces + XDP, ~6 минут;
  не гонять впустую. Для точечной проверки:
  `sudo bash functional_tests/run.sh path::Class::test` или
  `ctest -L unit`. На каждом фиксе спрашивать: есть ли тест, который
  closes this finding? Нет — добавить (unit / bpf_dataplane /
  functional по уровню).
- Cross-cutting рефакторы — сначала mini-design в `_fixes/`
  (правила в `_fixes/README.md`); простые фиксы — straight to commit
  с `[RESOLVED]`-маркером в `99_REPORT.md`.

## Sibling-проект

`/home/user/pktgate-dpdk/` — greenfield DPDK-фильтр под тот же бриф.
**Не fork**, код не переиспользуется; переносятся только семантические
уроки (first-match-wins, compound L2, fragment handling, dual-stack).
Разговор про «pktgate-dpdk», DPDK design/review-notes — это туда.
