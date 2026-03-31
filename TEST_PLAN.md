# TEST_PLAN.md — pktgate Test Plan

## Сводка

| Категория | Файлов | Тестов | Привилегии | Время |
|-----------|--------|--------|------------|-------|
| C++ unit | 14 | ~340 | нет | ~5 с |
| C++ integration | 4 | ~66 | нет | ~3 с |
| BPF dataplane | 1 | 23 | root/CAP_BPF | ~15 с |
| Functional (pytest) | 13 | 104 | root | ~3 мин |
| Fuzz | 3 | ∞ | нет | 60с–∞ |
| Benchmark | 1 | — | нет | manual |

**Итого**: 19 ctest-целей + 104 functional + 3 fuzz harness.

---

## 1. C++ Unit тесты (ctest -L unit)

14 test binaries, все чисто userspace — ни BPF, ни root, ни сеть не нужны.

```bash
cmake -B build && cmake --build build -j$(nproc)
ctest --test-dir build -L unit --output-on-failure
```

| # | ctest name | Файл | Что тестирует |
|---|------------|------|---------------|
| 1 | config_parser | tests/test_config_parser.cpp | JSON → Config struct: объекты, пайплайн, ошибки |
| 2 | object_compiler | tests/test_object_compiler.cpp | MAC/subnet/port group → BPF map entries |
| 3 | generation_logic | tests/test_generation_logic.cpp | Double-buffer state machine, atomic swap |
| 4 | net_types | tests/test_net_types.cpp | MacAddr::parse(), Ipv4Prefix::parse(), edge cases |
| 5 | config_validation | tests/test_config_validation.cpp | Валидация object references, protocol/port ranges |
| 6 | rule_compiler_edge | tests/test_rule_compiler_edge.cpp | L3/L4 rule compilation, collision detection, все action types |
| 7 | config_validator | tests/test_config_validator.cpp | Full config validation pipeline, multi-layer |
| 8 | byte_layout | tests/test_byte_layout.cpp | sizeof/offsetof для BPF struct key/value, endianness |
| 9 | packet_builder | tests/test_packet_builder.cpp | PacketBuilder: L2/L3/L4 frame construction |
| 10 | ipv6 | tests/test_ipv6.cpp | IPv6Prefix, lpm_v6_key layout, dual-stack compilation |
| 11 | fault_injection | tests/test_fault_injection.cpp | Truncation, bit flip, broken JSON, dangling refs |
| 12 | prometheus | tests/test_prometheus.cpp | HTTP /metrics, concurrent scrapes, metric coverage |
| 13 | map_registry | tests/test_map_registry.cpp | MapRegistry FD lookup: generational, shared, progs |
| 14 | afxdp_config | tests/test_afxdp_config.cpp | AF_XDP config parse, validate, compile, round-trip |

### Нюансы

- **prometheus** слушает на портах 19090-19095; если порты заняты — тесты провалятся.
- **byte_layout** — критический тест: если struct layout изменился, BPF programs и CP рассинхронятся. Фейл здесь = нельзя деплоить.
- **fault_injection** содержит 500+300 рандомных мутаций; seed зафиксирован, но тест может быть flaky при изменении порядка выполнения.
- **afxdp_config** — чисто userspace: проверяет parse/validate/compile AF_XDP конфигурации, не требует AF_XDP сокетов или привилегий.

---

## 2. C++ Integration тесты (ctest -L integration)

4 test binaries, полные pipeline-прогоны: parse → validate → compile → verify.

```bash
ctest --test-dir build -L integration --output-on-failure
```

| # | ctest name | Файл | Что тестирует |
|---|------------|------|---------------|
| 1 | pipeline_integration | tests/test_pipeline_integration.cpp | E2E: JSON → compiled maps, cross-layer rules |
| 2 | roundtrip | tests/test_roundtrip.cpp | Parse → compile → verify binary output, byte-exact |
| 3 | stress | tests/test_stress.cpp | 1000 subnets, 100-port groups, 500 L4 rules |
| 4 | concurrency | tests/test_concurrency.cpp | Thread safety: generation swap, atomic ops, pthread |

### Нюансы

- **stress** аллоцирует ~100K map entries; на low-memory CI может OOM.
- **concurrency** линкуется с `-lpthread`; под TSAN (`-DSANITIZER=tsan`) время увеличивается ~5×.

---

## 3. BPF Dataplane тест (ctest -L bpf)

```bash
sudo ctest --test-dir build -L bpf --output-on-failure
```

| # | ctest name | Файл | Что тестирует |
|---|------------|------|---------------|
| 1 | bpf_dataplane | tests/bpf/test_bpf_dataplane.cpp | BPF_PROG_TEST_RUN: реальный XDP, map populate, verdict check |

### Требования

- **Root** или `CAP_BPF + CAP_NET_ADMIN`.
- **Kernel ≥ 5.15** с поддержкой BPF_PROG_TEST_RUN.
- Exit code 77 = skip (нет привилегий); ctest не считает это failure.
- Без root CI coverage job скипает этот тест: `ctest -E bpf_dataplane`.

### Нюансы

- Тест загружает скелетон через libbpf — если BPF-объект не пересобран, будет stale.
  Всегда пересобирайте перед запуском: `cmake --build build`.
- На GH Actions (ubuntu-24.04) BPF_PROG_TEST_RUN доступен без sudo,
  но на production-подобных ядрах может потребоваться `sysctl kernel.unprivileged_bpf_disabled=0`.

---

## 4. Functional тесты (pytest + scapy)

104 теста через реальный XDP трафик в network namespaces.

```bash
sudo bash functional_tests/run.sh                      # все тесты
sudo bash functional_tests/run.sh test_l2_mac.py       # один файл
sudo bash functional_tests/run.sh -k "mirror"          # по ключевому слову
sudo bash functional_tests/run.sh -m slow              # только @slow
```

### Тестовая инфраструктура

```
┌──────────────┐    veth-ft-cli / veth-ft-flt    ┌──────────────┐
│  ns_ft_client│◄───────────────────────────────►│ ns_ft_filter  │
│  10.99.0.2   │    scapy sends                  │ 10.99.0.1     │
│  fd00::2     │                                 │ fd00::1       │
└──────────────┘                                 │ pktgate_ctl   │
                                                 │ XDP attached  │
                 veth-ft-mir-p / veth-ft-mir      │               │
┌──────────────┐◄────────────────────────────────│               │
│ ns_ft_mirror │    (mirror/redirect tests only) │               │
│ 10.88.0.2    │                                 └──────────────┘
└──────────────┘
```

- **run.sh** проверяет root, killает orphan-процессы, чистит namespaces на exit.
- **conftest.py** предоставляет: `veth_pair`, `base_config`, `pktgate`, `standalone_gate`.
- `test_zz_*` файлы сортируются ПОСЛЕ session-тестов (standalone gate detachит XDP).

### Перечень файлов

| # | Файл | Тестов | Scope | Что проверяет |
|---|------|--------|-------|---------------|
| 1 | test_l2_mac.py | 8 | session | MAC allow/deny, broadcast, spoofing |
| 2 | test_l3_subnet.py | 15 | session | IPv4 subnet LPM, CIDR, multi-rule |
| 3 | test_l3_ipv6.py | 10 | session | IPv6 fragments, ext headers (HBH/Routing/Dest), L4 parsing |
| 4 | test_l4_ports.py | 16 | session | TCP/UDP port match, port groups, protocol filter |
| 5 | test_dscp_tag.py | 3 | session | DSCP EF rewrite в TC, TOS byte verification |
| 6 | test_pipeline.py | 11 | session | Cross-layer: L2 drop > L3 > L4, default behavior |
| 7 | test_malformed.py | 15 | session | Truncated packets, invalid headers, undersized frames |
| 8 | test_zz_lifecycle.py | 4 | standalone | SIGTERM detach, SIGHUP reload, SIGUSR1 stats, restart |
| 9 | test_zz_reload.py | 3 | standalone | inotify reload, new rules applied, no downtime |
| 10 | test_zz_gen_swap.py | 2 | standalone | Generation swap, double-buffer activation |
| 11 | test_zz_config_edge.py | 5 | standalone | default_behavior:allow, 3+ MACs, 50 port groups |
| 12 | test_zz_rate_limit.py | 2 | session | Token bucket, burst drop rate (@slow) |
| 13 | test_zz_mirror_redirect.py | 10 | standalone | Mirror clone, redirect, IPv6, Prometheus metrics |

### Нюансы

- **DSCP тесты** используют `IP_RECVTOS` через UDP socket (не tcpdump), потому что
  AF_PACKET захватывает пакет ДО TC ingress и видит оригинальный TOS.
- **Mirror** работает через TC `bpf_clone_redirect()` — клон создаётся только если XDP
  вернул `XDP_PASS`. Если L4 дропнул (`XDP_DROP`), TC не вызывается → клон не создаётся.
- **Redirect** на veth требует dummy XDP_PASS программу на **peer** интерфейсе
  (veth-ft-mir-p). Без неё `veth_xdp_xmit()` возвращает `-ENXIO` и пакет тихо теряется.
  Тест компилирует минимальный BPF prog через clang (авто-поиск clang-19..16) и загружает на peer.
- **Rate-limit** тесты (`@pytest.mark.slow`) отправляют burst 100+ пакетов; результат
  зависит от CPU load. При высокой загрузке возможен flaky fail.
- **Prometheus metrics** проверяются через `curl` к `127.0.0.1:19199/metrics` изнутри
  ns_ft_filter. Порт 19199 захардкожен; конфликт маловероятен.
- Полный прогон ~3 мин; `test_zz_mirror_redirect.py` один ~45 сек (10 start/stop циклов).

---

## 5. Фаззинг

3 harness, dual-mode: libFuzzer (clang-17+) или standalone/stdin (GCC/any).

### Сборка

```bash
# libFuzzer (clang-17+, рекомендуется)
CC=clang-18 CXX=clang++-18 cmake -B build -DFUZZ=ON
cmake --build build --target fuzz_config_parser fuzz_net_types fuzz_roundtrip

# Standalone (GCC, любой компилятор)
cmake -B build -DFUZZ=ON
cmake --build build --target fuzz_config_parser fuzz_net_types fuzz_roundtrip
```

### Запуск

```bash
# libFuzzer — 5 минут каждый, с seed corpus
./build/fuzz_config_parser fuzz/corpus_config -max_total_time=300
./build/fuzz_net_types     fuzz/corpus_net    -max_total_time=300
./build/fuzz_roundtrip     fuzz/corpus_roundtrip -max_total_time=300

# Standalone — через stdin (для GCC/AFL++)
./build/fuzz_config_parser < some_input.json
echo "AA:BB:CC:DD:EE:FF" | ./build/fuzz_net_types
```

| # | Target | Corpus | Что фаззит |
|---|--------|--------|------------|
| 1 | fuzz_config_parser | fuzz/corpus_config/ (2 seeds) | JSON parser: произвольный input → parse_config_string() |
| 2 | fuzz_net_types | fuzz/corpus_net/ (2 seeds) | MacAddr::parse(), Ipv4Prefix::parse() |
| 3 | fuzz_roundtrip | fuzz/corpus_roundtrip/ (1 seed) | Full pipeline: parse → validate → compile_objects → compile_rules |

### CI интеграция (.github/workflows/fuzz.yml)

| Job | Триггер | Длительность | Описание |
|-----|---------|-------------|----------|
| fuzz-smoke | Pull Request | 60с × 3 | Быстрая проверка на регрессии |
| fuzz-overnight | Cron (Mon-Fri 02:00 UTC) | 1ч × 3 (настраиваемо) | Долгий прогон, corpus caching |
| fuzz-overnight | workflow_dispatch | custom | Ручной запуск с параметром duration |

Overnight job: corpus кешируется через `actions/cache`, crash artifacts загружаются,
при crash автоматически создаётся GitHub Issue.

### Нюансы

- **clang-16 не подходит** для libFuzzer mode — нет `std::expected` (C++23).
  С clang-19 проблема решена. Standalone mode с GCC тоже работает.
- CI (ubuntu-24.04) использует clang-18+ — libFuzzer работает.
- Standalone mode (GCC) компилируется с ASAN+UBSAN, но без fuzzer engine.
  Для полноценного мутационного фаззинга — AFL++ или ручной скрипт с мутациями.
- Seed corpus маленький (5 файлов); для overnight эффективнее начать с расширенного
  корпуса из реальных конфигов.
- **Известная находка**: port > 65535 проходил валидацию (исправлено: `int` → `int64_t` в парсере).

---

## 6. Benchmark (ручной запуск)

```bash
./build/bench_compile
```

| # | Binary | Что измеряет |
|---|--------|-------------|
| 1 | bench_compile | Время компиляции: 10/100/1000 subnets, 10/100 port groups |

Не входит в ctest. Полезен для отслеживания регрессий после оптимизаций.

---

## 7. Sanitizer-прогоны

```bash
# Address Sanitizer
cmake -B build -DSANITIZER=asan && cmake --build build && ctest --test-dir build

# Undefined Behavior Sanitizer
cmake -B build -DSANITIZER=ubsan && cmake --build build && ctest --test-dir build

# Thread Sanitizer
cmake -B build -DSANITIZER=tsan && cmake --build build && ctest --test-dir build
```

CI матрица запускает Debug+ASAN, Debug+UBSAN автоматически на каждый push/PR.

### Известные находки (исправлены)

- **UBSAN**: misaligned `struct iphdr*` cast в PacketBuilder (offset 14) → исправлено memcpy.
- Все 17 ctest-целей проходят чисто под всеми тремя sanitizers.

---

## 8. Coverage

```bash
cmake -B build -DCOVERAGE=ON
cmake --build build
ctest --test-dir build -E bpf_dataplane --output-on-failure
make -C build coverage
# Отчёт: build/coverage_html/index.html
```

CI job `coverage` делает это автоматически и загружает артефакт.

---

## 9. Чеклист перед релизом

- [ ] `ctest -L unit` — все 14 бинарей проходят
- [ ] `ctest -L integration` — все 4 бинаря проходят
- [ ] `sudo ctest -L bpf` — BPF dataplane 23 теста
- [ ] `sudo bash functional_tests/run.sh` — 104 functional теста
- [ ] ASAN прогон (`-DSANITIZER=asan`) — 0 ошибок
- [ ] UBSAN прогон (`-DSANITIZER=ubsan`) — 0 ошибок
- [ ] Fuzz smoke (60с × 3 harness) — 0 crashes
- [ ] Coverage ≥ текущий baseline
- [ ] `rpm -ba filter.spec` — RPM собирается, `%check` проходит
