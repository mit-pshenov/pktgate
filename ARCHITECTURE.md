# ARCHITECTURE.md — eBPF Packet Filter Pipeline

## 1. Обзор среды и зависимости

| Компонент        | Статус            | Требуется                          |
|------------------|-------------------|------------------------------------|
| Kernel           | 6.1.0-43 (OK)    | >= 5.15 для BPF_MAP_TYPE_LPM_TRIE, tail calls, atomic ops |
| clang            | ✅ установлен     | `clang-16` или новее               |
| libbpf-dev       | ✅ установлен     | `libbpf-dev >= 1.1`                |
| bpftool          | ✅ установлен     | `bpftool` (генерация skeleton)     |
| linux-headers    | ✅ установлен     | `linux-headers-$(uname -r)`        |
| nlohmann_json    | ✅ установлен     | `nlohmann-json3-dev >= 3.11`       |

Установка (выполнена через `scripts/setup_env.sh`):
```bash
apt install -y clang-16 llvm-16 libbpf-dev bpftool \
    linux-headers-$(uname -r) libelf-dev zlib1g-dev \
    nlohmann-json3-dev
```

---

## 2. Высокоуровневая архитектура

```
┌─────────────────────────────────────────────────────────┐
│                   Control Plane (C++23)                  │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  Config   │  │  Object      │  │  Generation       │  │
│  │  Parser   │→ │  Compiler    │→ │  Swap Manager     │  │
│  │ (JSON)    │  │ (→ BPF maps) │  │ (atomic cutover)  │  │
│  └──────────┘  └──────────────┘  └───────────────────┘  │
│                        │                    │             │
│                   libbpf skeleton API       │             │
└────────────────────────┼────────────────────┼────────────┘
                         │ map fd             │ prog fd
─────────────────────────┼────────────────────┼────────────
                    Kernel Space              │
┌────────────────────────┼────────────────────┼────────────┐
│                        ▼                    ▼             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐            │
│  │ Layer 2  │──→ │ Layer 3  │──→ │ Layer 4  │            │
│  │  (XDP)   │    │  (XDP)   │    │  (XDP)   │            │
│  │ tail call│    │ tail call│    │          │            │
│  └──────────┘    └──────────┘    └──────────┘            │
│       ↕               ↕               ↕                  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Shared BPF Maps                        │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │ │
│  │  │ MAC hash │ │ LPM trie │ │Port hash │            │ │
│  │  └──────────┘ └──────────┘ └──────────┘            │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  Packet metadata passed via XDP data_meta area           │
│  (zero map lookups between tail calls)                   │
└──────────────────────────────────────────────────────────┘
```

---

## 3. Data Plane: eBPF программы

### 3.1. Точка входа и tail call chain

Используем **XDP** (максимальная производительность, до parsing L4). Программы вызываются
через **tail calls** из `BPF_MAP_TYPE_PROG_ARRAY`:

```
Entry XDP program
  → tail_call(prog_array, LAYER_2)
      → tail_call(prog_array, LAYER_3)
          → tail_call(prog_array, LAYER_4)
              → default action (XDP_DROP)
```

Каждый слой — отдельная секция в `.bpf.c`, компилируется в отдельную BPF-программу
и загружается в `prog_array` по индексу.

**Почему tail calls, а не один монолит:**
- Независимая замена слоёв (generation swap по слою).
- Обход лимита 1M инструкций — каждый слой имеет свой лимит.
- Чистая декомпозиция, соответствующая JSON-конфигу.

### 3.2. Layer 2 — Ethernet Filtering

```c
// Ключ: MAC-адрес (6 байт, выровнен до 8)
struct mac_key { __u8 addr[8]; };

// BPF_MAP_TYPE_HASH — mac_groups
// Lookup src_mac → если нет совпадения → XDP_DROP
// Если match → tail_call(LAYER_3)
```

### 3.3. Layer 3 — IP / VRF Filtering

```c
// BPF_MAP_TYPE_LPM_TRIE — subnets
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};
// compile-time assert: sizeof == 8 (no padding) — in common.h for BPF and C++

// Правила с match по src_ip:
//   lookup в LPM trie → action (mirror / redirect / allow)
//
// Правила с match по vrf:
//   VRF ID читается из skb->mark или ifindex → lookup в hash map
//
// IP-фрагменты: non-first fragments (frag_off & 0x1FFF != 0)
//   дропаются в L3, т.к. не содержат L4 заголовков.
//   Счётчик: STAT_DROP_L3_FRAGMENT
//
// mirror: clone + redirect через bpf_clone_redirect()
//   (Требует TC, а не XDP — см. секцию 3.6)
// redirect: bpf_redirect() на другой ifindex (target_vrf)
```

### 3.4. Layer 4 — Transport Filtering

```c
// BPF_MAP_TYPE_HASH — port_groups
struct port_key { __u16 port; };
struct port_val { __u32 group_id; };  // к какой группе принадлежит порт

// match: protocol + dst_port (object lookup)
// action: tag → модификация DSCP/CoS
// action: rate-limit → token bucket через per-CPU map
```

### 3.5. Действия (Actions)

| Action      | Реализация                                                        | Hook    |
|-------------|-------------------------------------------------------------------|---------|
| `allow`     | Передать в следующий слой или `XDP_PASS`                          | XDP     |
| `drop`      | `XDP_DROP`                                                        | XDP     |
| `mirror`    | `bpf_clone_redirect(skb, ifindex, 0)` — **только TC**            | TC      |
| `redirect`  | `bpf_redirect(ifindex, 0)` — перенаправление в другой VRF/порт   | XDP/TC  |
| `tag`       | Перезапись DSCP: `iph->tos = (iph->tos & 0x3) \| (dscp << 2)`; CoS: через `bpf_skb_set_tunnel_key` или VLAN PCP rewrite | TC |
| `rate-limit`| Per-CPU token bucket: `PERCPU_HASH`, rate/ncpus, 1s burst cap, elapsed clamp | XDP |
| `userspace` | `bpf_redirect_map(&xsks_map, rx_queue_index, XDP_PASS)` — AF_XDP fast path | XDP |

### 3.6. Гибридная модель XDP + TC

Некоторые действия (`mirror`, `tag` с CoS/VLAN) невозможны в чистом XDP.
Архитектура использует **два хука**:

```
NIC → [XDP: L2 filter + L3 (drop/redirect/allow)] → [TC ingress: L3 mirror + L4 tag/rate-limit]
```

- **XDP**: быстрый drop/redirect/pass для простых правил (Layer 2, часть Layer 3).
- **TC (cls_bpf)**: clone_redirect, skb rewrite для mirror/tag/rate-limit.

Решение принимается на этапе компиляции конфига: если pipeline содержит только
drop/allow/redirect — используется чистый XDP. Если есть mirror/tag — подключается TC.

### 3.7. AF_XDP Userspace Fast Path

Правила с `ACT_USERSPACE` перенаправляют пакеты в userspace через AF_XDP сокеты.
Пакет проходит полный pipeline (L2→L3→L4), затем `bpf_redirect_map(&xsks_map)`.

```
entry → L2 → L3 → L4 ─┬─ XDP_PASS ──► TC ingress ──► kernel stack
                        │
                        └─ ACT_USERSPACE ──► bpf_redirect_map(&xsks_map)
                                                    │
                                                    ▼
                                              AF_XDP socket(s)
                                              (per-queue threads)
```

**Ключевые решения:**
- **Post-filter redirect**: полная фильтрация перед AF_XDP — userspace видит только разрешённый трафик.
- **XDP_PASS fallback**: если AF_XDP сокет не привязан к очереди, пакет идёт в kernel stack.
- **xsks_map не double-buffered**: сокеты живут через config reload, как stats_map.
- **TC bypass**: XDP_REDIRECT минует TC ingress → mirror+userspace и tag+userspace на одном пакете **не поддерживаются** (валидатор предупредит).

**Control plane** (`src/xdp/`):
- `XdpSocket` — RAII обёртка: UMEM mmap, RX/fill rings, bind, poll_rx, refill.
  Использует raw Linux AF_XDP API (`linux/if_xdp.h`), без libxdp.
- `XdpSocketManager` — создаёт N сокетов (по числу RX queues), запускает worker threads,
  вызывает `PacketCallback(data, len)` для каждого пакета. Thread-safe callback required.

---

## 4. BPF Maps — полная схема

```
┌────────────────────────┬──────────────────────┬──────────────────────────────┐
│ Name                   │ Type                 │ Key → Value                  │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ gen_config             │ ARRAY(1)             │ 0 → active_gen (__u32)       │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ prog_array_0/1         │ PROG_ARRAY(4)        │ layer_idx → prog_fd         │
│ mac_allow_0/1          │ HASH(4096)           │ mac_key[8] → __u32 (1=ok)   │
│ subnet_rules_0/1       │ LPM_TRIE(16384)      │ lpm_v4_key → l3_rule        │
│ vrf_rules_0/1          │ HASH(256)            │ vrf_key → l3_rule            │
│ l4_rules_0/1           │ HASH(4096)           │ l4_match_key → l4_rule       │
│ default_action_0/1     │ ARRAY(1)             │ 0 → __u32 (filter_action)    │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ rate_state_map         │ PERCPU_HASH(4096)    │ rule_id → rate_state         │
│ stats_map              │ PERCPU_ARRAY(39)     │ stat_key → __u64 (counter)   │
│ xsks_map               │ XSKMAP(64)           │ queue_id → xsk_fd            │
└────────────────────────┴──────────────────────┴──────────────────────────────┘

Итого: 17 maps (3 shared + 6×2 double-buffered + 1 rate_state).
Maps _0/_1 — двойная буферизация для generation swap.
rate_state_map, stats_map и xsks_map общие (не буферизируются).
xsks_map — AF_XDP socket map, не double-buffered (сокеты живут через config reload).
stats_map — 39 per-CPU счётчиков: entry/L2/L3/L4 drops, pass/actions, TC mirror/tag, IPv6 L3/L4, fragment/proto drops, AF_XDP userspace (см. секцию 8).
```

**`pkt_meta`** — передаётся через XDP `data_meta` area (не через BPF map):
```c
struct pkt_meta {
    __u32 generation;       // текущая активная генерация
    __u32 action_flags;     // bitmap deferred actions для TC (mirror, tag)
    __u32 redirect_ifindex; // ifindex для redirect
    __u32 mirror_ifindex;   // ifindex для mirror
    __u8  dscp;             // DSCP для tag
    __u8  cos;              // CoS для tag
    __u8  _pad[2];
};
// sizeof == 20 байт, помещается в data_meta area
```

Entry вызывает `bpf_xdp_adjust_meta()` один раз, последующие слои читают через
`ctx->data_meta` (XDP) / `skb->data_meta` (TC) — zero map lookups между tail calls.
Metadata сохраняется при XDP_PASS → TC ingress transition.

---

## 5. Generation Swap — атомарное обновление конфигурации

### Проблема

При обновлении pipeline (новый JSON-конфиг) нельзя допустить:
- Частично обновлённое состояние (часть правил старых, часть новых).
- Потерю пакетов во время обновления.

### Решение: Double-Buffered Maps + Atomic Prog Replace

Механизм основан на **двух поколениях** (generation 0 и generation 1):

```
Generation 0 (active)          Generation 1 (shadow)
┌──────────────┐               ┌──────────────┐
│ mac_allow_0  │               │ mac_allow_1  │  ← CP заполняет
│ subnet_0     │               │ subnet_1     │     новыми данными
│ rules_l3_0   │               │ rules_l3_1   │
│ rules_l4_0   │               │ rules_l4_1   │
│ prog_array_0 │               │ prog_array_1 │
└──────┬───────┘               └──────┬───────┘
       │                              │
       ▼                              ▼
  entry_prog reads              entry_prog reads
  gen_config[0]=0               gen_config[0]=1
  → uses maps *_0               → uses maps *_1
```

**Алгоритм обновления (Control Plane):**

```
1. Определить shadow generation: shadow = active ^ 1

2. Заполнить все shadow maps (mac_allow_{shadow}, subnet_{shadow}, ...)
   — Можно делать сколько угодно долго, трафик идёт через active.

3. Загрузить новые BPF-программы слоёв (если код изменился),
   обновить prog_array_{shadow}.

4. Атомарный swap:
   bpf_map_update_elem(gen_config, &key, &shadow, BPF_ANY)
   — Одна атомарная запись переключает всё поколение.
   — Все последующие пакеты читают новый gen_id
     и обращаются к shadow maps.

5. Дождаться drain старого поколения:
   — rcu_barrier() или просто usleep(100ms)
     чтобы все in-flight пакеты на старом gen завершились.

6. Старое поколение становится новым shadow — готово к следующему обновлению.
```

**Реализация в BPF (фактический код из `entry.bpf.c`):**
```c
SEC("xdp")
int entry_prog(struct xdp_md *ctx) {
    __u32 key = 0;
    __u32 *gen = bpf_map_lookup_elem(&gen_config, &key);
    if (!gen) return XDP_DROP;

    // Grow XDP metadata area, write pkt_meta into data_meta
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct pkt_meta));
    if (ret) return XDP_DROP;

    void *data      = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) return XDP_DROP;

    __builtin_memset(meta, 0, sizeof(*meta));
    meta->generation = *gen;

    // Выбор prog_array по генерации
    if (*gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_2_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_2_IDX);

    return XDP_DROP; // tail call failed
}
```

**Примечание:** Вместо map-of-maps используется простой `if/else` по generation —
проще, не требует `BPF_MAP_TYPE_ARRAY_OF_MAPS`, и всего 2 генерации.

Последующие слои читают metadata через `ctx->data_meta` с bounds check:
```c
void *data_meta = (void *)(long)ctx->data_meta;
struct pkt_meta *meta = data_meta;
if ((void *)(meta + 1) > data) return XDP_DROP;
// meta->generation, meta->action_flags доступны без map lookup
```

### Гарантии

| Свойство                    | Гарантия                                  |
|-----------------------------|-------------------------------------------|
| Атомарность                 | Один `map_update` переключает generation  |
| Zero packet loss            | Старый pipeline работает до полного drain  |
| Rollback                    | Записать старый gen_id обратно             |
| Скорость переключения       | O(1) — не зависит от числа правил         |

---

## 6. Control Plane — структура проекта (C++23)

```
filter/
├── ARCHITECTURE.md              ← этот файл
├── sample2.json                 ← целевая конфигурация
├── CMakeLists.txt               ← top-level cmake (coverage, benchmarks)
│
├── bpf/                         ← eBPF C-программы (Data Plane)
│   ├── vmlinux.h                ← генерируется bpftool btf dump
│   ├── common.h                 ← общие структуры (mac_key, l3_rule, pkt_meta и т.д.)
│   ├── maps.h                   ← все BPF map definitions (double-buffered)
│   ├── entry.bpf.c              ← entry XDP program (generation dispatch)
│   ├── layer2.bpf.c             ← L2 filter (MAC allow-list)
│   ├── layer3.bpf.c             ← L3 filter (LPM subnet + VRF, redirect/mirror)
│   ├── layer4.bpf.c             ← L4 filter (protocol+port, tag/rate-limit)
│   └── tc_ingress.bpf.c         ← TC ingress companion (mirror clone, DSCP rewrite)
│
├── src/                         ← Control Plane (C++23)
│   ├── main.cpp                 ← entry point, inotify hot reload, SIGUSR1 stats dump
│   │
│   ├── config/
│   │   ├── config_model.hpp     ← C++ типы: Pipeline, Rule, Action, ObjectStore
│   │   ├── config_parser.hpp    ← JSON → Config (file + string API)
│   │   ├── config_parser.cpp
│   │   ├── config_validator.hpp ← семантическая валидация Config
│   │   └── config_validator.cpp ← rule_id, object refs, port ranges, bandwidth overflow, empty interface, action params
│   │
│   ├── compiler/
│   │   ├── object_compiler.hpp  ← ObjectStore → CompiledObjects (MAC hash, LPM, ports)
│   │   ├── object_compiler.cpp
│   │   ├── rule_compiler.hpp    ← Pipeline → CompiledRules (L3/L4 BPF entries)
│   │   └── rule_compiler.cpp    ← port group expansion, key collision detection, rate/ncpus
│   │
│   ├── loader/
│   │   ├── bpf_loader.hpp       ← libbpf skeleton wrapper (5 programs, map reuse)
│   │   ├── bpf_loader.cpp
│   │   ├── map_registry.hpp     ← FD registry: map/prog name+gen → fd
│   │   ├── map_registry.cpp
│   │   ├── map_manager.hpp      ← CRUD для BPF maps + batch_update
│   │   └── map_manager.cpp      ← batch_update с fallback, safe hash iteration
│   │
│   ├── xdp/
│   │   ├── xdp_socket.hpp       ← RAII AF_XDP socket (UMEM, RX/fill rings)
│   │   ├── xdp_socket.cpp
│   │   ├── xdp_socket_manager.hpp ← multi-queue AF_XDP worker threads
│   │   └── xdp_socket_manager.cpp
│   │
│   ├── pipeline/
│   │   ├── deploy_stats.hpp     ← DeployStats + ScopedTimer (per-phase timing)
│   │   ├── generation_manager.hpp  ← double-buffer prepare/commit/rollback
│   │   ├── generation_manager.cpp  ← batch MAC/L4, LPM key tracking
│   │   ├── pipeline_builder.hpp    ← orchestrator: validate → compile → deploy
│   │   ├── pipeline_builder.cpp    ← instrumented with DeployStats
│   │   └── stats_reader.hpp        ← runtime BPF stats reader (percpu aggregation)
│   │
│   └── util/
│       ├── net_types.hpp        ← MacAddr, Ipv4Prefix (parse + NBO), resolve_ifindex
│       └── log.hpp              ← lightweight printf-based logging
│
├── tests/                       ← 350+ тестов в 17 сьютах
│   ├── test_config_parser.cpp       (24 теста)  — JSON парсинг, DSCP, bandwidth
│   ├── test_config_validation.cpp   (30 тестов) — edge cases, все action/DSCP types
│   ├── test_config_validator.cpp    (27 тестов) — семантика: refs, duplicates, params
│   ├── test_object_compiler.cpp     (14 тестов) — MAC/subnet/port компиляция
│   ├── test_rule_compiler_edge.cpp  (47 тестов) — refs, expansion, collisions, layout
│   ├── test_net_types.cpp           (26 тестов) — MacAddr, Ipv4Prefix парсинг
│   ├── test_generation_logic.cpp    (15 тестов) — state machine генераций
│   ├── test_pipeline_integration.cpp (22 теста) — E2E compile, stress 500+ rules
│   ├── test_byte_layout.cpp         (31 тест)  — map key/value byte-level
│   ├── test_packet_builder.cpp      (17 тестов) — ETH/IP/TCP/UDP headers
│   ├── test_roundtrip.cpp           (17 тестов) — parse → validate → compile → verify
│   ├── test_stress.cpp              (9 тестов)  — 4096 rules, 16K subnets
│   ├── test_concurrency.cpp         (13 тестов) — multi-threaded gen swap
│   ├── test_afxdp_config.cpp         (12 тестов) — AF_XDP config parse/validate/compile
│   ├── bpf/test_bpf_dataplane.cpp   (23 теста)  — BPF_PROG_TEST_RUN (requires sudo)
│   └── bench_compile.cpp           — бенчмарк: small/medium/large конфиги
│
├── systemd/
│   ├── pktgate.service           ← systemd unit (hardened)
│   └── pktgate.conf              ← environment overrides
│
└── scripts/
    ├── setup_env.sh             ← установка зависимостей
    ├── gen_vmlinux.sh           ← bpftool btf dump file /sys/kernel/btf/vmlinux
    ├── install.sh               ← build + install binary, config, systemd unit
    └── uninstall.sh             ← stop, remove (--purge for config)
```

### 6.1. Ключевые C++ абстракции

```cpp
// config_model.hpp — типы конфигурации
namespace pktgate::config {

struct ObjectStore {
    std::unordered_map<std::string, std::string>              subnets;     // name → CIDR
    std::unordered_map<std::string, std::vector<std::string>> mac_groups;  // name → MACs
    std::unordered_map<std::string, std::vector<uint16_t>>    port_groups; // name → ports
};

enum class Action { Allow, Drop, Mirror, Redirect, Tag, RateLimit, Userspace };

struct AfXdpConfig {
    bool     enabled    = false;
    uint32_t queues     = 0;      // 0 = auto-detect
    bool     zero_copy  = false;
    uint32_t frame_size = 4096;
    uint32_t num_frames = 4096;
};

struct Config {
    std::string  interface;
    std::string  capacity;
    ObjectStore  objects;
    Pipeline     pipeline;    // layer_2, layer_3, layer_4
    Action       default_behavior = Action::Drop;
    AfXdpConfig  afxdp;
};
}  // namespace pktgate::config
```

```cpp
// generation_manager.hpp — double-buffer swap
namespace pktgate::pipeline {

class GenerationManager {
public:
    explicit GenerationManager(const loader::MapRegistry& registry);

    // Заполнить shadow maps скомпилированными данными
    std::expected<void, std::string> prepare(
        const compiler::CompiledObjects& objects,
        const compiler::CompiledRules& rules,
        config::Action default_action);

    // Атомарно переключить active ↔ shadow (+ 100ms drain)
    std::expected<void, std::string> commit();

    // Откатить на предыдущий generation
    std::expected<void, std::string> rollback();

    uint32_t active_generation() const;
    uint32_t shadow_generation() const;

private:
    std::atomic<uint32_t> active_gen_{0};
    const loader::MapRegistry& registry_;
    std::vector<std::vector<uint8_t>> lpm_keys_[2]; // LPM key tracking
};
}  // namespace pktgate::pipeline
```

```cpp
// pipeline_builder.hpp — orchestrator
namespace pktgate::pipeline {

class PipelineBuilder {
public:
    explicit PipelineBuilder(GenerationManager& gen_mgr);

    // validate → compile objects → compile rules → prepare → commit
    std::expected<void, std::string> deploy(
        const config::Config& cfg,
        compiler::IfindexResolver resolver);

    // Статистика последнего deploy (timing, counts)
    const std::optional<DeployStats>& last_stats() const;
};
}  // namespace pktgate::pipeline
```

### 6.2. Сборка

```bash
# Стандартная сборка
cmake -B build -DCMAKE_BUILD_TYPE=Debug
make -C build -j$(nproc)

# С покрытием кода
cmake -B build -DCOVERAGE=ON
make -C build -j$(nproc)
ctest --test-dir build --output-on-failure
make -C build coverage   # → build/coverage_html/index.html

# Запуск бенчмарков
./build/bench_compile
```

BPF pipeline сборки:
```
clang -O2 -g -target bpf -c entry.bpf.c -o entry.bpf.o
bpftool gen skeleton entry.bpf.o > entry.skel.h
```

Entry program владеет всеми maps. Layer 2/3/4 переиспользуют maps через
`bpf_map__reuse_fd()` при загрузке — все программы работают с одними и теми же maps.

**Targets:** `pktgate_ctl` (main), `libpktgate_lib.a` (static lib), 19 test executables, `bench_compile`.

---

## 7. Поток данных: от JSON до пакета

```
sample2.json
    │
    ▼
ConfigParser::parse()              → Config
    │
    ▼
ConfigValidator::validate()        → семантические проверки (rule_id, refs, params)
    │
    ▼
ObjectCompiler::compile_objects()  → CompiledObjects (MAC hash, LPM trie keys, port lists)
RuleCompiler::compile_rules()      → CompiledRules (L3: subnet+VRF, L4: expanded по портам)
    │
    ▼
GenerationManager::prepare()       → clear shadow maps → batch populate → install progs
    │
    ▼
GenerationManager::commit()        → atomic gen_config[0] = shadow_id + 100ms drain
    │
    ▼
Kernel: entry_prog                 → reads gen → tail_call → L2 → L3 → L4
    │
    ▼
Packet: XDP_DROP / XDP_PASS / bpf_redirect / mirror flag → TC / DSCP tag
```

**Deploy timing (типичные значения, ~100 L3 + 250 L4 правил):**
- Validation: ~300 us
- Object compile: ~170 us
- Rule compile: ~380 us
- Map populate: зависит от kernel (batch vs sequential)
- Commit: ~100 ms (conservative drain wait)

---

## 8. Runtime Statistics & Observability

### 8.1. Packet Statistics (`stats_map`)

Каждый BPF-программе инструментирован макросом `STAT_INC(key)` на каждом `return`.
Счётчики хранятся в `BPF_MAP_TYPE_PERCPU_ARRAY` — zero-contention между CPU.

```
enum stat_key {
    STAT_PACKETS_TOTAL       = 0,    // все пакеты, вошедшие в entry

    // Entry drops
    STAT_DROP_NO_GEN         = 1,    // gen_config lookup failed
    STAT_DROP_NO_META        = 2,    // bpf_xdp_adjust_meta / data_meta bounds failed
    STAT_DROP_ENTRY_TAIL     = 3,    // tail_call to L2 failed

    // Layer 2 drops
    STAT_DROP_L2_BOUNDS      = 4,    // packet too short for ETH header
    STAT_DROP_L2_NO_META     = 5,
    STAT_DROP_L2_NO_MAC      = 6,    // src_mac not in allow-list
    STAT_DROP_L2_TAIL        = 7,    // tail_call to L3 failed

    // Layer 3 drops
    STAT_DROP_L3_BOUNDS      = 8,
    STAT_DROP_L3_NOT_IPV4    = 9,    // non-IPv4 (ARP, IPv6, etc.)
    STAT_DROP_L3_NO_META     = 10,
    STAT_DROP_L3_RULE        = 11,   // explicit DROP in L3 rule
    STAT_DROP_L3_DEFAULT     = 12,   // default action = DROP
    STAT_DROP_L3_REDIRECT_FAIL = 13, // redirect with ifindex=0
    STAT_DROP_L3_TAIL        = 14,   // tail_call to L4 failed

    // Layer 4 drops
    STAT_DROP_L4_BOUNDS      = 15,
    STAT_DROP_L4_RULE        = 16,   // explicit DROP in L4 rule
    STAT_DROP_L4_DEFAULT     = 17,
    STAT_DROP_L4_RATE_LIMIT  = 18,   // over rate limit
    STAT_DROP_L4_NO_META     = 19,

    // Success actions
    STAT_PASS_L3             = 20,
    STAT_PASS_L4             = 21,
    STAT_REDIRECT            = 22,
    STAT_MIRROR              = 23,   // mirror flag set
    STAT_TAG                 = 24,   // DSCP/CoS tag applied
    STAT_RATE_LIMIT_PASS     = 25,   // under rate limit, passed

    // TC ingress counters
    STAT_TC_MIRROR           = 26,   // bpf_clone_redirect success
    STAT_TC_MIRROR_FAIL      = 27,   // bpf_clone_redirect failed
    STAT_TC_TAG              = 28,   // DSCP rewrite applied
    STAT_TC_NOOP             = 29,   // no deferred actions

    // Additional drops
    STAT_DROP_L3_FRAGMENT    = 30,   // IP fragment (non-first) dropped
    STAT_DROP_L4_NOT_IPV4    = 31,   // non-IPv4 reached L4

    // IPv6
    STAT_PASS_L3_V6          = 32,   // IPv6 packet passed L3
    STAT_DROP_L3_V6_RULE     = 33,   // explicit DROP in L3 IPv6 rule
    STAT_DROP_L3_V6_DEFAULT  = 34,   // IPv6 default action = DROP
    STAT_DROP_L3_V6_FRAGMENT = 35,   // IPv6 fragment header at L3
    STAT_DROP_L4_V6_FRAGMENT = 36,   // IPv6 fragment after ext headers in L4

    // AF_XDP userspace
    STAT_USERSPACE           = 37,   // redirected to AF_XDP socket
    STAT_USERSPACE_FAIL      = 38,   // bpf_redirect_map failed (no socket)

    STAT__MAX                = 39,
};
```

### 8.2. Чтение статистики

**`StatsReader`** (`src/pipeline/stats_reader.hpp`) — читает per-CPU values через
`bpf_map_lookup_elem()`, суммирует по всем CPU, выводит на stderr.

```bash
# Дамп в рантайме (SIGUSR1):
kill -USR1 $(pidof pktgate_ctl)

# Автоматический дамп при shutdown (Ctrl+C / SIGTERM)
```

### 8.3. Map Key Collision Detection

`rule_compiler.cpp` проверяет дубликаты ключей **после** port group expansion:

| Тип коллизии | Ключ | Пример |
|-------------|------|--------|
| L4 | `protocol + dst_port` | Два правила на TCP:80 (одно literal, другое через port group) |
| L3 subnet | `prefixlen + addr` | Два объекта с одним CIDR `10.0.0.0/8` |
| L3 VRF | `ifindex` | Два VRF имени, разрешающихся в один ifindex |

При обнаружении — ошибка компиляции с указанием обоих rule_id.

---

## 9. Hot Reload

### 9.1. Триггеры перезагрузки

| Триггер | Механизм | Когда |
|---------|----------|-------|
| `SIGHUP` | Signal handler → `g_reload` flag | `kill -HUP $(pidof pktgate_ctl)` |
| inotify | Directory watch → `IN_CLOSE_WRITE \| IN_MOVED_TO` | Любое изменение config файла |

Inotify следит за **директорией**, а не за файлом — это обрабатывает atomic replace
(vim: write tmp → rename, sed -i: unlink → create).

### 9.2. Debounce

Редакторы часто сохраняют файл в два шага: truncate(0) → write(data). Без debounce
первое событие спровоцирует parse пустого файла.

```
inotify event → drain events
              → poll(150ms)       ← ждём пока редактор допишет
              → drain again       ← собираем накопившиеся события
              → stat(config) > 0? ← пустой файл = пропускаем
              → do_reload()
```

### 9.3. Fail-safe reload

`do_reload()` вызывает `parse_config()` → `builder.deploy()`. Любая ошибка
(невалидный JSON, missing objects, collision, map update failure) логируется
и **не влияет на активную генерацию** — трафик продолжает идти по текущим правилам.

### 9.4. Main loop

```cpp
// poll() с 1s timeout — interruptible by signals
while (g_running) {
    poll(&pfd, nfds, 1000);

    // inotify → debounce → reload
    // SIGHUP  → reload
    // SIGUSR1 → stats dump
}
```

---

## 10. Открытые вопросы

1. ~~**XDP vs TC**~~ → **Решено**: гибридная модель XDP + TC. XDP pipeline ставит
   deferred flags в `pkt_meta.action_flags`, TC ingress (`tc_ingress.bpf.c`) выполняет
   `bpf_clone_redirect()` для mirror и `bpf_skb_store_bytes()` для DSCP rewrite.

2. ~~**VRF mapping**~~ → **Решено**: VRF определяется через `ifindex` (VRF device).
   В конфиге указывается имя VRF, resolver маппит в ifindex через `if_nametoindex()`.

3. ~~**Rate-limit точность**~~ → **Улучшено**: `rule_compiler.cpp` делит `rate_bps` на
   `libbpf_num_possible_cpus()` при компиляции правил, чтобы агрегатный лимит
   по всем CPU ≈ configured rate. Per-CPU token bucket остаётся приблизительным
   (зависит от равномерности RSS). Для точного shaping нужен `tc-htb` или `EDT`.

4. **Mirror target**: `"target_port"` маппится в ifindex через тот же resolver.
   Логические имена портов (Eth-1/10) **требуют внешний маппинг** — пока нет.

5. ~~**Масштаб правил**~~ → **Проверено бенчмарками**: 1000 subnet + 2000 L4 rules
   компилируется за ~6.6 ms. Hash lookup в BPF — O(1) per packet.

6. ~~**TC companion program**~~ → **Реализовано** (фаза 9): `tc_ingress.bpf.c` читает
   `pkt_meta` из `skb->data_meta` (передаётся из XDP через packet buffer) и выполняет
   `bpf_clone_redirect()` для mirror, `bpf_skb_store_bytes()` для DSCP rewrite.
   VLAN PCP (CoS) rewrite пока не реализован — требует `bpf_skb_vlan_push/pop`.

7. ~~**Hot reload**~~ → **Реализовано** (фаза 10): `main.cpp` использует inotify (directory watch)
   + SIGHUP для перезагрузки конфига. Debounce 150ms + проверка непустого файла защищают
   от гонок при atomic save (vim, sed -i). Ошибки парсинга/деплоя не трогают активную генерацию.

8. ~~**BPF_PROG_TEST_RUN тесты**~~ → **Реализовано** (фаза 7): 23 data plane теста
   (L2/L3/L4/pipeline/bench) через `bpf_prog_test_run_opts()`, плюс live тест на veth.

9. **LPM_TRIE не поддерживает итерацию**: `subnet_rules_0/1` — LPM_TRIE с
   `BPF_F_NO_PREALLOC`. Ядро не поддерживает `bpf_map_get_next_key` для этого типа.
   Поэтому `GenerationManager` хранит `lpm_keys_[2]` — in-memory список вставленных
   ключей для явного удаления при `clear_shadow_maps()`.
   **Проблема**: при крэше демона этот список теряется. Сейчас не критично, т.к. maps
   не pinned — при рестарте skeleton пересоздаёт все maps с нуля. Но если в будущем
   потребуются pinned maps (bpffs) для zero-downtime restart, нужно одно из:
   - **(a)** Пересоздавать shadow LPM_TRIE при старте (`close` + `bpf_map_create`)
   - **(b)** Заменить LPM_TRIE на HASH с offline prefix expansion
   - **(c)** Персистить `lpm_keys_[]` на диск (наименее предпочтительно)

---

## 11. Статус реализации

| Фаза | Описание | Статус |
|------|----------|--------|
| 1 | Архитектура (этот документ) | ✅ Завершена |
| 2 | Toolchain + окружение | ✅ Завершена |
| 3 | Реализация: 5 BPF программ (4 XDP + 1 TC) + C++23 control plane | ✅ Завершена |
| 4 | Тесты: 147 unit tests, 8 test suites, gcov/lcov | ✅ Завершена |
| 5 | Оптимизация: validator, batch updates, metrics, benchmarks | ✅ Завершена |
| 6 | Расширенные тесты: byte-layout, packet builder, round-trip, stress, concurrency (+87 тестов) | ✅ Завершена |
| 7 | BPF data plane: 23 BPF_PROG_TEST_RUN теста + live veth demo | ✅ Завершена |
| 8 | Observability: stats_map (30 per-CPU counters), SIGUSR1 dump, key collision detection | ✅ Завершена |
| 9 | TC companion program: `tc_ingress.bpf.c` — bpf_clone_redirect + DSCP rewrite | ✅ Завершена |
| 10 | Hot reload: inotify + SIGHUP, debounce, fail-safe deploy | ✅ Завершена |
| 11 | Hardening: sanitizers (ASAN/TSAN/UBSAN), fuzz harnesses, fault injection | ✅ Завершена |
| 12 | Systemd integration: service unit, install/uninstall scripts, cmake install | ✅ Завершена |
| 13 | IPv6 dual-stack: lpm_v6_key, Ipv6Prefix parser, BPF L3/L4 v6 paths, 25 tests | ✅ Завершена |
| 14 | RPM packaging: .spec, rpmbuild script, ctest in %check, systemd scriptlets | ✅ Завершена |
| 15 | Functional tests: pytest+scapy, 84 теста через реальный XDP трафик на veth | ✅ Завершена |
| 16 | Audit: IPv6 stats/fragments, reload race guard, CI/CD, README | ✅ Завершена |
| 17 | Mirror/redirect e2e tests, fuzz CI (smoke + overnight), TEST_PLAN.md | ✅ Завершена |
| 18 | AF_XDP userspace fast path: MapRegistry, BPF data plane, config, sockets, tests | ✅ Завершена |

**Тесты: 500+ test points** (19 ctest targets + 104 functional + 3 fuzz harnesses).
Полный тест-план: [TEST_PLAN.md](TEST_PLAN.md).

### Тестовые наборы

| Suite | Тестов | Категория |
|-------|--------|-----------|
| config_parser | 24 | JSON parsing, error handling |
| object_compiler | 14 | MAC/subnet/port compilation |
| generation_logic | 15 | Generation state machine, rollback |
| net_types | 26 | IP/MAC parsing, CIDR, utilities |
| config_validation | 30 | Config validation (negative) |
| rule_compiler_edge | 47 | Rule compiler edge cases, key collision detection |
| pipeline_integration | 27 | E2E pipeline, reload, stress 500+ rules |
| config_validator | 27 | Semantic validation |
| byte_layout | 31 | Map key/value byte-level verification |
| packet_builder | 17 | ETH/IP/TCP/UDP header correctness |
| roundtrip | 17 | Parse → validate → compile → verify |
| stress | 9 | 4096 rules, 16K subnets, 1000 ports |
| concurrency | 13 | Multi-threaded gen swap, double-buffer |
| fault_injection | 13 | Truncation, byte flip, random mutation, edge-case inputs |
| ipv6 | 52 | IPv6 prefix parsing, byte layout, rule compilation, dual-stack, config, validation |
| bpf_dataplane | 23 | BPF_PROG_TEST_RUN (L2/L3/L4/pipeline/bench, requires sudo) |
| prometheus | 7 | HTTP /metrics, concurrent scrapes, metric coverage |
| map_registry | 6 | MapRegistry: generational/shared FD lookup, convenience accessors |
| afxdp_config | 12 | AF_XDP config parse, validate, compile, round-trip |

### Functional тесты (pytest + scapy, 104 теста)

Реальный XDP трафик через veth-пары в network namespaces.
Запуск: `sudo bash functional_tests/run.sh`

| Файл | Тестов | Что проверяет |
|------|--------|---------------|
| test_l2_mac | 8 | MAC allow/deny, broadcast, spoofing |
| test_l3_subnet | 15 | IPv4 subnet LPM, CIDR, multi-rule |
| test_l3_ipv6 | 10 | IPv6 fragments, extension headers, L4 parsing |
| test_l4_ports | 16 | TCP/UDP port match, port groups |
| test_dscp_tag | 3 | DSCP EF rewrite в TC, TOS verification |
| test_pipeline | 11 | Cross-layer interactions, default behavior |
| test_malformed | 15 | Truncated/invalid packets |
| test_zz_lifecycle | 4 | SIGTERM, SIGHUP, SIGUSR1, restart |
| test_zz_reload | 3 | inotify reload, no downtime |
| test_zz_gen_swap | 2 | Generation swap, double-buffer |
| test_zz_config_edge | 5 | default:allow, many MACs, 50 port groups |
| test_zz_rate_limit | 2 | Token bucket, burst drop rate |
| test_zz_mirror_redirect | 10 | Mirror clone, redirect, IPv6, Prometheus metrics |

### Fuzz harnesses (3 target, libFuzzer / standalone)

| Target | Corpus | Что фаззит |
|--------|--------|------------|
| fuzz_config_parser | fuzz/corpus_config/ | JSON parser |
| fuzz_net_types | fuzz/corpus_net/ | MAC/IP parsing |
| fuzz_roundtrip | fuzz/corpus_roundtrip/ | parse → validate → compile |

CI: `.github/workflows/fuzz.yml` — smoke (60с на PR) + overnight (cron, corpus caching).

### BPF data plane benchmarks (BPF_PROG_TEST_RUN, 1M packets)

| Path | ns/pkt | Mpps |
|------|--------|------|
| L2 MAC drop | 76 | ~13.2 |
| L4 TCP:80 allow | 90 | ~11.1 |
| L3 LPM + L4 full pipeline | 165 | ~6.1 |

*С per-packet STAT_INC (percpu array). ~8-10% overhead vs без статистики.*

### Live demo (veth)

Скрипты в `demo/`:
- `setup_veth.sh` — создаёт `ns_pktgate`/`ns_client` + veth пару
- `cleanup_veth.sh` — удаляет namespaces
- `veth_config.json` — конфиг для live теста

`BpfLoader::attach()` автоматически определяет native vs SKB XDP mode.

### Systemd deployment

```bash
# Быстрая установка
sudo scripts/install.sh

# Или через cmake
cmake -B build -DCMAKE_BUILD_TYPE=Release
make -C build -j$(nproc)
sudo make -C build install

# Управление
systemctl start pktgate          # запуск
systemctl enable pktgate         # автозапуск
systemctl reload pktgate         # SIGHUP → hot reload конфига
systemctl status pktgate         # статус
journalctl -u pktgate -f         # логи (JSON)
kill -USR1 $(pidof pktgate_ctl)  # дамп статистики

# Удаление
sudo scripts/uninstall.sh           # сохранить конфиг
sudo scripts/uninstall.sh --purge   # удалить всё
```

Файлы:
- `/usr/local/bin/pktgate_ctl` — бинарь
- `/etc/pktgate/config.json` — конфигурация pipeline
- `/etc/pktgate/pktgate.conf` — env overrides (extra args, alt config path)
- `/etc/systemd/system/pktgate.service` — systemd unit

Security hardening в unit: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
минимальный `CapabilityBoundingSet` (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_PERFMON).

### RPM packaging

```bash
# Сборка RPM (на Debian/Ubuntu — cross-build, на Fedora/RHEL — нативно)
scripts/build_rpm.sh

# Через mock (clean-room, Fedora)
scripts/build_rpm.sh --mock

# Результат
~/rpmbuild/RPMS/x86_64/pktgate-1.0.0-1.x86_64.rpm

# Установка на целевом хосте (Fedora/RHEL)
sudo rpm -ivh pktgate-1.0.0-1.x86_64.rpm
systemctl enable --now filter
```

Файлы:
- `rpm/pktgate.spec` — RPM spec (cmake build, ctest %check, systemd scriptlets)
- `scripts/build_rpm.sh` — обёртка над rpmbuild (source tree + spec copy)

### Следующие шаги

1. **AF_XDP functional tests** — pytest+scapy через veth с реальным AF_XDP трафиком (copy mode).
2. **Custom PacketCallback** — API для пользовательской обработки (DPI, analytics, custom forwarding).
3. **VLAN CoS rewrite** — `bpf_skb_vlan_push/pop` в TC для CoS tagging.
4. **Coverage-guided fuzzing** — запустить fuzz harnesses с реальным corpus-ом длительно.
