# ARCHITECTURE.md — eBPF Packet Filter Pipeline

Internal design document for developers. For user-facing config format see
[CONFIG.md](CONFIG.md). For build and usage see [README.md](README.md).

## 1. Обзор среды и зависимости

| Компонент        | Статус            | Требуется                          |
|------------------|-------------------|------------------------------------|
| Kernel           | 6.1.0-43 (OK)    | >= 5.15 для BPF_MAP_TYPE_LPM_TRIE, tail calls, atomic ops |
| clang            | ✅ установлен     | `clang-19` (CI), `clang-16`+ для local build |
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
│  │  │ L2 hash  │ │ LPM trie │ │Port hash │            │ │
│  │  │(4 types) │ │(subnet)  │ │ (L4)     │            │ │
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
// Single composite-key HASH (post-#10 refactor). Previously 5 per-field maps
// were probed in lexical order, which paid 5× hash lookups per packet AND
// silently dropped fields beyond the lexically-first one in compound rules.
//
// Now: one l2_rules_{gen} HASH keyed on `struct l2_key` (all five possible
// fields + a filter_mask bit naming which fields the rule actually constrains).
// Fields the rule doesn't pin are zero. A second tiny ARRAY l2_active_masks_{gen}
// (max 8 entries) lists the distinct filter_mask values currently present, so
// the BPF datapath knows which projections to try without scanning all 32
// combinations.

struct l2_key {
    __u8  filter_mask;     // FILTER_MASK_{PCP,ETHERTYPE,VLAN,SRCMAC,DSTMAC}
    __u8  pcp;             // 0-7,  valid iff PCP bit
    __u16 ethertype;       // NBO,  valid iff ETHERTYPE bit
    __u16 vlan_id;         // host, valid iff VLAN bit
    __u8  src_mac[6];      // valid iff SRCMAC bit
    __u8  dst_mac[6];      // valid iff DSTMAC bit
    __u8  _pad[2];
};

struct l2_rule {
    __u32 rule_id;
    __u32 action;            // ACT_ALLOW/DROP/REDIRECT/MIRROR
    __u32 redirect_ifindex;
    __u32 mirror_ifindex;
    __u8  next_layer;        // 0=terminal, LAYER_3_IDX, LAYER_4_IDX
    __u8  _pad[3];
};

// BPF datapath (layer2_prog):
//   1. parse_l2 — extract pcp, ethertype, vlan_id, src_mac, dst_mac from the
//      packet, then for each i ∈ [0, MAX_L2_MASKS):
//        mask = l2_active_masks_{gen}[i]
//        if mask == 0: break
//        build_l2_key(out, mask, parsed_fields)  // project parsed → keyed
//        rule = lookup(l2_rules_{gen}, out)
//        if rule: dispatch action (first-match wins, masks sorted by popcount
//                 desc at deploy time so most-specific rule fires first).
//
// 802.1Q parsing: если h_proto == 0x8100, извлекается vlan_id и inner
// ethertype. QinQ (0x88a8) не парсится — отложено (см. §"Known limitations"
// ниже). Тест `test_l2_qinq_documented_unsupported` пинит текущее
// поведение и должен быть переписан при добавлении 0x88a8 в parse_l2.
//
// On no match L2 consults layer_present_{gen}[0]:
//   - bit LAYER_PRESENT_L2 set → apply configured default_behavior
//     (mirrors L3/L4: STAT_DROP_L2_NO_MATCH on drop, STAT_PASS_L2 on allow).
//   - bit unset → skip to Layer 3 unchanged (preserves "L3-only config" UX
//     where layer_2: [] is treated as no opinion, not "drop everything").
// The flag is populated at deploy time by GenerationManager::set_layer_present
// from `rules.l2_rules.empty()`. A planned follow-up adds per-layer
// default_behavior so operators can be explicit instead of relying on
// emptiness-as-skip.
//
// Latency note: bench_l2_no_match_fallthrough_1M shows ~590 ns/pkt
// post-refactor vs ~294 ns pre-refactor — the verifier doesn't optimise
// the unrolled mask-iteration as well as the design predicted. Tracked
// as a follow-up (see _review/HANDOVER.md §performance).
```

### 3.3. Layer 3 — IP / VRF Filtering

```c
// BPF_MAP_TYPE_LPM_TRIE — IPv4 subnets
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};
// compile-time assert: sizeof == 8 (no padding) — in common.h for BPF and C++

// BPF_MAP_TYPE_LPM_TRIE — IPv6 subnets (post-P0-03/04: IPv6 as a class)
struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];          // network byte order
};

// IPv4 path:
//   match по src_ip → lookup в subnet_rules_{gen} → action
//   match по vrf  → lookup в vrf_rules_{gen} keyed by ingress_ifindex
//   non-first fragments (frag_off & 0x1FFF != 0) → drop in L3
//     (no L4 header to inspect). Counter: STAT_DROP_L3_FRAGMENT.
//
// IPv6 path:
//   1. Stamp pkt_meta.ip_family = IP_FAMILY_V6 — every downstream action site
//      gates on this so IPv4-shaped writes (DSCP via iph->tos, ipv4 LPM, …)
//      can't fire on v6 traffic (closed P0-03/04 family-leak bugs).
//   2. Walk up to 4 extension headers searching for Fragment (nexthdr=44).
//      Any Fragment → drop with STAT_DROP_L3_V6_FRAGMENT. Closes the old
//      "Hop-by-Hop → Fragment hides from L3" bypass; L4 walks again for
//      defense in depth and bumps STAT_DROP_L4_V6_FRAGMENT.
//   3. Bound exhausted with chain still on an ext-header → fail-closed
//      drop with STAT_DROP_L3_V6_EXT_DEPTH (mirror at L4).
//   4. subnet6_rules_{gen} lookup (LPM v6) → action.
//
// Actions (both v4 and v6):
//   - mirror: defer to TC via pkt_meta.action_flags |= (1 << ACT_MIRROR);
//     TC ingress then bpf_clone_redirect(skb, mirror_ifindex, 0). See 3.6.
//   - redirect: bpf_redirect(ifindex, 0) at XDP — bypasses TC.
//
// src_ip / dst_ip are full first-class match fields: each routes into its
// own LPM_TRIE map (subnet_rules_{0,1} keyed on src, subnet_rules_dst_{0,1}
// keyed on dst). Lookup order is src → dst → VRF → default; source matches
// win when both apply. Same shape for IPv6 (subnet6_rules*). src+dst in
// one rule is rejected at validation — composite-key L3 is not implemented;
// operators wanting AND should split into two rules.
//
// History: dst_ip used to be silently parsed and dropped by the compiler,
// turning narrow drops into 0.0.0.0/0 wildcards (P0-01 Gi-blackhole).
// Validator then rejected it outright as a stop-gap; real destination
// LPM support landed afterwards.
```

### 3.4. Layer 4 — Transport Filtering

```c
// BPF_MAP_TYPE_HASH — port_groups
struct port_key { __u16 port; };
struct port_val { __u32 group_id; };  // к какой группе принадлежит порт

// match: protocol + dst_port (object lookup)
// action: tag → модификация DSCP в IPv4 TOS (CoS/PCP — пока не поддерживается, отвергается валидатором)
// action: rate-limit → token bucket через per-CPU map
```

### 3.5. Действия (Actions)

| Action      | Реализация                                                        | Hook    |
|-------------|-------------------------------------------------------------------|---------|
| `allow`     | Передать в следующий слой или `XDP_PASS`                          | XDP     |
| `drop`      | `XDP_DROP`                                                        | XDP     |
| `mirror`    | `bpf_clone_redirect(skb, ifindex, 0)` — **только TC**            | TC      |
| `redirect`  | `bpf_redirect(ifindex, 0)` — перенаправление в другой VRF/порт   | XDP/TC  |
| `tag`       | IPv4: перезапись DSCP — `iph->tos = (iph->tos & 0x3) \| (dscp << 2)` + L3 checksum update. IPv6: stub (`STAT_TC_TAG_V6_UNIMPL`, требует отдельной реализации). `cos` (802.1p PCP rewrite) отвергается валидатором — нужен `bpf_skb_vlan_push/pop` | TC |
| `rate-limit`| Per-CPU token bucket: `PERCPU_HASH`, rate/online_cpus (P1#6 — was possible CPUs, ~1000× under-limit on stock NR_CPUS=8192 kernels), 1s burst cap, elapsed clamp. State garbage-collected at every commit() — keys not in the new active rate-limit ruleset are pruned, preventing the 4096-entry leak that previously silently disabled rate-limit (P1#7) | XDP |

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

---

## 4. BPF Maps — полная схема

```
┌────────────────────────┬──────────────────────┬──────────────────────────────┐
│ Name                   │ Type                 │ Key → Value                  │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ gen_config             │ ARRAY(1)             │ 0 → active_gen (__u32)       │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ prog_array_0/1         │ PROG_ARRAY(4)        │ layer_idx → prog_fd          │
│ l2_rules_0/1           │ HASH(16384)          │ l2_key → l2_rule             │
│ l2_active_masks_0/1    │ ARRAY(8)             │ slot → __u8 (filter_mask)    │
│ subnet_rules_0/1       │ LPM_TRIE(16384)      │ lpm_v4_key → l3_rule         │
│ subnet6_rules_0/1      │ LPM_TRIE(16384)      │ lpm_v6_key → l3_rule         │
│ vrf_rules_0/1          │ HASH(256)            │ vrf_key → l3_rule            │
│ l4_rules_0/1           │ HASH(4096)           │ l4_match_key → l4_rule       │
│ default_action_0/1     │ ARRAY(1)             │ 0 → __u32 (filter_action)    │
│ layer_present_0/1      │ ARRAY(1)             │ 0 → __u8 (LAYER_PRESENT_*)   │
├────────────────────────┼──────────────────────┼──────────────────────────────┤
│ rate_state_map         │ PERCPU_HASH(4096)    │ rule_id → rate_state         │
│ stats_map              │ PERCPU_ARRAY(45)     │ stat_key → __u64 (packets)   │
│ bytes_map              │ PERCPU_ARRAY(45)     │ stat_key → __u64 (bytes)     │
└────────────────────────┴──────────────────────┴──────────────────────────────┘

Итого 23 maps: 4 shared + 9×2 double-buffered + 1 rate_state.
Maps _0/_1 — двойная буферизация для generation swap.
rate_state_map, stats_map, bytes_map общие (не буферизируются).
stats_map / bytes_map — 45 per-CPU слотов (packet+byte counters in parallel,
keyed identically). Полный enum stat_key в секции 8.

Per-map capacity is enforced TWICE: kernel via `max_entries`, and userspace
in `compile_rules` (P1#10) before deploy so an oversize config is rejected
with a named diagnostic ("Map capacity exceeded: L4 rules has 8000 entries
(cap 4096)") instead of failing mid-batch-update with -E2BIG.
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
    __u8  ip_family;        // IP_FAMILY_V4 | IP_FAMILY_V6 — stamped by L3,
                            //   read by L4/TC to gate v4-shaped writes
    __u8  _pad;
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
│ l2_src_mac_0 │               │ l2_src_mac_1 │  ← CP заполняет
│ l2_dst_mac_0 │               │ l2_dst_mac_1 │     новыми данными
│ l2_ether*_0  │               │ l2_ether*_1  │
│ l2_vlan_0    │               │ l2_vlan_1    │
│ subnet_0     │               │ subnet_1     │
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

2. Заполнить все shadow maps (l2_*_{shadow}, subnet_{shadow}, ...)
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
│   ├── layer2.bpf.c             ← L2 filter (src/dst MAC, ethertype, VLAN)
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
│   │   ├── rule_compiler.hpp    ← Pipeline → CompiledRules (L2/L3/L4 BPF entries)
│   │   └── rule_compiler.cpp    ← L2 rule compilation, port group expansion, key collision detection, rate/ncpus
│   │
│   ├── loader/
│   │   ├── bpf_loader.hpp       ← libbpf skeleton wrapper (4 programs, map reuse)
│   │   ├── bpf_loader.cpp
│   │   ├── map_manager.hpp      ← CRUD для BPF maps + batch_update
│   │   └── map_manager.cpp      ← batch_update с fallback, safe hash iteration
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
├── tests/                       ← 466 тестов в 17 сьютах
│   ├── test_config_parser.cpp       (41 тест)   — JSON парсинг, DSCP, bandwidth, L2 fields
│   ├── test_config_validation.cpp   (30 тестов)  — edge cases, все action/DSCP types
│   ├── test_config_validator.cpp    (51 тест)    — семантика: refs, duplicates, params, L2 extended
│   ├── test_object_compiler.cpp     (14 тестов)  — MAC/subnet/port компиляция
│   ├── test_rule_compiler_edge.cpp  (67 тестов)  — refs, expansion, collisions, layout, L2 rules
│   ├── test_net_types.cpp           (26 тестов)  — MacAddr, Ipv4Prefix парсинг
│   ├── test_generation_logic.cpp    (15 тестов)  — state machine генераций
│   ├── test_pipeline_integration.cpp (27 тестов) — E2E compile, reload, stress 500+ rules
│   ├── test_byte_layout.cpp         (31 тест)   — map key/value byte-level
│   ├── test_packet_builder.cpp      (17 тестов)  — ETH/IP/TCP/UDP headers
│   ├── test_roundtrip.cpp           (17 тестов)  — parse → validate → compile → verify
│   ├── test_stress.cpp              (9 тестов)   — 4096 rules, 16K subnets
│   ├── test_concurrency.cpp         (13 тестов)  — multi-threaded gen swap
│   ├── test_ipv6.cpp                (52 теста)   — IPv6 prefixes, byte layout, dual-stack
│   ├── test_fault_injection.cpp     (13 тестов)  — truncation, byte flip, mutation
│   ├── test_prometheus.cpp          (7 тестов)   — HTTP /metrics, concurrent scrapes
│   ├── bpf/test_bpf_dataplane.cpp   (36 тестов)  — BPF_PROG_TEST_RUN (requires sudo)
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

enum class Action { Allow, Drop, Mirror, Redirect, Tag, RateLimit };

struct Config {
    std::string interface;
    std::string capacity;
    ObjectStore objects;
    Pipeline    pipeline;    // layer_2, layer_3, layer_4
    Action      default_behavior = Action::Drop;
};
}  // namespace pktgate::config
```

```cpp
// generation_manager.hpp — double-buffer swap
namespace pktgate::pipeline {

class GenerationManager {
public:
    explicit GenerationManager(loader::BpfLoader& loader);

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
    loader::BpfLoader& loader_;
    std::vector<std::vector<uint8_t>> lpm_keys_[2]; // LPM key tracking
};
}  // namespace pktgate::pipeline
```

```cpp
// pipeline_builder.hpp — orchestrator
namespace pktgate::pipeline {

class PipelineBuilder {
public:
    PipelineBuilder(loader::BpfLoader& loader, GenerationManager& gen_mgr);

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

**Targets:** `pktgate_ctl` (main), `libpktgate_lib.a` (static lib), 8 test executables, `bench_compile`.

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
RuleCompiler::compile_rules()      → CompiledRules (L2: 4 match types, L3: subnet+VRF, L4: expanded по портам)
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
    STAT_DROP_L2_NO_MATCH    = 6,    // no L2 rule matched
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
    STAT_TC_NOOP             = 29,   // XDP ran, no deferred TC action

    // Additional drops
    STAT_DROP_L3_FRAGMENT    = 30,   // IP fragment (non-first) dropped
    STAT_DROP_L4_NOT_IPV4    = 31,   // non-IPv4 reached L4

    // IPv6
    STAT_PASS_L3_V6          = 32,   // IPv6 packet passed L3
    STAT_DROP_L3_V6_RULE     = 33,   // explicit DROP in L3 IPv6 rule
    STAT_DROP_L3_V6_DEFAULT  = 34,   // IPv6 default action = DROP
    STAT_DROP_L3_V6_FRAGMENT = 35,   // IPv6 fragment header at L3
    STAT_DROP_L4_V6_FRAGMENT = 36,   // IPv6 fragment after ext headers in L4

    // L2 extended
    STAT_DROP_L2_RULE        = 37,   // explicit DROP in L2 rule
    STAT_PASS_L2             = 38,   // L2 rule ALLOW (terminal, no next_layer)
    STAT_DROP_L2_REDIRECT_FAIL = 39, // L2 redirect with ifindex=0

    // IPv6 ext-header hardening (P0-03/04, P1#8)
    STAT_DROP_L4_V6_EXT_DEPTH = 40,  // L4 ext-header walker fail-closed
    STAT_DROP_L3_V6_EXT_DEPTH = 41,  // L3 ext-header walker fail-closed
    STAT_TC_TAG_V6_UNIMPL    = 42,   // TC ACT_TAG on IPv6 — TC rewrite TBD

    // TC observability split (P1#13/P1#14)
    STAT_TC_NO_META          = 43,   // TC entered without XDP data_meta —
                                     //   XDP detached or driver stripped meta
    STAT_TC_MIRROR_NO_IFINDEX = 44,  // ACT_MIRROR with mirror_ifindex==0

    STAT__MAX                = 45,
};
```

`bytes_map` (added in P0-08) shares the same key space, accumulating
bytes instead of packets. Each `STAT_COUNT(key, pkt_len)` site bumps
both maps; `STAT_INC(key)` bumps only the packet counter. Prometheus
exporter emits `*_packets_total` and `*_bytes_total` series in parallel.

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
| L2 src_mac | `mac_key` | Два правила на один и тот же src_mac (literal или через mac_group) |
| L2 dst_mac | `mac_key` | Два правила на один и тот же dst_mac |
| L2 ethertype | `ethertype_key` | "IPv4" и "0x0800" — одно значение в NBO |
| L2 vlan | `vlan_key` | Два правила на один vlan_id |
| L4 | `protocol + dst_port` | Два правила на TCP:80 (одно literal, другое через port group) |
| L3 subnet | `prefixlen + addr` | Два объекта с одним CIDR `10.0.0.0/8` |
| L3 VRF | `ifindex` | Два VRF имени, разрешающихся в один ifindex |

L2 коллизии отслеживаются **по типу** — один и тот же MAC в src_mac и dst_mac правилах не коллидирует (разные maps).

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

## 9a. Known limitations

Фичи, которые осознанно отложены, но которые могут быть упомянуты в тестах
или конфигах. Любой тест, который ассертит «здесь работает X неправильно»,
должен ссылаться сюда — иначе тест становится contract'ом (false safety).

### 9a.1. QinQ (802.1ad, 0x88a8) outer tag не парсится

- **Симптом**: пакеты с outer ethertype 0x88a8 (S-Tag) проходят через `parse_l2`
  без извлечения `vlan_id`, потому что код проверяет только 0x8100. На L3 такой
  кадр выглядит как «не-IPv4/v6» и дропается с `STAT_DROP_L3_NOT_IPV4`.
- **Влияние**: на carrier Gi-side filter, где S-Tag (0x88a8) outer + C-Tag (0x8100)
  inner — типовая схема, **все правила с `vlan_id` молча промахиваются** на QinQ
  трафике, а сам трафик дропается на L3 даже без явного DROP-правила.
- **Цена фикса**: ~20 LOC в `bpf/layer2.bpf.c::parse_l2` — добавить ветку
  `h_proto == 0x88a8`, читать ещё 4 байта, доставать inner `vlan_id` из второго
  тэга. Field `vlan_id` уже host byte order, остальные поля совместимы.
- **Тест-якорь**: `tests/bpf/test_bpf_dataplane.cpp::test_l2_qinq_documented_unsupported`
  — assert `XDP_DROP`. Этот ассерт **должен перевернуться** одновременно с фиксом:
  переименование `_documented_unsupported` явно сигналит проверяющему, что
  ассерт фиксирует bug-by-design, а не желаемое поведение.
- **Состояние**: открыто. Tracking — TEST_AUDIT §"Phase 2c P1 — QinQ".

### 9a.2. Rate-limit reload — emergent regression (open)

- **Symptom**: configuring `bandwidth: "100Kbps"`, generating partial-drop
  baseline, then `reload_config({bandwidth: "1Mbps"})` causes the rate-limit
  rule to drop **everything** in the post-reload generation (functional
  test observed `low=41`, `high=0` over a 500-packet burst). Pre-reload
  works fine.
- **Possible roots**:
  - inotify-triggered reload races with XDP attach state on the new generation
  - `rate_state_map` carries stale per-CPU buckets from generation 0 into
    generation 1 (was the suspected P1#7 surface; we landed GC of stale
    entries in commit `a0d2f8e`, but only via online_cpu accounting — not
    a clean-on-rule-replace).
- **Test-anchor**: `functional_tests/test_zz_rate_limit.py::TestRateLimit::test_reload_changes_effective_rate`
  is marked `@pytest.mark.xfail(strict=False)` — will flip to `XPASS` the
  moment the underlying behaviour is fixed.
- **State**: open. Filed 2026-05-13 while building out testing-roadmap #7.

### 9a.3. (place future deferred-by-design items here)

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

8. ~~**BPF_PROG_TEST_RUN тесты**~~ → **Реализовано** (фаза 7+18): 36 data plane тестов
   (L2 extended/L3/L4/pipeline/bench) через `bpf_prog_test_run_opts()` с `ctx_in` для data_meta, плюс live тест на veth.

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
| 18 | L2 extended filtering: dst_mac, ethertype, vlan_id — full stack + 71 тест | ✅ Завершена |

**Тесты: 570+ test points** (17 ctest targets / 466 тестов + 104 functional + 3 fuzz harnesses).
Полный тест-план: [TEST_PLAN.md](TEST_PLAN.md).

### Тестовые наборы

| Suite | Тестов | Категория |
|-------|--------|-----------|
| config_parser | 41 | JSON parsing, error handling, L2 field parsing |
| object_compiler | 14 | MAC/subnet/port compilation |
| generation_logic | 15 | Generation state machine, rollback |
| net_types | 26 | IP/MAC parsing, CIDR, utilities |
| config_validation | 30 | Config validation (negative) |
| rule_compiler_edge | 67 | Rule compiler edge cases, key collision detection, L2 rules |
| pipeline_integration | 27 | E2E pipeline, reload, stress 500+ rules |
| config_validator | 51 | Semantic validation, L2 match field constraints |
| byte_layout | 31 | Map key/value byte-level verification |
| packet_builder | 17 | ETH/IP/TCP/UDP header correctness |
| roundtrip | 17 | Parse → validate → compile → verify |
| stress | 9 | 4096 rules, 16K subnets, 1000 ports |
| concurrency | 13 | Multi-threaded gen swap, double-buffer |
| fault_injection | 13 | Truncation, byte flip, random mutation, edge-case inputs |
| ipv6 | 52 | IPv6 prefix parsing, byte layout, rule compilation, dual-stack, config, validation |
| bpf_dataplane | 36 | BPF_PROG_TEST_RUN (L2 extended/L3/L4/pipeline/bench, requires sudo) |
| prometheus | 7 | HTTP /metrics, concurrent scrapes, metric coverage |

### Functional тесты (pytest + scapy, 104 теста)

Реальный XDP трафик через veth-пары в network namespaces.
Запуск: `sudo bash functional_tests/run.sh`

| Файл | Тестов | Что проверяет |
|------|--------|---------------|
| test_l2_mac | 8 | MAC src/dst match, broadcast, spoofing |
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
`NoNewPrivileges=yes`, `SystemCallFilter=@system-service @network-io @file-system`,
минимальный `CapabilityBoundingSet` (CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON).

### Fail-safe contract

`Type=notify` + `WatchdogSec=30`. `pktgate_ctl` пишет `READY=1` после успешного
attach и пингует `WATCHDOG=1` раз в секунду из главного цикла. Если 30 секунд
ping'а нет — systemd убивает и рестартит. `Restart=on-failure` + `RestartSec=3`.

Что происходит при разных видах сбоя:
- **Crash (SIGSEGV/abort)** — ядро держит последнюю загруженную XDP-программу
  на интерфейсе; трафик продолжает фильтроваться по замороженной generation
  пока systemd не запустит pktgate_ctl снова (≤ 3 с по `RestartSec`).
- **Stop (SIGTERM / `systemctl stop`)** — `loader.detach()` отвязывает XDP +
  TC, трафик идёт **нефильтрованным**. Это явный fail-open для plannned
  shutdown'ов. На время рестарта (≤ 3 с) при `systemctl restart` тоже.
- **BPF load failure при старте** — pktgate_ctl выходит с ошибкой, XDP не
  привязан вообще, трафик нефильтрованный, systemd рестартит по `on-failure`.
- **Watchdog miss (зависание в main loop)** — systemd киляет, перезапускает.
  Текущая загруженная BPF-программа остаётся на интерфейсе до момента
  `detach()` нового процесса (т.е. практически не видна).

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

1. **Coverage-guided fuzzing** — запустить fuzz harnesses с реальным corpus-ом длительно.
2. **VLAN CoS rewrite** — `bpf_skb_vlan_push/pop` в TC для CoS tagging.
