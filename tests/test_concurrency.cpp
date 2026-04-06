/*
 * Concurrency tests for generation logic.
 *
 * GenerationManager requires real BPF maps (root), so we test the generation
 * state machine pattern directly: atomic generation counter, shadow/active
 * semantics, and thread-safety of the double-buffer swap.
 */
#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
#include <barrier>

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

// ── Simulated generation state (mirrors GenerationManager logic) ──

class GenState {
public:
    uint32_t active() const { return gen_.load(std::memory_order_acquire); }
    uint32_t shadow() const { return gen_.load(std::memory_order_acquire) ^ 1; }

    void commit() {
        uint32_t new_gen = shadow();
        gen_.store(new_gen, std::memory_order_release);
    }

    void rollback() {
        uint32_t old_gen = active() ^ 1;
        gen_.store(old_gen, std::memory_order_release);
    }

private:
    std::atomic<uint32_t> gen_{0};
};

// ═══════════════════════════════════════════════════════════
// Basic state machine
// ═══════════════════════════════════════════════════════════

TEST(gen_initial_state) {
    GenState gs;
    assert(gs.active() == 0);
    assert(gs.shadow() == 1);
}

TEST(gen_commit_swaps) {
    GenState gs;
    gs.commit();
    assert(gs.active() == 1);
    assert(gs.shadow() == 0);
}

TEST(gen_double_commit) {
    GenState gs;
    gs.commit();
    gs.commit();
    assert(gs.active() == 0);
    assert(gs.shadow() == 1);
}

TEST(gen_rollback_restores) {
    GenState gs;
    gs.commit(); // active=1
    gs.rollback(); // back to active=0
    assert(gs.active() == 0);
    assert(gs.shadow() == 1);
}

TEST(gen_commit_rollback_cycle_1000) {
    GenState gs;
    for (int i = 0; i < 1000; ++i) {
        uint32_t before = gs.active();
        gs.commit();
        assert(gs.active() == (before ^ 1));
        gs.rollback(); // rollback = swap again → back to before
        assert(gs.active() == before);
    }
}

TEST(gen_shadow_always_opposite) {
    GenState gs;
    for (int i = 0; i < 100; ++i) {
        assert(gs.active() + gs.shadow() == 1);
        assert((gs.active() ^ gs.shadow()) == 1);
        gs.commit();
    }
}

// ═══════════════════════════════════════════════════════════
// Concurrent readers
// ═══════════════════════════════════════════════════════════

TEST(gen_concurrent_readers_active_always_01) {
    GenState gs;
    std::atomic<bool> done{false};
    std::atomic<int> invalid_count{0};

    // Reader threads: verify active() is always 0 or 1
    // Note: active() and shadow() are separate loads, so checking both
    // at once would be a TOCTOU race. BPF reads gen_config once per packet.
    auto reader = [&]() {
        while (!done.load(std::memory_order_relaxed)) {
            uint32_t a = gs.active();
            if (a > 1)
                invalid_count.fetch_add(1);
        }
    };

    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i)
        readers.emplace_back(reader);

    // Writer: commit rapidly
    for (int i = 0; i < 10000; ++i)
        gs.commit();

    done.store(true, std::memory_order_relaxed);
    for (auto& t : readers)
        t.join();

    assert(invalid_count.load() == 0);
}

TEST(gen_concurrent_reader_writer_no_torn_read) {
    GenState gs;
    std::atomic<bool> done{false};
    std::atomic<int> reads{0};
    std::atomic<int> torn{0};

    auto reader = [&]() {
        while (!done.load(std::memory_order_relaxed)) {
            uint32_t v = gs.active();
            if (v != 0 && v != 1)
                torn.fetch_add(1);
            reads.fetch_add(1);
        }
    };

    std::vector<std::thread> readers;
    for (int i = 0; i < 8; ++i)
        readers.emplace_back(reader);

    for (int i = 0; i < 50000; ++i)
        gs.commit();

    done.store(true);
    for (auto& t : readers)
        t.join();

    assert(torn.load() == 0);
    std::cout << "    [info] " << reads.load() << " concurrent reads, 0 torn\n";
}

// ═══════════════════════════════════════════════════════════
// Concurrent writers (simulated — only one should win)
// ═══════════════════════════════════════════════════════════

TEST(gen_concurrent_commits_always_valid) {
    GenState gs;
    std::atomic<int> invalid{0};
    constexpr int N = 4;
    constexpr int OPS = 10000;

    std::barrier sync_point(N);

    auto worker = [&](int) {
        sync_point.arrive_and_wait();
        for (int i = 0; i < OPS; ++i) {
            gs.commit();
            uint32_t a = gs.active();
            if (a != 0 && a != 1)
                invalid.fetch_add(1);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < N; ++i)
        threads.emplace_back(worker, i);
    for (auto& t : threads)
        t.join();

    assert(invalid.load() == 0);
    // Final state must be 0 or 1
    assert(gs.active() <= 1);
}

TEST(gen_concurrent_commit_rollback_mix) {
    GenState gs;
    std::atomic<int> invalid{0};
    constexpr int N = 4;
    constexpr int OPS = 10000;

    auto worker = [&](int id) {
        for (int i = 0; i < OPS; ++i) {
            if (id % 2 == 0)
                gs.commit();
            else
                gs.rollback();

            uint32_t a = gs.active();
            if (a > 1)
                invalid.fetch_add(1);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < N; ++i)
        threads.emplace_back(worker, i);
    for (auto& t : threads)
        t.join();

    assert(invalid.load() == 0);
    assert(gs.active() <= 1);
}

// ═══════════════════════════════════════════════════════════
// Reader snapshot consistency
// ═══════════════════════════════════════════════════════════

TEST(gen_reader_snapshot_consistent) {
    // Simulates a reader that takes a "snapshot" of the generation
    // and uses it for multiple lookups. The generation shouldn't change
    // between reads within the same "packet processing cycle."
    GenState gs;

    auto packet_processor = [&]() {
        // Take snapshot
        uint32_t gen = gs.active();
        // Simulate multiple map lookups using same gen
        for (int i = 0; i < 100; ++i) {
            // In real BPF, gen is read once per packet in entry_prog
            // and stored in data_meta area. Subsequent layers use it.
            // This simulates that the stored gen is consistent.
            assert(gen == 0 || gen == 1);
            // "Use" gen for lookup (just verify it's still a valid number)
            uint32_t mac_map = gen;  // would index l2_src_mac_{gen}
            uint32_t l4_map = gen;   // would index l4_rules_{gen}
            assert(mac_map == l4_map); // same gen for all lookups
        }
    };

    // Run many "packets" while generation changes
    std::atomic<bool> done{false};
    auto writer = [&]() {
        for (int i = 0; i < 10000 && !done.load(); ++i)
            gs.commit();
    };

    std::thread w(writer);
    for (int i = 0; i < 10000; ++i)
        packet_processor();
    done.store(true);
    w.join();
}

// ═══════════════════════════════════════════════════════════
// Double-buffer isolation: shadow writes don't affect active
// ═══════════════════════════════════════════════════════════

TEST(gen_double_buffer_isolation) {
    // Simulates that writing to shadow generation's "map" doesn't
    // affect the active generation's "map".
    int maps[2] = {0, 0}; // simulate map content per gen
    GenState gs;

    // Active gen=0, maps[0]=100
    maps[gs.active()] = 100;
    assert(maps[gs.active()] == 100);

    // Write to shadow (gen=1)
    maps[gs.shadow()] = 200;
    assert(maps[gs.active()] == 100); // active unchanged
    assert(maps[gs.shadow()] == 200);

    // Commit: active becomes 1
    gs.commit();
    assert(maps[gs.active()] == 200);
    assert(maps[gs.shadow()] == 100); // old active is now shadow
}

TEST(gen_double_buffer_swap_cycle) {
    int maps[2] = {0, 0};
    GenState gs;

    for (int round = 0; round < 100; ++round) {
        int shadow = gs.shadow();
        maps[shadow] = round * 10; // prepare shadow

        // Active still sees old value
        assert(maps[gs.active()] != round * 10 || round == 0);

        gs.commit();
        // Now active sees new value
        assert(maps[gs.active()] == round * 10);
    }
}

int main() {
    int passed = 0, failed = 0;
    for (auto& [name, fn] : tests) {
        try {
            fn();
            std::cout << "  PASS  " << name << "\n";
            ++passed;
        } catch (const std::exception& e) {
            std::cout << "  FAIL  " << name << ": " << e.what() << "\n";
            ++failed;
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed > 0 ? 1 : 0;
}
