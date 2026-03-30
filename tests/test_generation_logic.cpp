#include <cassert>
#include <iostream>
#include <atomic>
#include <vector>

/*
 * Unit tests for generation swap logic.
 * Tests the state machine (active/shadow/commit/rollback)
 * without requiring BPF runtime.
 */

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry {
    const char* name;
    void (*fn)();
};
static std::vector<TestEntry> tests;

// Minimal mock of generation logic
class MockGenerationManager {
public:
    uint32_t active_generation() const { return active_gen_.load(); }
    uint32_t shadow_generation() const { return active_gen_.load() ^ 1; }

    void commit() {
        uint32_t new_gen = shadow_generation();
        active_gen_.store(new_gen);
    }

    void rollback() {
        uint32_t old_gen = active_gen_.load() ^ 1;
        active_gen_.store(old_gen);
    }

private:
    std::atomic<uint32_t> active_gen_{0};
};

TEST(test_initial_state) {
    MockGenerationManager gm;
    assert(gm.active_generation() == 0);
    assert(gm.shadow_generation() == 1);
}

TEST(test_commit_swaps_generations) {
    MockGenerationManager gm;
    assert(gm.active_generation() == 0);

    gm.commit();
    assert(gm.active_generation() == 1);
    assert(gm.shadow_generation() == 0);
}

TEST(test_double_commit) {
    MockGenerationManager gm;
    gm.commit();
    assert(gm.active_generation() == 1);

    gm.commit();
    assert(gm.active_generation() == 0);
    assert(gm.shadow_generation() == 1);
}

TEST(test_rollback_after_commit) {
    MockGenerationManager gm;
    assert(gm.active_generation() == 0);

    gm.commit();
    assert(gm.active_generation() == 1);

    gm.rollback();
    assert(gm.active_generation() == 0);
    assert(gm.shadow_generation() == 1);
}

TEST(test_rollback_without_commit) {
    MockGenerationManager gm;
    assert(gm.active_generation() == 0);

    // Rollback without commit — swaps to gen 1
    gm.rollback();
    assert(gm.active_generation() == 1);
}

TEST(test_commit_rollback_commit) {
    MockGenerationManager gm;
    gm.commit();   // 0 → 1
    gm.rollback(); // 1 → 0
    gm.commit();   // 0 → 1
    assert(gm.active_generation() == 1);

    gm.commit();   // 1 → 0
    assert(gm.active_generation() == 0);
}

TEST(test_shadow_always_opposite) {
    MockGenerationManager gm;
    for (int i = 0; i < 100; ++i) {
        assert(gm.active_generation() + gm.shadow_generation() == 1);
        assert((gm.active_generation() ^ gm.shadow_generation()) == 1);
        gm.commit();
    }
}

// ── Negative / stress tests ─────────────────────────────────

TEST(test_double_rollback) {
    MockGenerationManager gm;
    assert(gm.active_generation() == 0);

    gm.rollback(); // 0 → 1
    gm.rollback(); // 1 → 0
    assert(gm.active_generation() == 0);
    assert(gm.shadow_generation() == 1);
}

TEST(test_triple_rollback) {
    MockGenerationManager gm;
    gm.commit();   // 0 → 1
    gm.rollback(); // 1 → 0
    gm.rollback(); // 0 → 1
    gm.rollback(); // 1 → 0
    assert(gm.active_generation() == 0);
}

TEST(test_rapid_commit_rollback_stress) {
    MockGenerationManager gm;
    // 1000 random commit/rollback cycles — invariant must hold
    for (int i = 0; i < 1000; ++i) {
        if (i % 3 == 0)
            gm.rollback();
        else
            gm.commit();

        // Invariant: active + shadow == 1, always
        assert(gm.active_generation() <= 1);
        assert(gm.shadow_generation() <= 1);
        assert(gm.active_generation() != gm.shadow_generation());
        assert((gm.active_generation() ^ gm.shadow_generation()) == 1);
    }
}

TEST(test_commit_idempotent_state) {
    // After even number of commits, back to gen 0
    MockGenerationManager gm;
    for (int i = 0; i < 50; ++i) {
        gm.commit();
        gm.commit();
    }
    assert(gm.active_generation() == 0);

    // After odd number, gen 1
    gm.commit();
    assert(gm.active_generation() == 1);
}

TEST(test_rollback_is_own_inverse) {
    MockGenerationManager gm;
    gm.commit(); // 0 → 1
    uint32_t before = gm.active_generation();
    gm.rollback();
    gm.rollback();
    // Two rollbacks = identity
    assert(gm.active_generation() == before);
}

// Test LPM key tracking logic
TEST(test_lpm_key_tracking) {
    // Simulate tracking keys for each generation
    std::vector<std::vector<uint8_t>> lpm_keys[2];

    uint32_t active = 0;
    uint32_t shadow = active ^ 1;

    // Prepare shadow: add keys
    lpm_keys[shadow].push_back({0, 0, 0, 24, 192, 168, 1, 0}); // 192.168.1.0/24
    lpm_keys[shadow].push_back({0, 0, 0, 16, 10, 0, 0, 0});    // 10.0.0.0/16
    assert(lpm_keys[shadow].size() == 2);

    // Commit: shadow becomes active
    active = shadow;
    shadow = active ^ 1;
    assert(active == 1);
    assert(shadow == 0);

    // Clear old shadow (gen 0) — should be empty
    assert(lpm_keys[shadow].empty());

    // Prepare new shadow with different keys
    lpm_keys[shadow].push_back({0, 0, 0, 8, 172, 0, 0, 0}); // 172.0.0.0/8
    assert(lpm_keys[shadow].size() == 1);

    // Commit again
    active = shadow;
    shadow = active ^ 1;
    assert(active == 0);
    assert(shadow == 1);

    // Old shadow (gen 1) still has its keys — they need to be cleared
    assert(lpm_keys[shadow].size() == 2);
    lpm_keys[shadow].clear();
    assert(lpm_keys[shadow].empty());
}

TEST(test_lpm_key_tracking_empty_gen) {
    // Shadow with no keys — clear should be a no-op
    std::vector<std::vector<uint8_t>> lpm_keys[2];
    assert(lpm_keys[0].empty());
    assert(lpm_keys[1].empty());

    // "Clear" empty gen — nothing should break
    lpm_keys[0].clear();
    lpm_keys[1].clear();
    assert(lpm_keys[0].empty());
    assert(lpm_keys[1].empty());
}

TEST(test_lpm_key_tracking_overwrite_shadow) {
    // Simulate: prepare shadow, don't commit, prepare again (overwrite)
    std::vector<std::vector<uint8_t>> lpm_keys[2];

    uint32_t active = 0;
    uint32_t shadow = 1;

    // First prepare
    lpm_keys[shadow].push_back({0, 0, 0, 24, 10, 0, 0, 0});
    assert(lpm_keys[shadow].size() == 1);

    // Second prepare (without commit) — must clear first
    lpm_keys[shadow].clear();
    lpm_keys[shadow].push_back({0, 0, 0, 16, 172, 16, 0, 0});
    lpm_keys[shadow].push_back({0, 0, 0, 8, 192, 0, 0, 0});
    assert(lpm_keys[shadow].size() == 2);

    // Active gen untouched
    assert(lpm_keys[active].empty());
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
