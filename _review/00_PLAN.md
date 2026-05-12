# Critical review of `filter`

Status: started 2026-05-11. Project itself is on pause; this review is a structured pre-archive sweep.

Output convention: each phase produces one numbered markdown file in this folder. The final report (`99_REPORT.md`) is the consolidated, prioritised punch-list.

---

## Phase 0 — Recon

Goal: build a compact map of the project before any deep reading. Decide which modules deserve close attention in Phase 2.

Inputs:
- `ARCHITECTURE.md`, `CONFIG.md`, `TEST_PLAN.md`, `README.md`
- Structure of `src/`, `bpf/`, `functional_tests/`, `tests/`, `fuzz/`, `tools/`, `scripts/`
- `CMakeLists.txt` — what builds, dependencies
- `git log` last ~2 months — direction of work, recently touched areas
- TODO / FIXME / XXX grep across the tree — author-known debt

Output: `01_recon.md` — component map (≤2 pages), proposed "hot zones" for deep review, list of known gaps.

Method: delegated to Explore agent so it doesn't burn main-thread context.

---

## Phase 1 — Architecture review

Goal: judge the architecture as stated vs as implemented.

Checks:
- ARCHITECTURE.md vs reality — declared but missing, or implemented but not declared
- Module-boundary invariants: where they hold, where they could break
- Failure modes — what was thought through, what wasn't
- Observability, scaling, upgrade paths
- Comparison with typical XDP-filter patterns (the `scenarios/` directory hints at a broad surface: DDoS, VLAN, QoS, IPv6, port-scan detection)

Output: `02_architecture.md` — findings keyed to ARCHITECTURE.md sections.

---

## Phase 2 — Module-level implementation review

Order by decreasing criticality:

1. **`bpf/`** — XDP programs and maps. Highest-risk area.
   - Verifier correctness, CO-RE soundness
   - Map races, overflow, lifetime, helper misuse
   - BTF correctness
2. **`src/`** — userspace control plane.
   - Config parser (input is attacker-influenced)
   - BPF map management
   - Trust boundary between userspace and BPF
3. **`functional_tests/`, `tests/`, `fuzz/`** — do they cover declared scenarios, or are they smoke-tests?
4. **`systemd/`, `rpm/`, `scripts/`** — deployment & capabilities. Privilege escalation surface.
5. **`CMakeLists.txt`** — sane flags? insecure defaults?
6. **`tools/`** — supporting CLIs, do they bypass any safety checks?

Output: one file per module: `03_bpf.md`, `04_src.md`, `05_tests.md`, `06_deploy.md`, `07_build.md`, `08_tools.md`.

---

## Phase 3 — Cross-cutting checks

Topics that span all modules:
- **Security:** privilege escalation paths, capability minimisation, input validation at every trust boundary
- **Performance:** XDP per-packet cost, userspace hot loops
- **Observability:** metrics, structured logs, debug under load
- **Build & supply chain:** dependencies, pinning, reproducibility

Output: `09_cross_cutting.md`.

Optionally: run the `code-review` plugin against any meaningful unmerged branch / recent commit cluster — for an independent second opinion.

---

## Phase 4 — Consolidated report

`99_REPORT.md`:
- P0 findings (must-fix before any production use)
- P1 findings (significant debt, fix before resuming feature work)
- P2 findings (nice-to-have, ergonomics, docs)
- Architectural recommendations
- Low-hanging fruit (easy wins)

This is the file to read first when un-pausing the project.

---

## Working agreement

- Each phase ends with a checkpoint: show summary, ask whether to continue, fix anything, or pause.
- Long phases get delegated to Explore agents so the main thread stays clean.
- Untracked files (`Testing/`, `scenarios_v2/`, `tools/`) are in scope — they're part of the project's current state.
- The build was working at pause time; clangd diagnostics via `compile_commands.json` are available if needed.
