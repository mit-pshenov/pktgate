# 13 — `tools/validate_config.cpp` (Phase 2j)

## What this tool does

A 37-LOC standalone CLI documented at `CONFIG.md:40` as `./build/validate_config config.json`. It iterates over each argv path, runs `pktgate::config::parse_config(path)` then `pktgate::config::validate_config(*parsed)`, prints `FAIL <name>: parse: …` or `FAIL <name>: …\n     <ctx>: <msg>` per error, or `OK   <name>` on success, and returns the count of failed files as exit code. It links `pktgate_lib` and runs entirely in userspace — no BPF context, no map handles.

## Per-question findings

### Q1 — Does `validate_config` invoke `compile_rules`? **NO**

`tools/validate_config.cpp:1-2,17,24`: only includes `config_parser.hpp` and `config_validator.hpp`; never includes `compiler/rule_compiler.hpp`; never includes `compiler/object_compiler.hpp`. Confirmed via the binary: `nm /home/user/filter/build/validate_config | grep compile_rules` returns nothing, while `parse_config` and `validate_config` symbols are present.

**Operator-facing consequence.** The tool runs only the two stages Phase 2i confirmed (`_review/12_config_parser_validator.md`) to be missing:
- the L3 "must have a match field" guard (the dst_ip P0 root cause)
- the wrong-layer match-field rejection (P0 #7 in `08_CHECKPOINT.md`)
- the eager CIDR / interface-name / port-group-overflow checks

A config that triggers the dst_ip P0 — e.g. `{"pipeline":{"layer_3":[{"rule_id":1,"action":"drop","match":{"dst_ip":"10.0.0.0/8"}}]}}` — will produce `OK   <file>\n` on stdout and exit 0. The operator deploys, and the data plane drops every IPv4 packet. **This is the false-confidence scenario from the prompt; the tool actively misleads.**

Even the per-map size limits (`MAX_PORT_ENTRIES=4096`, `MAX_SUBNET_ENTRIES=16384`, etc., per `03_rule_compiler.md §Q4`) are not surfaced — port-group expansion overflow surfaces only at deploy as a generic `update_elem E2BIG` mid-batch. The pre-deploy validator is silent on it.

### Q2 — Output format & exit codes

`tools/validate_config.cpp:36` returns the count of failed files. So:
- Exit 0 iff every file is OK. Suitable for CI yes/no.
- **Parse error and validation error are NOT distinguished by exit code.** Both increment the same `failures` counter and contribute to the same return value. An operator running `validate_config a.json b.json` who gets `exit 2` cannot tell whether they have two parse errors, two validation errors, or one of each. The first line of each FAIL message distinguishes them on stderr (`FAIL fname: parse: …` vs `FAIL fname:\n     ctx: msg`), so a human or `grep parse:` can distinguish; an exit code consumer cannot.
- Output is human-readable only: no `--json` flag, no machine-parseable structure. Stderr carries everything (parse + validation errors), stdout carries OKs only. This split is correct for shell scripts (`validate_config *.json 2>/dev/null` shows just OKs) but the `OK   fname` line has fixed-width padding and is implicitly a column format — not advertised, not stable.
- No counts summary at the end (`N OK / M failed`). For a multi-file invocation the operator scrolls stderr.

### Q3 — Object resolution coverage

The tool runs only `parse_config` and `validate_config`. `validate_config` does call `check_object_ref` (`config_validator.cpp:7-17`) — single-level existence check against the in-config `ObjectStore`. So the tool catches typos like `object:nonexistent_subnet` in `r.match.src_ip` for L3 (and equivalent paths for `src_mac` / `dst_port`). The bespoke `object6:` block (`config_validator.cpp:93-100`) is also reached. **What is not reached:** any compile-time object-name resolution that happens inside `rule_compiler.cpp`, including the cross-layer "ignored field" silent drop (Phase 2a §Q7) — meaning an `object6:foo` ref in an L2 rule's `src_ip6` passes the tool unconditionally, even if `foo` doesn't exist (the L3 compiler would never read it; the L2 compiler ignores it). Not a P0 (the field is dead anyway), but illustrative of how the tool's coverage is "what the validator does, no more".

### Q4 — Stderr / error visibility

On parse failure the operator sees `FAIL <basename>: parse: <e.what()>`. nlohmann's `what()` includes `"[json.exception.parse_error.101] parse error at line 7, column 13: …"` for syntax errors, which IS reasonable — line and column come through. On `type_error` / `out_of_range` (the "wrong field type" case translated at `config_parser.cpp:136-138`), the message is `Parse error: [json.exception.type_error.302] type must be string, but is number` — no rule context, no field path. Operator gets the type clash but not the path to the offending value.

On validate failure the operator sees `FAIL <basename>:\n     <rule_context>: <message>`, one line per accumulated error. `rule_context` is what `config_validator.cpp` populates — `"L3 rule 42"`, `"action_params"`, etc. — at least the rule_id is shown when the validator knows it. Good enough.

**Path basename only.** Line 15 calls `std::filesystem::path(path).filename().string()`, so if the operator runs `validate_config /etc/pktgate/configs/foo.json /var/tmp/foo.json`, both files show as `FAIL foo.json: …` with no disambiguation. Mild UX bug.

### Q5 — Symlink / file-path handling

`std::ifstream(path)` (line 142 of parser) follows symlinks by default. No checks: symlinked configs, hardlinked configs, configs on a tmpfs all work. `/dev/stdin` opens as a file and reads to EOF — this works for a `cat foo.json | validate_config /dev/stdin` workflow but the FAIL/OK output line then prints `FAIL stdin: …` (basename of `/dev/stdin` is `stdin`), which is fine. No `-` argument support: `validate_config -` literally tries to `std::ifstream("-")` and gets `Cannot open file: -` from `config_parser.cpp:143-144`.

### Q6 — Stdin support

Effectively yes via `/dev/stdin` (above). No native `-` convention. A real-world CI pipeline using `jq … | validate_config /dev/stdin` works. Documented? No — neither `CONFIG.md:40` nor the tool's own usage line mentions this.

### Q7 — `--help`, `--version`, no-arg behaviour

`argc < 2` prints `Usage: validate_config <file.json> ...\n` and returns 1 (`tools/validate_config.cpp:7-10`). **No `--help` parsing** — `validate_config --help` is treated as a file path (`Cannot open file: --help`), exit 1. **No `--version`.** **No `-v` / verbose.** Standard CLI ergonomics absent; minor P2.

### Q8 — Coupling to libpktgate_lib.a

Confirmed: the tool's source includes `config/config_parser.hpp` and `config/config_validator.hpp` from `src/`, and links the static library. No duplicated validation logic in the tool itself — it is a thin wrapper. Good.

### Q9 — Surprising findings

1. **The tool is not in `CMakeLists.txt`.** A full grep of `/home/user/filter/CMakeLists.txt` for `validate_config` returns zero hits. There is no `add_executable(validate_config tools/validate_config.cpp)` anywhere. The binary at `/home/user/filter/build/validate_config` exists from a previous manual build (timestamp Apr 9 09:04, while the rest of the build artefacts are from Apr 9 19:13). A user following CONFIG.md's `./build/validate_config config.json` instruction on a clean checkout will not have this binary. **This is a P1 build-integrity finding** — documented operator-facing tool, no build wiring, no install rule, no CI gate.
2. **No `install()` rule.** Even if added to CMake, the tool is not in the install manifest (the `install(TARGETS ...)` block at `CMakeLists.txt:128` lists only `pktgate_ctl`). RPM packaging will not ship it. Operators who can't `git clone && cmake` have no path to running the tool.
3. **No glob / directory traversal.** `validate_config configs/*.json` works via shell expansion only. A nested-directory layout (`configs/customer-A/*.json` and `configs/customer-B/*.json`) needs the operator to write the shell glob. Probably fine.
4. **Failure count is the exit code.** This means **`exit 256` if you point it at 256 broken files**, which becomes `exit 0` due to POSIX exit-code truncation to 8 bits. Pathological corner case; documenting it. A `return failures ? 1 : 0` would be safer.
5. **Path basename collision.** Same-basename files from different directories print indistinguishably (Q4). Minor.
6. **No file-size guard inherited from parser.** The Phase 2i P1 (no file-size cap in `parse_config`) propagates here: `validate_config a-10GB.json` will OOM the operator's shell exactly as the daemon would, and the resulting OOM-kill is the operator's first signal. Mention only — same root cause as Phase 2i.

### Q10 — Test coverage of the tool

**Zero.** Grep over `tests/` and `functional_tests/` for the tool's binary name returns nothing. The 11 hits for `validate_config` inside `tests/` are all to the library function `pktgate::config::validate_config`, not the binary at `build/validate_config`. No `test_validate_config_tool.cpp`, no pytest fixture invoking the binary, no functional test that asserts "this bad config exits non-zero". For a tool that operators run as the pre-deploy gate, this is the worst test-audit miss in the entire review: the gate has no gate-test.

## Findings (graded)

```
- [P0] tools/validate_config does NOT invoke compile_rules; gives operator green-light on the dst_ip P0
  Where: tools/validate_config.cpp:17,24 (only parse_config + validate_config)
  What: The tool is documented at CONFIG.md:40 as the pre-deploy gate. It runs only the
        parser + validator. Phase 2i (12_config_parser_validator.md) confirmed those two
        stages miss: L3 no-match guard, wrong-layer fields, eager CIDR check, port-group
        overflow vs MAX_*_ENTRIES, target_port interface-name check. A config that
        triggers the dst_ip catch-all (P0 #4 in CHECKPOINT) or any of P0 #7's wrong-layer
        cases prints "OK" and exits 0.
  Why it matters: Operator-facing tool with the documented purpose of catching these exact
        issues. Worse than not having the tool — it gives positive confirmation on the
        catastrophic configs.
  Suggested action: After validate_config, call object_compiler::compile_objects and
        rule_compiler::compile_rules on the result; surface any std::expected<…, std::string>
        error to stderr in the same FAIL format. ~15 LOC.

- [P1] tools/validate_config.cpp is not in CMakeLists.txt
  Where: CMakeLists.txt (no add_executable for the tool); CONFIG.md:40 (documents the binary)
  What: The tool is documented in CONFIG.md but never wired into the build system. The
        binary currently in build/ is a leftover from an older manual build. A fresh
        cmake --build will not produce it.
  Suggested action: Add add_executable(validate_config tools/validate_config.cpp);
        target_link_libraries(validate_config PRIVATE pktgate_lib); and an install() rule
        if the tool is meant to ship in packages.

- [P2] No --help, --version, --json output, or `-` stdin convention
  Where: tools/validate_config.cpp:7-10 (usage only on argc<2)
  What: Standard CLI ergonomics absent. CI scripts have to either hard-code paths or use
        /dev/stdin. No --help means flags like --version are interpreted as file paths.
  Suggested action: Trivial argument parsing; --json output (one ValidationError per JSON
        line) would be a strict win for CI.

- [P2] Exit code does not distinguish parse-error vs validation-error
  Where: tools/validate_config.cpp:21,30,36 (single `failures` counter, returned)
  What: An operator's pre-commit hook can see exit != 0 but cannot tell which failure
        class without parsing stderr. Pre-commit hooks frequently distinguish for
        diagnosis ("schema invalid" vs "semantic invalid").
  Suggested action: Track parse_failures and validate_failures separately; return e.g.
        exit code 2 for parse, 3 for validate, 0 for OK. Document.

- [P2] Path basename only — same-name files in different dirs collide in output
  Where: tools/validate_config.cpp:15 (std::filesystem::path(path).filename())
  Suggested action: Print full path on FAIL, basename only on OK if column width is wanted.
        Or always print full path; the alignment isn't load-bearing.

- [P2] exit code can wrap at 256 failed files
  Where: tools/validate_config.cpp:36 (return failures)
  Suggested action: return failures ? 1 : 0;

- [P2] No file-size guard before parse
  Where: parse_config in config_parser.cpp (already P1 in Phase 2i); inherited by the tool
  What: Same root cause as Phase 2i. validate_config will happily attempt to slurp a 10 GB
        config and OOM the operator's shell.
  Suggested action: Already covered by the Phase 2i P1 fix; mention here for completeness.
```

## Test-audit notes

| Phase 2j finding | Test that should have caught | Current status |
|---|---|---|
| Tool does not invoke `compile_rules` | A `test_validate_config_dst_ip_rejected` (Python functional test or cpp test that invokes the binary) | **absent**. No test exercises the binary at all. |
| CMake doesn't build the tool | Build smoke-test that runs `./build/validate_config --version` (or `--help`) | **absent**. Even if the source weren't wired in, no CI step would notice. |
| Tool's exit codes | A pytest in `functional_tests/` that asserts `subprocess.run([validate_config, bad_config]).returncode != 0` | **absent**. The functional tests use Python loaders directly, not the tool. |
| Stale binary in build/ | n/a (cleanup hygiene) | **the binary at `/home/user/filter/build/validate_config` is from Apr 9 09:04 while the rest of the build is Apr 9 19:13 — the tool is decoupled from regular incremental builds, and there is no signal when it goes stale.** |

**Promote to TEST_AUDIT.md (Phase 2j entry):**

> ### [Phase 2j] P0/P1 — No test exercises `tools/validate_config` binary
>
> The binary documented at `CONFIG.md:40` as the operator-facing pre-deploy gate has no test of any kind: no cpp test, no functional pytest, no CI step. Combined with the P0 finding that the tool does not invoke `compile_rules`, the test gap means there is no signal — at code-review, at CI, or at release — that the documented gate fails open on the dst_ip P0 and the wrong-layer P0. This is the worst class of test-audit miss in the review: a tool whose purpose is "catch dangerous configs before deploy" with zero acceptance tests against known-dangerous configs.

## Open issues / pickup for later phases

- (Tests phase) Add a functional test in `functional_tests/` (Python is fine) that builds a known-bad config triggering the dst_ip P0, invokes the binary, and asserts non-zero exit. Repeat for wrong-layer fields, port-group overflow, bad CIDR, bad target_port. This is the cheapest possible defence and would have caught all four P0s.
- (Build phase) Decide whether the tool is meant to be a shipped artefact (then: CMakeLists.txt + install rule + RPM packaging) or a developer-only helper (then: delete the documentation in CONFIG.md, or label it "developer build only").
- (Consolidation phase) The P0 here should be lifted into `99_REPORT.md` and explicitly cross-linked to P0 #4 and P0 #7 from `08_CHECKPOINT.md` — they share a root cause (validator gaps + tool that doesn't compile) and a single fix (add compile_rules to the tool) closes the false-confidence loophole.
