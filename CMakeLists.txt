cmake_minimum_required(VERSION 3.25)
project(pktgate VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Find system dependencies ──────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
find_package(nlohmann_json 3.11 REQUIRED)

# ── Clang for BPF compilation ─────────────────────────────────
find_program(CLANG NAMES clang-16 clang-17 clang-18 clang REQUIRED)
find_program(BPFTOOL bpftool PATHS /usr/sbin /usr/local/bin REQUIRED)

# ── Options ───────────────────────────────────────────────────
option(BPF_DEBUG "Enable bpf_printk debug tracing in BPF programs" OFF)

# ── BPF targets ───────────────────────────────────────────────
set(BPF_SRC_DIR ${CMAKE_SOURCE_DIR}/bpf)
set(BPF_OUT_DIR ${CMAKE_BINARY_DIR}/bpf)
file(MAKE_DIRECTORY ${BPF_OUT_DIR})

set(BPF_SOURCES
    entry.bpf.c
    layer2.bpf.c
    layer3.bpf.c
    layer4.bpf.c
    tc_ingress.bpf.c
)

set(BPF_OBJECTS "")
set(BPF_SKELETONS "")

foreach(src ${BPF_SOURCES})
    get_filename_component(name ${src} NAME_WE)
    set(obj ${BPF_OUT_DIR}/${name}.bpf.o)
    set(skel ${BPF_OUT_DIR}/${name}.skel.h)

    add_custom_command(
        OUTPUT ${obj}
        COMMAND ${CLANG} -O2 -g -target bpf
            -I${BPF_SRC_DIR}
            -I/usr/include
            -D__TARGET_ARCH_x86
            $<$<BOOL:${BPF_DEBUG}>:-DBPF_DEBUG>
            -c ${BPF_SRC_DIR}/${src}
            -o ${obj}
        DEPENDS ${BPF_SRC_DIR}/${src}
                ${BPF_SRC_DIR}/common.h
                ${BPF_SRC_DIR}/maps.h
                ${BPF_SRC_DIR}/vmlinux.h
        COMMENT "Compiling BPF: ${src}"
    )

    add_custom_command(
        OUTPUT ${skel}
        COMMAND ${BPFTOOL} gen skeleton ${obj} > ${skel}
        DEPENDS ${obj}
        COMMENT "Generating skeleton: ${name}.skel.h"
    )

    list(APPEND BPF_OBJECTS ${obj})
    list(APPEND BPF_SKELETONS ${skel})
endforeach()

add_custom_target(bpf_programs ALL DEPENDS ${BPF_SKELETONS})

# ── Control Plane library ─────────────────────────────────────
add_library(pktgate_lib STATIC
    src/config/config_parser.cpp
    src/config/config_validator.cpp
    src/compiler/object_compiler.cpp
    src/compiler/rule_compiler.cpp
    src/loader/bpf_loader.cpp
    src/loader/map_manager.cpp
    src/pipeline/generation_manager.cpp
    src/pipeline/pipeline_builder.cpp
)

target_include_directories(pktgate_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${BPF_OUT_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(pktgate_lib PUBLIC
    ${LIBBPF_LIBRARIES}
    nlohmann_json::nlohmann_json
    elf
    z
)

add_dependencies(pktgate_lib bpf_programs)

# ── Main executable ───────────────────────────────────────────
add_executable(pktgate_ctl src/main.cpp)
target_link_libraries(pktgate_ctl PRIVATE pktgate_lib)

# ── Install targets ───────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS pktgate_ctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES systemd/pktgate.service
    DESTINATION lib/systemd/system)
install(FILES sample2.json
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pktgate
    RENAME config.json
    COMPONENT config)
install(FILES systemd/pktgate.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pktgate)

# ── Coverage support ──────────────────────────────────────────
option(COVERAGE "Enable code coverage (gcov/lcov)" OFF)

if(COVERAGE)
    message(STATUS "Code coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage -O0 -g")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage -O0 -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")

    find_program(LCOV lcov)
    find_program(GENHTML genhtml)

    if(LCOV AND GENHTML)
        add_custom_target(coverage
            COMMAND ${LCOV} --capture --directory ${CMAKE_BINARY_DIR}
                --include '${CMAKE_SOURCE_DIR}/src/*'
                --output-file coverage.info
                --ignore-errors mismatch
            COMMAND ${LCOV} --remove coverage.info '/usr/*' '*/nlohmann/*'
                --output-file coverage_filtered.info
                --ignore-errors unused
            COMMAND ${GENHTML} coverage_filtered.info
                --output-directory coverage_html
                --title "pktgate coverage"
                --legend --branch-coverage
            COMMAND ${CMAKE_COMMAND} -E echo "Coverage report: ${CMAKE_BINARY_DIR}/coverage_html/index.html"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating lcov code coverage report"
        )

        add_custom_target(coverage_reset
            COMMAND ${LCOV} --zerocounters --directory ${CMAKE_BINARY_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Resetting coverage counters"
        )
    else()
        message(WARNING "lcov/genhtml not found — coverage targets disabled")
    endif()
endif()

# ── Sanitizer support ────────────────────────────────────────
set(SANITIZER "" CACHE STRING "Enable sanitizer (asan, tsan, ubsan)")

if(SANITIZER)
    message(STATUS "Sanitizer enabled: ${SANITIZER}")
    if(SANITIZER STREQUAL "asan")
        set(SAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
    elseif(SANITIZER STREQUAL "tsan")
        set(SAN_FLAGS "-fsanitize=thread")
    elseif(SANITIZER STREQUAL "ubsan")
        set(SAN_FLAGS "-fsanitize=undefined -fno-sanitize-recover=all")
    else()
        message(FATAL_ERROR "Unknown sanitizer: ${SANITIZER}. Use asan, tsan, or ubsan.")
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SAN_FLAGS} -g")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SAN_FLAGS} -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SAN_FLAGS}")
endif()

# ── Tests ─────────────────────────────────────────────────────
enable_testing()

# Unit tests (no BPF runtime needed)
add_executable(test_config
    tests/test_config_parser.cpp
)
target_link_libraries(test_config PRIVATE pktgate_lib)
add_test(NAME config_parser COMMAND test_config)

add_executable(test_compiler
    tests/test_object_compiler.cpp
)
target_link_libraries(test_compiler PRIVATE pktgate_lib)
add_test(NAME object_compiler COMMAND test_compiler)

add_executable(test_generation
    tests/test_generation_logic.cpp
)
target_link_libraries(test_generation PRIVATE pktgate_lib)
add_test(NAME generation_logic COMMAND test_generation)

# Phase 4: Extended test suite
add_executable(test_net_types
    tests/test_net_types.cpp
)
target_link_libraries(test_net_types PRIVATE pktgate_lib)
add_test(NAME net_types COMMAND test_net_types)

add_executable(test_config_validation
    tests/test_config_validation.cpp
)
target_link_libraries(test_config_validation PRIVATE pktgate_lib)
add_test(NAME config_validation COMMAND test_config_validation)

add_executable(test_rule_compiler_edge
    tests/test_rule_compiler_edge.cpp
)
target_link_libraries(test_rule_compiler_edge PRIVATE pktgate_lib)
add_test(NAME rule_compiler_edge COMMAND test_rule_compiler_edge)

add_executable(test_pipeline_integration
    tests/test_pipeline_integration.cpp
)
target_link_libraries(test_pipeline_integration PRIVATE pktgate_lib)
add_test(NAME pipeline_integration COMMAND test_pipeline_integration)

add_executable(test_config_validator
    tests/test_config_validator.cpp
)
target_link_libraries(test_config_validator PRIVATE pktgate_lib)
add_test(NAME config_validator COMMAND test_config_validator)

# Phase 6: byte-level, round-trip, stress, concurrency tests
add_executable(test_byte_layout tests/test_byte_layout.cpp)
target_link_libraries(test_byte_layout PRIVATE pktgate_lib)
add_test(NAME byte_layout COMMAND test_byte_layout)

add_executable(test_packet_builder tests/test_packet_builder.cpp)
target_link_libraries(test_packet_builder PRIVATE pktgate_lib)
add_test(NAME packet_builder COMMAND test_packet_builder)

add_executable(test_roundtrip tests/test_roundtrip.cpp)
target_link_libraries(test_roundtrip PRIVATE pktgate_lib)
add_test(NAME roundtrip COMMAND test_roundtrip)

add_executable(test_stress tests/test_stress.cpp)
target_link_libraries(test_stress PRIVATE pktgate_lib)
add_test(NAME stress COMMAND test_stress)

add_executable(test_concurrency tests/test_concurrency.cpp)
target_link_libraries(test_concurrency PRIVATE pktgate_lib)
target_link_libraries(test_concurrency PRIVATE pthread)
add_test(NAME concurrency COMMAND test_concurrency)

add_executable(test_ipv6 tests/test_ipv6.cpp)
target_link_libraries(test_ipv6 PRIVATE pktgate_lib)
add_test(NAME ipv6 COMMAND test_ipv6)

add_executable(test_fault_injection tests/test_fault_injection.cpp)
target_link_libraries(test_fault_injection PRIVATE pktgate_lib)
add_test(NAME fault_injection COMMAND test_fault_injection)

# ── BPF data plane tests (require CAP_BPF / sudo) ────────────
add_executable(test_bpf_dataplane
    tests/bpf/test_bpf_dataplane.cpp
)
target_include_directories(test_bpf_dataplane PRIVATE
    ${CMAKE_SOURCE_DIR}/bpf
)
target_link_libraries(test_bpf_dataplane PRIVATE pktgate_lib)
add_test(NAME bpf_dataplane COMMAND test_bpf_dataplane)
set_tests_properties(bpf_dataplane PROPERTIES
    LABELS "bpf;privileged"
    SKIP_RETURN_CODE 77
)

# ── Benchmarks (not part of ctest, run manually) ─────────────
add_executable(bench_compile
    tests/bench_compile.cpp
)
target_link_libraries(bench_compile PRIVATE pktgate_lib)
target_compile_options(bench_compile PRIVATE -O2)

# ── Fuzz targets (libFuzzer, requires clang) ─────────────────
option(FUZZ "Build libFuzzer fuzz targets" OFF)

if(FUZZ)
    message(STATUS "Fuzzing enabled — building fuzz targets")

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # libFuzzer mode (clang with std::expected support required)
        foreach(target fuzz_config_parser fuzz_net_types fuzz_roundtrip)
            add_executable(${target} fuzz/${target}.cpp)
            target_link_libraries(${target} PRIVATE pktgate_lib)
            target_compile_options(${target} PRIVATE
                -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
            target_link_options(${target} PRIVATE
                -fsanitize=fuzzer,address,undefined)
        endforeach()
    else()
        # Standalone mode (GCC / AFL++) — reads from stdin
        foreach(target fuzz_config_parser fuzz_net_types fuzz_roundtrip)
            add_executable(${target} fuzz/${target}.cpp)
            target_link_libraries(${target} PRIVATE pktgate_lib)
            target_compile_definitions(${target} PRIVATE FUZZ_STANDALONE)
            target_compile_options(${target} PRIVATE
                -fsanitize=address,undefined -fno-omit-frame-pointer -g)
            target_link_options(${target} PRIVATE
                -fsanitize=address,undefined)
        endforeach()
    endif()
endif()
