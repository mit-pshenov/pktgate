/*
 * Fuzz harness for full pipeline: parse → validate → compile.
 * See fuzz_config_parser.cpp for build instructions.
 */
#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include <cstdint>
#include <string>

static int fuzz_one(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);

    auto parsed = pktgate::config::parse_config_string(input);
    if (!parsed) return 0;

    auto valid = pktgate::config::validate_config(*parsed);
    if (!valid) return 0;

    auto objects = pktgate::compiler::compile_objects(parsed->objects);
    if (!objects) return 0;

    pktgate::compiler::IfindexResolver resolver = [](const std::string&) -> uint32_t {
        return 42;
    };

    auto rules = pktgate::compiler::compile_rules(
        parsed->pipeline, parsed->objects, resolver);
    (void)rules;

    return 0;
}

#ifdef FUZZ_STANDALONE
#include <iostream>
#include <iterator>
int main() {
    std::string input((std::istreambuf_iterator<char>(std::cin)),
                       std::istreambuf_iterator<char>());
    return fuzz_one(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
#else
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    return fuzz_one(data, size);
}
#endif
