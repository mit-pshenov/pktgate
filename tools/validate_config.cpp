#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include <filesystem>
#include <iostream>

/*
 * Offline pre-deploy gate. Runs the full transform that a live deployment
 * does, minus the BPF load: parse → validate → compile. The compile step
 * is what catches structural shape bugs the parser/validator can miss
 * (e.g. the dst_ip-as-LPM-wildcard footgun before P0-01 closed it).
 *
 * Exit code: number of failing files. Non-zero on any failure.
 */

namespace {

uint32_t fake_ifindex_resolver(const std::string& /*name*/) {
    // Offline validation: real interfaces aren't available. Return a sentinel
    // non-zero ifindex so resolver-dependent rules don't reject. The actual
    // deploy path will resolve names against the live netlink view.
    return 1;
}

int validate_one(const std::string& path) {
    auto fname = std::filesystem::path(path).filename().string();

    auto parsed = pktgate::config::parse_config(path);
    if (!parsed) {
        std::cerr << "FAIL " << fname << ": parse: " << parsed.error() << "\n";
        return 1;
    }

    auto valid = pktgate::config::validate_config(*parsed);
    if (!valid) {
        std::cerr << "FAIL " << fname << ":";
        for (auto& e : valid.error())
            std::cerr << "\n     " << e.rule_context << ": " << e.message;
        std::cerr << "\n";
        return 1;
    }

    auto objs = pktgate::compiler::compile_objects(parsed->objects);
    if (!objs) {
        std::cerr << "FAIL " << fname << ": object compile: " << objs.error() << "\n";
        return 1;
    }

    auto rules = pktgate::compiler::compile_rules(parsed->pipeline, parsed->objects,
                                                   fake_ifindex_resolver);
    if (!rules) {
        std::cerr << "FAIL " << fname << ": rule compile: " << rules.error() << "\n";
        return 1;
    }

    std::cout << "OK   " << fname << "\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: validate_config <file.json> ...\n";
        return 1;
    }

    int failures = 0;
    for (int i = 1; i < argc; ++i) {
        failures += validate_one(argv[i]);
    }
    return failures;
}
