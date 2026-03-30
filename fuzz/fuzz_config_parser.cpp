/*
 * Fuzz harness for config_parser.
 *
 * libFuzzer mode (clang with -fsanitize=fuzzer):
 *   Uses LLVMFuzzerTestOneInput entry point.
 *
 * Standalone / AFL++ mode (any compiler):
 *   Reads stdin, compile with -DFUZZ_STANDALONE.
 *   afl-g++-12 -std=c++23 -DFUZZ_STANDALONE -o fuzz_config ...
 */
#include "config/config_parser.hpp"
#include <cstdint>
#include <string>

static int fuzz_one(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    auto result = pktgate::config::parse_config_string(input);
    (void)result;
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
