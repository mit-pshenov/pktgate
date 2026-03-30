/*
 * Fuzz harness for net_types parsers (MacAddr::parse, Ipv4Prefix::parse).
 * See fuzz_config_parser.cpp for build instructions.
 */
#include "util/net_types.hpp"
#include <cstdint>
#include <string>

static int fuzz_one(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);

    try { auto mac = pktgate::util::MacAddr::parse(input); (void)mac; }
    catch (const std::invalid_argument&) {}

    try { auto p = pktgate::util::Ipv4Prefix::parse(input); (void)p.addr_nbo(); }
    catch (const std::invalid_argument&) {}

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
