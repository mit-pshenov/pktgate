#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>
#include <charconv>
#include <net/if.h>
#include <arpa/inet.h>

namespace pktgate::util {

struct MacAddr {
    std::array<uint8_t, 6> bytes{};

    static MacAddr parse(const std::string& s) {
        MacAddr m;
        if (s.size() != 17)
            throw std::invalid_argument("Invalid MAC: " + s);
        for (int i = 0; i < 6; ++i) {
            auto hi = hex_nibble(s[i * 3]);
            auto lo = hex_nibble(s[i * 3 + 1]);
            m.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
            // Validate separator (expect ':' or '-' between octets)
            if (i < 5) {
                char sep = s[i * 3 + 2];
                if (sep != ':' && sep != '-')
                    throw std::invalid_argument("Invalid MAC separator: " + s);
            }
        }
        return m;
    }

private:
    static uint8_t hex_nibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument(std::string("Invalid hex char: ") + c);
    }
};

struct Ipv4Prefix {
    uint32_t addr{};       // host byte order
    uint8_t  prefixlen{};

    static Ipv4Prefix parse(const std::string& s) {
        Ipv4Prefix p;
        auto slash = s.find('/');
        if (slash == std::string::npos)
            throw std::invalid_argument("Missing prefix length: " + s);

        auto ip_str = s.substr(0, slash);
        auto plen_str = s.substr(slash + 1);

        auto fc = std::from_chars(plen_str.data(),
                                  plen_str.data() + plen_str.size(),
                                  p.prefixlen);
        if (fc.ec != std::errc{} || p.prefixlen > 32)
            throw std::invalid_argument("Invalid prefix length: " + plen_str);

        p.addr = parse_ipv4(ip_str);
        return p;
    }

    // Return addr in network byte order
    uint32_t addr_nbo() const {
        return __builtin_bswap32(addr);
    }

private:
    static uint32_t parse_ipv4(const std::string& s) {
        uint32_t result = 0;
        int octet = 0;
        uint32_t cur = 0;
        for (char c : s) {
            if (c == '.') {
                if (cur > 255 || octet >= 3)
                    throw std::invalid_argument("Invalid IP: " + s);
                result = (result << 8) | cur;
                cur = 0;
                ++octet;
            } else if (c >= '0' && c <= '9') {
                cur = cur * 10 + (c - '0');
            } else {
                throw std::invalid_argument("Invalid IP char: " + s);
            }
        }
        if (cur > 255 || octet != 3)
            throw std::invalid_argument("Invalid IP: " + s);
        result = (result << 8) | cur;
        return result;
    }
};

struct Ipv6Prefix {
    std::array<uint8_t, 16> addr{};  // network byte order
    uint8_t prefixlen{};

    static Ipv6Prefix parse(const std::string& s) {
        Ipv6Prefix p;
        auto slash = s.find('/');
        if (slash == std::string::npos)
            throw std::invalid_argument("Missing prefix length: " + s);

        auto ip_str = s.substr(0, slash);
        auto plen_str = s.substr(slash + 1);

        auto fc = std::from_chars(plen_str.data(),
                                  plen_str.data() + plen_str.size(),
                                  p.prefixlen);
        if (fc.ec != std::errc{} || p.prefixlen > 128)
            throw std::invalid_argument("Invalid IPv6 prefix length: " + plen_str);

        struct in6_addr addr6{};
        if (inet_pton(AF_INET6, ip_str.c_str(), &addr6) != 1)
            throw std::invalid_argument("Invalid IPv6 address: " + ip_str);

        std::memcpy(p.addr.data(), &addr6, 16);
        return p;
    }
};

inline uint32_t resolve_ifindex(const std::string& name) {
    unsigned idx = if_nametoindex(name.c_str());
    if (idx == 0)
        throw std::runtime_error("Interface not found: " + name);
    return static_cast<uint32_t>(idx);
}

} // namespace pktgate::util
