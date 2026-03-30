#pragma once

#include <cstdio>
#include <cstdarg>
#include <ctime>

namespace pktgate::log {

enum class Level { DEBUG, INFO, WARN, ERROR };

inline Level g_level = Level::INFO;
inline bool  g_json  = false;

inline void set_level(Level l) { g_level = l; }
inline void set_json(bool on)  { g_json = on; }

inline const char* level_str(Level l) {
    switch (l) {
        case Level::DEBUG: return "debug";
        case Level::INFO:  return "info";
        case Level::WARN:  return "warn";
        case Level::ERROR: return "error";
    }
    return "unknown";
}

inline void log(Level l, const char* fmt, ...) {
    if (l < g_level) return;

    // Format message into buffer
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    int n = std::vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    if (n < 0) n = 0;
    if (n >= static_cast<int>(sizeof(msg))) n = sizeof(msg) - 1;

    if (g_json) {
        // ISO 8601 timestamp
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm;
        gmtime_r(&ts.tv_sec, &tm);
        char tbuf[32];
        std::snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);

        // Escape msg for JSON (handle \ and " and control chars)
        char escaped[2048];
        int j = 0;
        for (int i = 0; i < n && j < static_cast<int>(sizeof(escaped)) - 6; i++) {
            char c = msg[i];
            if (c == '"')       { escaped[j++] = '\\'; escaped[j++] = '"'; }
            else if (c == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
            else if (c == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
            else if (c == '\t') { escaped[j++] = '\\'; escaped[j++] = 't'; }
            else                { escaped[j++] = c; }
        }
        escaped[j] = '\0';

        std::fprintf(stderr, "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"}\n",
                     tbuf, level_str(l), escaped);
    } else {
        const char* prefix = "";
        switch (l) {
            case Level::DEBUG: prefix = "[DEBUG] "; break;
            case Level::INFO:  prefix = "[INFO]  "; break;
            case Level::WARN:  prefix = "[WARN]  "; break;
            case Level::ERROR: prefix = "[ERROR] "; break;
        }
        std::fputs(prefix, stderr);
        std::fputs(msg, stderr);
        std::fputc('\n', stderr);
    }
}

#define LOG_DBG(fmt, ...) ::pktgate::log::log(::pktgate::log::Level::DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) ::pktgate::log::log(::pktgate::log::Level::INFO,  fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) ::pktgate::log::log(::pktgate::log::Level::WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) ::pktgate::log::log(::pktgate::log::Level::ERROR, fmt, ##__VA_ARGS__)

} // namespace pktgate::log
