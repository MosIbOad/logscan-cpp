#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "logscan/fast_writer.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Config {
    std::string output_path{"sample.log"};
    size_t size_bytes{100 * 1024 * 1024}; // default 100 MB
    uint64_t seed{42};
};

const char* RESOURCES[] = {
    "Resource:auth",
    "Resource:database",
    "Resource:api_gw",
    "Resource:cache",
    "Resource:worker",
    "Resource:billing",
    "Resource:scheduler"
};
constexpr size_t RESOURCE_COUNT = sizeof(RESOURCES) / sizeof(RESOURCES[0]);

const char* INFO_MSGS[] = {
    "User session authenticated successfully client_id=",
    "HTTP request GET /api/v2/items completed status=200 duration_ms=",
    "Periodic system health check passed active_nodes=16",
    "Background data synchronization completed records_processed=",
    "Cache warm-up finished total_keys="
};
constexpr size_t INFO_COUNT = sizeof(INFO_MSGS) / sizeof(INFO_MSGS[0]);

const char* DEBUG_MSGS[] = {
    "Query execution plan compiled plan_hash=",
    "Buffer allocation succeeded size_kb=64 block_id=",
    "TCP keep-alive heartbeat ping acknowledged",
    "Thread worker pool capacity idle_workers=8 queue_depth=0",
    "Parsing metadata header attributes count="
};
constexpr size_t DEBUG_COUNT = sizeof(DEBUG_MSGS) / sizeof(DEBUG_MSGS[0]);

const char* WARN_MSGS[] = {
    "High memory pressure detected heap_usage_pct=",
    "Slow database query execution_time_ms=",
    "Connection retry attempt 2 for host=shard-",
    "Client rate limit quota nearing exhaustion client_id=",
    "Disk storage volume threshold warning free_pct="
};
constexpr size_t WARN_COUNT = sizeof(WARN_MSGS) / sizeof(WARN_MSGS[0]);

const char* ERROR_MSGS[] = {
    "Database connection timeout on shard-",
    "Failed to authenticate token: expired session_token=",
    "Connection reset by peer remote_endpoint=10.0.",
    "Disk IO write latency exceeded threshold 2500ms volume=",
    "user_" // followed by id + " failed password attempts=3"
};
constexpr size_t ERROR_COUNT = sizeof(ERROR_MSGS) / sizeof(ERROR_MSGS[0]);

void print_usage() {
    std::cout << "Kullanım: gen_logs <dosya_yolu> <boyut_mb> [--seed <n>]\n"
              << "   veya: gen_logs --output <dosya> --size-mb <n> [--seed <n>]\n\n"
              << "Seçenekler:\n"
              << "  -o, --output <dosya>   Üretilecek dosya yolu (varsayılan: sample.log)\n"
              << "  -s, --size-mb <n>      Üretilecek dosya boyutu (MB cinsinden)\n"
              << "  --size-gb <n>          Üretilecek dosya boyutu (GB cinsinden)\n"
              << "  --seed <n>             Tekrarlanabilirlik için rastgele sayı tohumu (varsayılan: 42)\n"
              << "  -h, --help             Bu yardım iletisini gösterir\n";
}

bool parse_args(int argc, char* argv[], Config& config) {
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            std::exit(0);
        } else if (arg == "--output" || arg == "-o") {
            if (++i >= argc) return false;
            config.output_path = argv[i];
        } else if (arg == "--size-mb" || arg == "-s") {
            if (++i >= argc) return false;
            config.size_bytes = static_cast<size_t>(std::stoull(argv[i])) * 1024 * 1024;
        } else if (arg == "--size-gb") {
            if (++i >= argc) return false;
            config.size_bytes = static_cast<size_t>(std::stoull(argv[i])) * 1024 * 1024 * 1024;
        } else if (arg == "--seed") {
            if (++i >= argc) return false;
            config.seed = std::stoull(argv[i]);
        } else if (!arg.empty() && arg[0] != '-') {
            if (config.output_path == "sample.log") {
                config.output_path = std::string(arg);
            } else {
                // Second positional argument is size in MB
                config.size_bytes = static_cast<size_t>(std::stoull(std::string(arg))) * 1024 * 1024;
            }
        } else {
            std::cerr << "Hata: Bilinmeyen argüman: " << arg << "\n";
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    Config config;
    if (!parse_args(argc, argv, config)) {
        print_usage();
        return 1;
    }

    FILE* out = std::fopen(config.output_path.c_str(), "wb");
    if (!out) {
        std::perror("Dosya oluşturulamadı");
        return 1;
    }

    // 1 MB high-throughput buffer for file writing
    logscan::FastWriter writer(out, 1024 * 1024);

    std::mt19937_64 rng(config.seed);

    // Realistic Level Distribution: 70% INFO, 20% DEBUG, 7% WARN, 3% ERROR
    std::discrete_distribution<int> level_dist({
        70, // 0: INFO
        20, // 1: DEBUG
        7,  // 2: WARN
        3   // 3: ERROR
    });

    std::uniform_int_distribution<size_t> res_dist(0, RESOURCE_COUNT - 1);
    std::uniform_int_distribution<uint32_t> val_dist(10, 99999);
    std::uniform_int_distribution<uint32_t> sec_step_dist(0, 2);

    // Starting timestamp: 2026-11-17 00:00:00 (approximate unix epoch seconds)
    int64_t current_epoch = 1794873600;

    size_t bytes_written = 0;
    char line_buf[512];

    while (bytes_written < config.size_bytes) {
        // Monotonically advancing timestamp
        current_epoch += sec_step_dist(rng);

        const int64_t total_sec = current_epoch;
        const int sec = static_cast<int>(total_sec % 60);
        const int min = static_cast<int>((total_sec / 60) % 60);
        const int hour = static_cast<int>((total_sec / 3600) % 24);
        // Simplified day calculation starting 2026-11-17
        const int day = 17 + static_cast<int>(total_sec / 86400 % 30);

        const int lvl_idx = level_dist(rng);
        const char* res = RESOURCES[res_dist(rng)];

        int len = 0;
        if (lvl_idx == 0) { // INFO (70%)
            const char* msg = INFO_MSGS[rng() % INFO_COUNT];
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [INFO] [%s] %s%u\n",
                day, hour, min, sec, res, msg, val_dist(rng));
        } else if (lvl_idx == 1) { // DEBUG (20%)
            const char* msg = DEBUG_MSGS[rng() % DEBUG_COUNT];
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [DEBUG] [%s] %s%u\n",
                day, hour, min, sec, res, msg, val_dist(rng));
        } else if (lvl_idx == 2) { // WARN (7%)
            const char* msg = WARN_MSGS[rng() % WARN_COUNT];
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [WARN] [%s] %s%u\n",
                day, hour, min, sec, res, msg, val_dist(rng) % 100);
        } else { // ERROR (3%)
            const size_t err_idx = rng() % ERROR_COUNT;
            if (err_idx == 4) {
                // user_[0-9]+ failed password pattern
                len = std::snprintf(line_buf, sizeof(line_buf),
                    "[2026-11-%02d %02d:%02d:%02d] [ERROR] [%s] user_%u failed password attempts=3\n",
                    day, hour, min, sec, res, val_dist(rng));
            } else {
                const char* msg = ERROR_MSGS[err_idx];
                len = std::snprintf(line_buf, sizeof(line_buf),
                    "[2026-11-%02d %02d:%02d:%02d] [ERROR] [%s] %s%u\n",
                    day, hour, min, sec, res, msg, val_dist(rng) % 16);
            }
        }

        if (len > 0) {
            writer.write_str(std::string_view(line_buf, static_cast<size_t>(len)));
            bytes_written += static_cast<size_t>(len);
        }
    }

    writer.flush();
    std::fclose(out);

    std::cout << "[gen_logs] " << (bytes_written / (1024 * 1024))
              << " MB sentetik log basariyla olusturuldu -> " << config.output_path << "\n";
    return 0;
}
