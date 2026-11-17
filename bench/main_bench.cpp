#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#ifdef ERROR
#undef ERROR
#endif
#elif defined(__linux__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/resource.h>
#include <unistd.h>
#endif

#include "logscan/chunk_processor.hpp"
#include "logscan/fast_writer.hpp"
#include "logscan/filter.hpp"
#include "logscan/log_line.hpp"
#include "logscan/mapped_file.hpp"
#include "logscan/runner.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

// ============================================================================
// Platform Memory Tracking (Peak RSS)
// ============================================================================
double get_peak_rss_mb() {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX pmc;
    std::memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        return static_cast<double>(pmc.PeakWorkingSetSize) / (1024.0 * 1024.0);
    }
    return 0.0;
#elif defined(__linux__)
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmHWM:", 0) == 0) { // High Water Mark
            size_t val = 0;
            if (std::sscanf(line.c_str(), "VmHWM: %zu kB", &val) == 1) {
                return static_cast<double>(val) / 1024.0;
            }
        }
    }
    return 0.0;
#elif defined(__APPLE__)
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return static_cast<double>(usage.ru_maxrss) / (1024.0 * 1024.0);
    }
    return 0.0;
#else
    return 0.0;
#endif
}

// ============================================================================
// Synthetic Log Generation (if test file does not exist)
// ============================================================================
void generate_test_log(const std::string& path, size_t size_bytes, uint64_t seed = 42) {
    std::cout << "[Benchmark Setup] Sentetik log dosyasi uretiliyor: " << path
              << " (" << (size_bytes / (1024 * 1024)) << " MB)...\n";

    FILE* out = std::fopen(path.c_str(), "wb");
    if (!out) {
        throw std::runtime_error("Test log dosyasi olusturulamadi: " + path);
    }

    logscan::FastWriter writer(out, 1024 * 1024);
    std::mt19937_64 rng(seed);

    // Realistic distribution: 70% INFO, 20% DEBUG, 7% WARN, 3% ERROR
    std::discrete_distribution<int> level_dist({70, 20, 7, 3});
    std::uniform_int_distribution<uint32_t> val_dist(10, 99999);
    std::uniform_int_distribution<uint32_t> sec_step_dist(0, 2);

    const char* resources[] = {
        "Resource:auth", "Resource:database", "Resource:api_gw",
        "Resource:cache", "Resource:worker", "Resource:billing"
    };
    constexpr size_t res_count = sizeof(resources) / sizeof(resources[0]);

    int64_t current_epoch = 1794873600;
    size_t written = 0;
    char line_buf[512];

    while (written < size_bytes) {
        current_epoch += sec_step_dist(rng);
        const int sec = static_cast<int>(current_epoch % 60);
        const int min = static_cast<int>((current_epoch / 60) % 60);
        const int hour = static_cast<int>((current_epoch / 3600) % 24);
        const int day = 17 + static_cast<int>((current_epoch / 86400) % 30);
        const char* res = resources[rng() % res_count];
        const int lvl = level_dist(rng);

        int len = 0;
        if (lvl == 0) { // INFO
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [INFO] [%s] User session authenticated successfully client_id=%u\n",
                day, hour, min, sec, res, val_dist(rng));
        } else if (lvl == 1) { // DEBUG
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [DEBUG] [%s] Buffer allocation succeeded size_kb=64 block_id=%u\n",
                day, hour, min, sec, res, val_dist(rng));
        } else if (lvl == 2) { // WARN
            len = std::snprintf(line_buf, sizeof(line_buf),
                "[2026-11-%02d %02d:%02d:%02d] [WARN] [%s] High memory pressure detected heap_usage_pct=%u\n",
                day, hour, min, sec, res, val_dist(rng) % 100);
        } else { // ERROR
            if ((rng() % 3) == 0) {
                len = std::snprintf(line_buf, sizeof(line_buf),
                    "[2026-11-%02d %02d:%02d:%02d] [ERROR] [%s] user_%u failed password attempts=3\n",
                    day, hour, min, sec, res, val_dist(rng));
            } else {
                len = std::snprintf(line_buf, sizeof(line_buf),
                    "[2026-11-%02d %02d:%02d:%02d] [ERROR] [%s] Database connection timeout on shard-%u\n",
                    day, hour, min, sec, res, val_dist(rng) % 8);
            }
        }

        if (len > 0) {
            writer.write_str(std::string_view(line_buf, static_cast<size_t>(len)));
            written += static_cast<size_t>(len);
        }
    }

    writer.flush();
    std::fclose(out);
    std::cout << "[Benchmark Setup] Sentetik dosya hazirlandi ("
              << (written / (1024 * 1024)) << " MB).\n\n";
}

// ============================================================================
// Naive Single-Threaded Implementation (std::ifstream + std::getline)
// ============================================================================
enum class ScenarioType {
    ErrorFilter,
    SubstringSearch,
    RegexSearch,
    StatsMode
};

struct NaiveResult {
    size_t matched_count{0};
    std::unordered_map<logscan::Level, size_t> level_counts;
    size_t unparsed_count{0};
};

NaiveResult run_naive_scenario(const std::string& path, ScenarioType scenario) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Naive okuma dosyasi acilamadi: " + path);
    }

    NaiveResult result;
    std::string line;
    const std::string sub_target = "timeout";
    const std::regex regex_target("user_[0-9]+ failed");
    std::unordered_map<std::string, size_t> message_counts;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        switch (scenario) {
            case ScenarioType::ErrorFilter: {
                auto parsed = logscan::parse_log_line(line);
                if (parsed.is_parsed && parsed.level == logscan::Level::ERROR) {
                    result.matched_count++;
                }
                break;
            }
            case ScenarioType::SubstringSearch: {
                if (line.find(sub_target) != std::string::npos) {
                    result.matched_count++;
                }
                break;
            }
            case ScenarioType::RegexSearch: {
                if (std::regex_search(line, regex_target)) {
                    result.matched_count++;
                }
                break;
            }
            case ScenarioType::StatsMode: {
                auto parsed = logscan::parse_log_line(line);
                if (parsed.is_parsed) {
                    result.level_counts[parsed.level]++;
                    result.matched_count++;
                    message_counts[std::string(parsed.message)]++;
                } else {
                    result.unparsed_count++;
                }
                break;
            }
        }
    }

    return result;
}

// ============================================================================
// Benchmark Data Structures
// ============================================================================
struct BenchConfig {
    std::string log_file{"bench_sample.log"};
    std::string csv_output{"benchmark_results.csv"};
    size_t generate_size_mb{100};
    int repetitions{5};
};

struct BenchRecord {
    std::string scenario_name;
    std::string method_name;
    size_t thread_count;
    double median_ms;
    double throughput_mb_s;
    double peak_rss_mb;
    double speedup;
    size_t matched_lines;
};

// ============================================================================
// Scenario Runner Function
// ============================================================================
std::vector<BenchRecord> run_all_benchmarks(const BenchConfig& cfg) {
    namespace fs = std::filesystem;

    if (!fs::exists(cfg.log_file)) {
        generate_test_log(cfg.log_file, cfg.generate_size_mb * 1024 * 1024);
    }

    const uintmax_t file_bytes = fs::file_size(cfg.log_file);
    const double file_size_mb = static_cast<double>(file_bytes) / (1024.0 * 1024.0);

    std::cout << "================================================================\n"
              << "              LOGSCAN PERFORMANS BENCHMARK TESTI                \n"
              << "================================================================\n"
              << " Hedef Dosya : " << cfg.log_file << " (" << std::fixed << std::setprecision(2)
              << file_size_mb << " MB)\n"
              << " Tekrar      : " << cfg.repetitions << " (Medyan alinacak)\n"
              << " CSV Ciktisi : " << cfg.csv_output << "\n"
              << "================================================================\n\n";

    struct ScenarioDef {
        ScenarioType type;
        std::string name;
        std::string description;
    };

    const std::vector<ScenarioDef> scenarios = {
        {ScenarioType::ErrorFilter, "ERROR Seviyesi Filtreleme", "LevelFilter(Level::ERROR)"},
        {ScenarioType::SubstringSearch, "Alt Dize Arama ('timeout')", "SubstringFilter('timeout')"},
        {ScenarioType::RegexSearch, "Regex Arama ('user_[0-9]+ failed')", "RegexFilter('user_[0-9]+ failed')"},
        {ScenarioType::StatsMode, "Istatistik ve Top Mesaj Modu", "track_messages=true, stats only"}
    };

    const std::vector<size_t> thread_configs = {1, 2, 4, 8};
    std::vector<BenchRecord> all_records;

    for (const auto& sc : scenarios) {
        std::cout << ">>> Calistiriliyor: " << sc.name << " (" << sc.description << ")...\n";

        // 1. Run Naive Reference (1 thread)
        std::vector<double> naive_times;
        NaiveResult naive_res;
        double naive_peak_rss = 0.0;

        for (int rep = 0; rep < cfg.repetitions; ++rep) {
            auto start = std::chrono::high_resolution_clock::now();
            naive_res = run_naive_scenario(cfg.log_file, sc.type);
            auto end = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            naive_times.push_back(ms);
            naive_peak_rss = (std::max)(naive_peak_rss, get_peak_rss_mb());
        }

        std::sort(naive_times.begin(), naive_times.end());
        double naive_median_ms = naive_times[static_cast<size_t>(cfg.repetitions / 2)];
        double naive_mb_s = (file_size_mb) / (naive_median_ms / 1000.0);

        BenchRecord naive_record{
            sc.name,
            "Naive (ifstream)",
            1,
            naive_median_ms,
            naive_mb_s,
            naive_peak_rss,
            1.0, // baseline
            naive_res.matched_count
        };
        all_records.push_back(naive_record);

        std::cout << "  [Naive Baseline] Medyan: " << std::fixed << std::setprecision(2)
                  << naive_median_ms << " ms | " << naive_mb_s << " MB/s | Eslesen: "
                  << naive_res.matched_count << "\n";

        // 2. Run logscan across thread counts
        for (size_t threads : thread_configs) {
            std::vector<double> logscan_times;
            size_t logscan_matched = 0;
            double logscan_peak_rss = 0.0;

            for (int rep = 0; rep < cfg.repetitions; ++rep) {
                // Setup filter chain
                logscan::FilterChain chain;
                logscan::Options options;

                if (sc.type == ScenarioType::ErrorFilter) {
                    chain.add_filter(std::make_unique<logscan::LevelFilter>(logscan::Level::ERROR));
                    options.collect_matched_lines = true;
                } else if (sc.type == ScenarioType::SubstringSearch) {
                    chain.add_filter(std::make_unique<logscan::SubstringFilter>("timeout"));
                    options.collect_matched_lines = true;
                } else if (sc.type == ScenarioType::RegexSearch) {
                    chain.add_filter(std::make_unique<logscan::RegexFilter>("user_[0-9]+ failed"));
                    options.collect_matched_lines = true;
                } else if (sc.type == ScenarioType::StatsMode) {
                    options.collect_matched_lines = false;
                    options.track_messages = true;
                }

                auto start = std::chrono::high_resolution_clock::now();
                // Map file and run parallel processing
                logscan::MappedFile mapped(cfg.log_file);
                logscan::Runner runner(threads);
                logscan::RunResult run_res = runner.run(mapped, chain, options);
                auto end = std::chrono::high_resolution_clock::now();

                double ms = std::chrono::duration<double, std::milli>(end - start).count();
                logscan_times.push_back(ms);
                logscan_peak_rss = (std::max)(logscan_peak_rss, get_peak_rss_mb());

                logscan_matched = run_res.matched_count;
            }

            std::sort(logscan_times.begin(), logscan_times.end());
            double logscan_median_ms = logscan_times[static_cast<size_t>(cfg.repetitions / 2)];
            double logscan_mb_s = (file_size_mb) / (logscan_median_ms / 1000.0);
            double speedup = naive_median_ms / logscan_median_ms;

            BenchRecord logscan_rec{
                sc.name,
                "logscan (mmap)",
                threads,
                logscan_median_ms,
                logscan_mb_s,
                logscan_peak_rss,
                speedup,
                logscan_matched
            };
            all_records.push_back(logscan_rec);

            std::cout << "  [logscan " << threads << " thread(s)] Medyan: "
                      << std::fixed << std::setprecision(2) << logscan_median_ms
                      << " ms | " << logscan_mb_s << " MB/s | Hizlanma: "
                      << speedup << "x | Eslesen: " << logscan_matched << "\n";
        }
        std::cout << "\n";
    }

    return all_records;
}

// ============================================================================
// Markdown Table Output Generator
// ============================================================================
void print_markdown_table(const std::vector<BenchRecord>& records) {
    std::cout << "### Logscan Benchmark Sonuclari\n\n";
    std::cout << "| Senaryo | Yontem / Iplik | Medyan Sure (ms) | Veri Hizi (MB/s) | Tepe RSS (MB) | Hizlanma | Eslesen Satir |\n";
    std::cout << "| :--- | :--- | :---: | :---: | :---: | :---: | :---: |\n";

    for (const auto& r : records) {
        std::string method_label = r.method_name;
        if (r.method_name.find("logscan") != std::string::npos) {
            method_label += " (" + std::to_string(r.thread_count) + "T)";
        }

        std::string speedup_str;
        if (r.method_name.find("Naive") != std::string::npos) {
            speedup_str = "1.0x (ref)";
        } else {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "**%.1fx**", r.speedup);
            speedup_str = buf;
        }

        std::cout << "| " << std::left << std::setw(30) << r.scenario_name
                  << " | " << std::left << std::setw(20) << method_label
                  << " | " << std::right << std::fixed << std::setprecision(2) << std::setw(16) << r.median_ms
                  << " | " << std::right << std::fixed << std::setprecision(2) << std::setw(16) << r.throughput_mb_s
                  << " | " << std::right << std::fixed << std::setprecision(2) << std::setw(13) << r.peak_rss_mb
                  << " | " << std::right << std::setw(10) << speedup_str
                  << " | " << std::right << std::setw(13) << r.matched_lines
                  << " |\n";
    }
    std::cout << "\n";
}

// ============================================================================
// CSV Output Generator
// ============================================================================
void write_csv_results(const std::string& path, const std::vector<BenchRecord>& records) {
    std::ofstream csv(path);
    if (!csv.is_open()) {
        std::cerr << "Uyari: CSV ciktisi acilamadi: " << path << "\n";
        return;
    }

    csv << "Scenario,Method,Threads,MedianTimeMs,ThroughputMBs,PeakRSSMB,Speedup,MatchedLines\n";
    for (const auto& r : records) {
        csv << '"' << r.scenario_name << "\","
            << '"' << r.method_name << "\","
            << r.thread_count << ","
            << std::fixed << std::setprecision(2) << r.median_ms << ","
            << std::fixed << std::setprecision(2) << r.throughput_mb_s << ","
            << std::fixed << std::setprecision(2) << r.peak_rss_mb << ","
            << std::fixed << std::setprecision(2) << r.speedup << ","
            << r.matched_lines << "\n";
    }
    std::cout << "[Benchmark] Sonuclar CSV olarak kaydedildi -> " << path << "\n";
}

void print_usage() {
    std::cout << "Kullanim: logscan_bench [dosya_yolu] [secenekler]\n\n"
              << "Secenekler:\n"
              << "  --csv <dosya>        CSV formatinda sonuc dosyasi (varsayilan: benchmark_results.csv)\n"
              << "  --reps <n>           Her test icin tekrar sayisi (varsayilan: 5)\n"
              << "  --size-mb <n>        Dosya yoksa uretilecek boyut (varsayilan: 100)\n"
              << "  -h, --help           Bu yardim iletisini gosterir\n";
}

} // namespace

int main(int argc, char* argv[]) {
    BenchConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg == "--csv") {
            if (++i >= argc) { print_usage(); return 1; }
            config.csv_output = argv[i];
        } else if (arg == "--reps") {
            if (++i >= argc) { print_usage(); return 1; }
            config.repetitions = (std::max)(1, std::atoi(argv[i]));
        } else if (arg == "--size-mb") {
            if (++i >= argc) { print_usage(); return 1; }
            config.generate_size_mb = static_cast<size_t>(std::stoull(argv[i]));
        } else if (!arg.empty() && arg[0] != '-') {
            config.log_file = std::string(arg);
        } else {
            std::cerr << "Bilinmeyen arguman: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    try {
        auto records = run_all_benchmarks(config);
        print_markdown_table(records);
        write_csv_results(config.csv_output, records);
    } catch (const std::exception& ex) {
        std::cerr << "Benchmark Hatasi: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
