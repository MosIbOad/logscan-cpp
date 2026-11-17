#include "logscan/fast_writer.hpp"
#include "logscan/filter.hpp"
#include "logscan/level.hpp"
#include "logscan/logscan.hpp"
#include "logscan/mapped_file.hpp"
#include "logscan/runner.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct CliArgs {
    std::string file_path;
    std::vector<std::string> contains_filters;
    std::optional<std::string> regex_filter;
    std::optional<std::string> level_filter;
    std::optional<std::string> from_time;
    std::optional<std::string> to_time;
    size_t threads{0};
    bool stats{false};
    size_t top_n{0};
    bool count_only{false};
    bool show_help{false};
    bool show_version{false};
};

void print_usage() {
    std::cout << "logscan v" << logscan::version() << " — High-Performance Log File Scanner and Analyzer\n\n"
              << "Usage:\n"
              << "  logscan <file> [options]\n\n"
              << "Options:\n"
              << "  --contains <text>        Substring filter (can be specified multiple times)\n"
              << "  --regex <pattern>        Regular expression filter\n"
              << "  --level <severity>       Minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)\n"
              << "  --from <time>            Start timestamp (YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS)\n"
              << "  --to <time>              End timestamp (YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS)\n"
              << "  --threads <n>            Number of worker threads (default: hardware concurrency)\n"
              << "  --stats                  Do not print lines; show statistical summary only\n"
              << "  --top <n>                Show N most frequent messages (used with --stats)\n"
              << "  --count                  Print only the count of matched lines\n"
              << "  --help, -h               Show this help message\n"
              << "  --version, -v            Show version information\n";
}

bool parse_arguments(int argc, char* argv[], CliArgs& args) {
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            args.show_help = true;
            return true;
        }
        if (arg == "--version" || arg == "-v") {
            args.show_version = true;
            return true;
        }
        if (arg == "--stats") {
            args.stats = true;
        } else if (arg == "--count") {
            args.count_only = true;
        } else if (arg == "--contains") {
            if (++i >= argc) {
                std::cerr << "Error: Missing search text for --contains.\n";
                return false;
            }
            args.contains_filters.emplace_back(argv[i]);
        } else if (arg.starts_with("--contains=")) {
            args.contains_filters.emplace_back(arg.substr(11));
        } else if (arg == "--regex") {
            if (++i >= argc) {
                std::cerr << "Error: Missing regex pattern for --regex.\n";
                return false;
            }
            args.regex_filter = argv[i];
        } else if (arg.starts_with("--regex=")) {
            args.regex_filter = std::string(arg.substr(8));
        } else if (arg == "--level") {
            if (++i >= argc) {
                std::cerr << "Error: Missing log level for --level.\n";
                return false;
            }
            args.level_filter = argv[i];
        } else if (arg.starts_with("--level=")) {
            args.level_filter = std::string(arg.substr(8));
        } else if (arg == "--from") {
            if (++i >= argc) {
                std::cerr << "Error: Missing timestamp for --from.\n";
                return false;
            }
            args.from_time = argv[i];
        } else if (arg.starts_with("--from=")) {
            args.from_time = std::string(arg.substr(7));
        } else if (arg == "--to") {
            if (++i >= argc) {
                std::cerr << "Error: Missing timestamp for --to.\n";
                return false;
            }
            args.to_time = argv[i];
        } else if (arg.starts_with("--to=")) {
            args.to_time = std::string(arg.substr(5));
        } else if (arg == "--threads") {
            if (++i >= argc) {
                std::cerr << "Error: Missing number for --threads.\n";
                return false;
            }
            try {
                const int t = std::stoi(argv[i]);
                if (t <= 0) {
                    throw std::invalid_argument("");
                }
                args.threads = static_cast<size_t>(t);
            } catch (...) {
                std::cerr << "Error: --threads must be a positive integer: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--top") {
            if (++i >= argc) {
                std::cerr << "Error: Missing message count for --top.\n";
                return false;
            }
            try {
                const int n = std::stoi(argv[i]);
                if (n <= 0) {
                    throw std::invalid_argument("");
                }
                args.top_n = static_cast<size_t>(n);
                args.stats = true; // --top automatically implies stats mode
            } catch (...) {
                std::cerr << "Error: --top must be a positive integer: " << argv[i] << "\n";
                return false;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: Unrecognized option: " << arg << "\n";
            return false;
        } else {
            if (args.file_path.empty()) {
                args.file_path = std::string(arg);
            } else {
                std::cerr << "Error: Multiple input files are not supported: " << arg << "\n";
                return false;
            }
        }
    }

    if (args.file_path.empty()) {
        std::cerr << "Error: No log file specified.\n";
        return false;
    }

    return true;
}

void print_stats_report(const logscan::RunResult& result, size_t top_n) {
    std::cout << "--------------------------------------------------\n"
              << "[logscan Statistics Summary]\n"
              << "Total Lines      : " << result.total_lines << "\n"
              << "Matched Lines    : " << result.matched_count;

    if (result.total_lines > 0) {
        const double pct = (static_cast<double>(result.matched_count) * 100.0) / static_cast<double>(result.total_lines);
        std::cout << " (" << std::fixed << std::setprecision(2) << pct << "%)\n";
    } else {
        std::cout << " (0.00%)\n";
    }

    std::cout << "Unparsed Lines   : " << result.unparsed_lines << "\n\n"
              << "Log Level Breakdown (Whole File):\n";

    for (size_t i = 0; i < static_cast<size_t>(logscan::Level::COUNT); ++i) {
        const auto lvl = static_cast<logscan::Level>(i);
        const uint64_t count = result.level_counts[i];
        double pct = 0.0;
        if (result.total_lines > 0) {
            pct = (static_cast<double>(count) * 100.0) / static_cast<double>(result.total_lines);
        }
        std::cout << "  [" << std::left << std::setw(5) << logscan::to_string(lvl) << "] "
                  << std::right << std::setw(10) << count
                  << " (" << std::fixed << std::setprecision(2) << std::setw(5) << pct << "%)\n";
    }

    if (top_n > 0 && !result.message_counts.empty()) {
        std::vector<std::pair<std::string_view, uint64_t>> sorted_msgs(
            result.message_counts.begin(),
            result.message_counts.end()
        );

        std::ranges::sort(sorted_msgs, [](const auto& a, const auto& b) {
            if (a.second != b.second) {
                return a.second > b.second;
            }
            return a.first < b.first;
        });

        const size_t show_count = std::min(top_n, sorted_msgs.size());
        std::cout << "\nTop " << show_count << " Most Frequent Messages:\n";
        for (size_t i = 0; i < show_count; ++i) {
            std::cout << "  " << (i + 1) << ". [" << sorted_msgs[i].second << " times] "
                      << sorted_msgs[i].first << "\n";
        }
    }

    std::cout << "--------------------------------------------------\n";
}

} // namespace

int main(int argc, char* argv[]) {
    CliArgs args;
    if (!parse_arguments(argc, argv, args)) {
        if (args.show_help) {
            print_usage();
            return 0;
        }
        if (args.show_version) {
            std::cout << "logscan v" << logscan::version() << "\n";
            return 0;
        }
        print_usage();
        return 1;
    }

    if (args.show_help) {
        print_usage();
        return 0;
    }

    if (args.show_version) {
        std::cout << "logscan v" << logscan::version() << "\n";
        return 0;
    }

    // 1. Build filter pipeline
    logscan::FilterChain filter_chain;

    for (const auto& needle : args.contains_filters) {
        filter_chain.emplace_filter<logscan::SubstringFilter>(needle);
    }

    if (args.regex_filter.has_value()) {
        try {
            filter_chain.emplace_filter<logscan::RegexFilter>(*args.regex_filter);
        } catch (const std::regex_error& err) {
            std::cerr << "Error: Invalid regular expression: " << *args.regex_filter << " (" << err.what() << ")\n";
            return 1;
        }
    }

    if (args.level_filter.has_value()) {
        const auto lvl = logscan::parse_level(*args.level_filter);
        if (!lvl.has_value()) {
            std::cerr << "Error: Unknown log level: " << *args.level_filter << "\n"
                      << "Valid levels: TRACE, DEBUG, INFO, WARN, ERROR, FATAL\n";
            return 1;
        }
        filter_chain.emplace_filter<logscan::LevelFilter>(*lvl);
    }

    if (args.from_time.has_value() || args.to_time.has_value()) {
        auto time_filter = logscan::TimeRangeFilter::from_strings(args.from_time, args.to_time);
        if (args.from_time.has_value() && !time_filter.start_epoch().has_value()) {
            std::cerr << "Error: Invalid start time format: " << *args.from_time << "\n"
                      << "Expected format: YYYY-MM-DD HH:MM:SS\n";
            return 1;
        }
        if (args.to_time.has_value() && !time_filter.end_epoch().has_value()) {
            std::cerr << "Error: Invalid end time format: " << *args.to_time << "\n"
                      << "Expected format: YYYY-MM-DD HH:MM:SS\n";
            return 1;
        }
        filter_chain.add_filter(std::make_unique<logscan::TimeRangeFilter>(time_filter));
    }

    // 2. Open memory-mapped file
    std::unique_ptr<logscan::MappedFile> mapped_file;
    try {
        mapped_file = std::make_unique<logscan::MappedFile>(args.file_path);
    } catch (const std::exception& err) {
        std::cerr << "Error: Failed to open file: " << err.what() << "\n";
        return 1;
    }

    // 3. Execution configuration
    logscan::Options options;
    if (args.stats || args.count_only) {
        options.collect_matched_lines = false; // Save heap memory
    }
    if (args.top_n > 0) {
        options.track_messages = true;
    }

    const size_t thread_count = args.threads > 0 ? args.threads : std::max(1U, std::thread::hardware_concurrency());
    logscan::Runner runner(thread_count);

    // 4. Run parallel scanning & measure time
    const auto start_clock = std::chrono::high_resolution_clock::now();
    logscan::RunResult result;

    try {
        result = runner.run(*mapped_file, filter_chain, options);
    } catch (const std::exception& err) {
        std::cerr << "Error: Exception occurred during scanning: " << err.what() << "\n";
        return 1;
    }

    const auto end_clock = std::chrono::high_resolution_clock::now();

    // 5. Output processing
    if (args.count_only) {
        std::cout << result.matched_count << "\n";
    } else if (args.stats) {
        print_stats_report(result, args.top_n);
    } else {
        // High-throughput buffered line streaming to stdout
        logscan::FastWriter writer(stdout);
        for (const auto& line : result.matched_lines) {
            writer.write_line(line);
        }
        writer.flush();
    }

    // 6. Performance metrics summary to stderr
    const double elapsed_seconds = std::chrono::duration<double>(end_clock - start_clock).count();
    const double mb_processed = static_cast<double>(mapped_file->size()) / (1024.0 * 1024.0);
    const double throughput_mb_s = elapsed_seconds > 0.0 ? (mb_processed / elapsed_seconds) : 0.0;

    std::fprintf(
        stderr,
        "[logscan] %.2f MB processed | Time: %.2f ms (%.2f MB/s) | Threads: %zu\n",
        mb_processed,
        elapsed_seconds * 1000.0,
        throughput_mb_s,
        runner.thread_count()
    );

    return 0;
}
