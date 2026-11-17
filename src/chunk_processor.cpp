#include "logscan/chunk_processor.hpp"

namespace logscan {

ChunkResult process_chunk(
    std::string_view chunk,
    const FilterChain& filter_chain,
    const Options& options
) {
    ChunkResult result;
    size_t start = 0;

    while (start < chunk.size()) {
        const size_t end = chunk.find('\n', start);
        std::string_view line;

        if (end == std::string_view::npos) {
            line = chunk.substr(start);
            start = chunk.size();
        } else {
            line = chunk.substr(start, end - start);
            start = end + 1;
        }

        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }

        if (line.empty()) {
            continue;
        }

        result.total_lines++;
        const LogLine log_line = parse_log_line(line);

        if (log_line.is_parsed) {
            result.level_counts[static_cast<size_t>(log_line.level)]++;
        } else {
            result.unparsed_lines++;
        }

        if (filter_chain.matches(log_line)) {
            result.matched_count++;
            if (log_line.is_parsed) {
                result.matched_level_counts[static_cast<size_t>(log_line.level)]++;
            }
            if (options.collect_matched_lines) {
                result.matched_lines.push_back(line);
            }
        }
    }

    return result;
}

} // namespace logscan
