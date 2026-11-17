#include "logscan/chunk_splitter.hpp"

#include <algorithm>

namespace logscan {

std::vector<std::string_view> ChunkSplitter::split(
    std::string_view data,
    size_t target_chunks
) {
    if (data.empty() || target_chunks == 0) {
        return {};
    }

    if (target_chunks == 1 || data.size() == 1) {
        return {data};
    }

    std::vector<std::string_view> chunks;
    chunks.reserve(target_chunks);

    const size_t delta = std::max<size_t>(1, data.size() / target_chunks);
    size_t current_start = 0;

    for (size_t i = 0; i < target_chunks && current_start < data.size(); ++i) {
        // Last chunk takes all the remaining bytes
        if (i == target_chunks - 1) {
            chunks.push_back(data.substr(current_start));
            break;
        }

        const size_t raw_end = current_start + delta;
        if (raw_end >= data.size()) {
            chunks.push_back(data.substr(current_start));
            break;
        }

        // Search forward for the next newline character to align on a line boundary
        const size_t newline_pos = data.find('\n', raw_end);
        if (newline_pos == std::string_view::npos) {
            // No more newlines found; this chunk extends to the end of the data
            chunks.push_back(data.substr(current_start));
            break;
        }

        const size_t next_start = newline_pos + 1;
        chunks.push_back(data.substr(current_start, next_start - current_start));
        current_start = next_start;
    }

    return chunks;
}

} // namespace logscan
