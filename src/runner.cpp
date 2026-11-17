#include "logscan/runner.hpp"

#include <stdexcept>
#include <string>

namespace logscan {

Runner::Runner(size_t thread_count)
    : pool_(thread_count) {}

RunResult Runner::run(
    const MappedFile& file,
    const FilterChain& filter_chain,
    const Options& options
) {
    return run(file.view(), filter_chain, options);
}

RunResult Runner::run(
    std::string_view content,
    const FilterChain& filter_chain,
    const Options& options
) {
    if (content.empty()) {
        return RunResult{};
    }

    // Oversubscribe chunks to 4x thread count to mitigate stragglers and workload imbalance
    const size_t target_chunks = pool_.thread_count() * 4;
    const std::vector<std::string_view> chunks = ChunkSplitter::split(content, target_chunks);

    if (chunks.empty()) {
        return RunResult{};
    }

    std::vector<std::future<ChunkResult>> futures;
    futures.reserve(chunks.size());

    for (const auto& chunk : chunks) {
        futures.push_back(pool_.submit([chunk, &filter_chain, &options]() {
            return process_chunk(chunk, filter_chain, options);
        }));
    }

    RunResult result;

    // Collect and merge results in the EXACT original chunk sequence to guarantee output order
    for (size_t i = 0; i < futures.size(); ++i) {
        try {
            ChunkResult chunk_res = futures[i].get();

            result.total_lines += chunk_res.total_lines;
            result.unparsed_lines += chunk_res.unparsed_lines;
            result.matched_count += chunk_res.matched_count;

            for (size_t l = 0; l < static_cast<size_t>(Level::COUNT); ++l) {
                result.level_counts[l] += chunk_res.level_counts[l];
                result.matched_level_counts[l] += chunk_res.matched_level_counts[l];
            }

            if (options.track_messages) {
                for (const auto& [msg, count] : chunk_res.message_counts) {
                    result.message_counts[msg] += count;
                }
            }

            if (options.collect_matched_lines && !chunk_res.matched_lines.empty()) {
                result.matched_lines.insert(
                    result.matched_lines.end(),
                    chunk_res.matched_lines.begin(),
                    chunk_res.matched_lines.end()
                );
            }
        } catch (const std::exception& ex) {
            throw std::runtime_error(
                "Error processing chunk " + std::to_string(i) +
                " (" + std::to_string(chunks[i].size()) + " bytes): " + ex.what()
            );
        } catch (...) {
            throw std::runtime_error("Unknown error processing chunk " + std::to_string(i));
        }
    }

    return result;
}

} // namespace logscan
