#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace logscan {

class ChunkSplitter {
public:
    [[nodiscard]] static std::vector<std::string_view> split(
        std::string_view data,
        size_t target_chunks
    );
};

} // namespace logscan
