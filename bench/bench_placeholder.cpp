#include <chrono>
#include <iostream>
#include "logscan/logscan.hpp"

int main() {
    std::cout << "Running logscan benchmark placeholder...\n";
    const auto start = std::chrono::high_resolution_clock::now();

    // Placeholder benchmark loop
    volatile auto ver = logscan::version();
    (void)ver;

    const auto end = std::chrono::high_resolution_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "logscan benchmark placeholder finished in " << elapsed << " ns\n";
    return 0;
}
