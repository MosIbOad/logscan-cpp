#include <iostream>
#include "logscan/logscan.hpp"

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    std::cout << "logscan v" << logscan::version() << " - High-performance log scanner\n";
    return 0;
}
