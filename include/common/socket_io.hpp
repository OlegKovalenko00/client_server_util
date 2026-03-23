#pragma once

#include <cstddef>

namespace malware_scan::common {
void read_exact(int fd, void *buffer, std::size_t size);
void write_exact(int fd, const void *buffer, std::size_t size);
} // namespace malware_scan::common
