#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace malware_scan::common {

std::uint16_t parse_port(std::string_view raw_port);
std::filesystem::path make_stats_fifo_request_path(std::uint16_t port);
std::filesystem::path make_stats_fifo_response_path(std::uint16_t port);

} // namespace malware_scan::common
