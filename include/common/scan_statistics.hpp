#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace malware_scan::common {

struct ScanStatisticsSnapshot {
  std::uint64_t scanned_files = 0;
  std::map<std::string, std::uint64_t> pattern_hits;
};

std::string serialize_statistics(const ScanStatisticsSnapshot &snapshot);
ScanStatisticsSnapshot parse_statistics(std::string_view serialized);
std::string
format_statistics_for_console(const ScanStatisticsSnapshot &snapshot);

} // namespace malware_scan::common
