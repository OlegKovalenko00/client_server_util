#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "common/patterns.hpp"
#include "common/scan_statistics.hpp"

namespace malware_scan::server {

class StatsRegistry {
public:
  void record_scanned_file();
  void record_pattern_hit(const std::string &pattern_id, std::uint64_t count);
  void record_scan(const common::ScanResult &result);
  common::ScanStatisticsSnapshot snapshot() const;

private:
  std::uint64_t scanned_files_ = 0;
  std::map<std::string, std::uint64_t> pattern_hits_;
};

} // namespace malware_scan::server
