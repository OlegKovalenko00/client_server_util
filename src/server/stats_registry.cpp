#include "server/stats_registry.hpp"

namespace malware_scan::server {

void StatsRegistry::record_scanned_file() { ++scanned_files_; }

void StatsRegistry::record_pattern_hit(const std::string &pattern_id,
                                       const std::uint64_t count) {
  pattern_hits_[pattern_id] += count;
}

void StatsRegistry::record_scan(const common::ScanResult &result) {
  record_scanned_file();

  for (const auto &match : result.matches) {
    record_pattern_hit(match.pattern_id,
                       static_cast<std::uint64_t>(match.count));
  }
}

common::ScanStatisticsSnapshot StatsRegistry::snapshot() const {
  common::ScanStatisticsSnapshot snapshot;
  snapshot.scanned_files = scanned_files_;
  snapshot.pattern_hits = pattern_hits_;
  return snapshot;
}

} // namespace malware_scan::server
