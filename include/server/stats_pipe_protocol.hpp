#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace malware_scan::server {

enum class StatsEventType : std::uint32_t {
  file_scanned = 1,
  pattern_hit = 2,
};

inline constexpr std::size_t k_stats_pipe_pattern_id_capacity = 256;

struct StatsEvent {
  StatsEventType type = StatsEventType::file_scanned;
  std::uint64_t count = 0;
  std::uint32_t pattern_id_size = 0;
  char pattern_id[k_stats_pipe_pattern_id_capacity] = {};
};

void write_file_scanned_event(int fd);
void write_pattern_hit_event(int fd, const std::string &pattern_id,
                             std::uint64_t count);
bool try_read_stats_event(int fd, StatsEvent &event);

} // namespace malware_scan::server
