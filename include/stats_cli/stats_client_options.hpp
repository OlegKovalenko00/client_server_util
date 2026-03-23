#pragma once

#include <filesystem>

namespace malware_scan::stats_cli {

struct StatsClientOptions {
  std::filesystem::path request_fifo;
  std::filesystem::path response_fifo;

  static StatsClientOptions parse(int argc, char **argv);
};

} // namespace malware_scan::stats_cli
