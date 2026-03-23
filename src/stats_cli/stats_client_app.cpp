#include "stats_cli/stats_client_app.hpp"

#include <iostream>

#include "common/scan_statistics.hpp"
#include "stats_cli/fifo_stats_client.hpp"

namespace malware_scan::stats_cli {

StatsClientApp::StatsClientApp(StatsClientOptions options)
    : options_(std::move(options)) {}

int StatsClientApp::run() const {
  const FifoStatsClient client{options_.request_fifo, options_.response_fifo};
  const auto snapshot = client.fetch();

  std::cout << common::format_statistics_for_console(snapshot) << '\n';
  return 0;
}

} // namespace malware_scan::stats_cli
