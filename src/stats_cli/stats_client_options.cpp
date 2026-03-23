#include "stats_cli/stats_client_options.hpp"

#include <stdexcept>
#include <string_view>

#include "common/cli_utils.hpp"

namespace malware_scan::stats_cli {

StatsClientOptions StatsClientOptions::parse(const int argc, char **argv) {
  if (argc != 2) {
    throw std::invalid_argument("usage: scan_stats <port>");
  }

  const auto port = common::parse_port(std::string_view{argv[1]});

  StatsClientOptions options;
  options.request_fifo = common::make_stats_fifo_request_path(port);
  options.response_fifo = common::make_stats_fifo_response_path(port);
  return options;
}

} // namespace malware_scan::stats_cli
