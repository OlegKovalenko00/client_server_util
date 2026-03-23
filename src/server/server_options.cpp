#include "server/server_options.hpp"

#include <stdexcept>
#include <string_view>

#include "common/cli_utils.hpp"

namespace malware_scan::server {

ServerOptions ServerOptions::parse(const int argc, char **argv) {
  if (argc != 3) {
    throw std::invalid_argument("usage: scan_server <config_path> <port>");
  }

  const auto port = common::parse_port(std::string_view{argv[2]});

  ServerOptions options;
  options.config_path = argv[1];
  options.port = port;
  options.stats_request_fifo = common::make_stats_fifo_request_path(port);
  options.stats_response_fifo = common::make_stats_fifo_response_path(port);
  return options;
}

} // namespace malware_scan::server
