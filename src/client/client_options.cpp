#include "client/client_options.hpp"

#include <stdexcept>
#include <string_view>

#include "common/cli_utils.hpp"

namespace malware_scan::client {

ClientOptions ClientOptions::parse(const int argc, char **argv) {
  if (argc != 3) {
    throw std::invalid_argument("usage: scan_client <file_path> <port>");
  }

  ClientOptions options;
  options.file_path = argv[1];
  options.port = common::parse_port(std::string_view{argv[2]});
  return options;
}

} // namespace malware_scan::client
