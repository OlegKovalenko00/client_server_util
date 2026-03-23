#pragma once

#include <cstdint>
#include <filesystem>

namespace malware_scan::server {

struct ServerOptions {
  std::filesystem::path config_path;
  std::uint16_t port = 0;
  std::filesystem::path stats_request_fifo;
  std::filesystem::path stats_response_fifo;

  static ServerOptions parse(int argc, char **argv);
};

} // namespace malware_scan::server
