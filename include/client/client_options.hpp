#pragma once

#include <cstdint>
#include <filesystem>

namespace malware_scan::client {

struct ClientOptions {
  std::filesystem::path file_path;
  std::uint16_t port = 0;

  static ClientOptions parse(int argc, char **argv);
};

} // namespace malware_scan::client
