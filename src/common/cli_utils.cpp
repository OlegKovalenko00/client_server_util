#include "common/cli_utils.hpp"

#include <charconv>
#include <stdexcept>
#include <string>

namespace malware_scan::common {

std::uint16_t parse_port(std::string_view raw_port) {
  unsigned int parsed_port = 0;
  const auto *begin = raw_port.data();
  const auto *end = raw_port.data() + raw_port.size();

  const auto [ptr, error] = std::from_chars(begin, end, parsed_port);
  if (error != std::errc{} || ptr != end || parsed_port == 0 ||
      parsed_port > 65535U) {
    throw std::invalid_argument("invalid port: " + std::string(raw_port));
  }

  return static_cast<std::uint16_t>(parsed_port);
}

std::filesystem::path make_stats_fifo_request_path(const std::uint16_t port) {
  return std::filesystem::path("/tmp") /
         ("malware_scan_" + std::to_string(port) + ".req.fifo");
}

std::filesystem::path make_stats_fifo_response_path(const std::uint16_t port) {
  return std::filesystem::path("/tmp") /
         ("malware_scan_" + std::to_string(port) + ".resp.fifo");
}

} // namespace malware_scan::common
