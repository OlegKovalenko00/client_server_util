#include "stats_cli/fifo_stats_client.hpp"

#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>

namespace malware_scan::stats_cli {
namespace {

void write_all(const int fd, const std::string &payload) {
  std::size_t total_written = 0;
  while (total_written < payload.size()) {
    const auto written = write(fd, payload.data() + total_written,
                               payload.size() - total_written);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }

      throw std::system_error(errno, std::generic_category(), "write failed");
    }

    total_written += static_cast<std::size_t>(written);
  }
}

std::string read_all(const int fd) {
  std::string data;
  char buffer[1024];

  while (true) {
    const auto read_result = read(fd, buffer, sizeof(buffer));
    if (read_result < 0) {
      if (errno == EINTR) {
        continue;
      }

      throw std::system_error(errno, std::generic_category(), "read failed");
    }

    if (read_result == 0) {
      break;
    }

    data.append(buffer, static_cast<std::size_t>(read_result));
  }

  return data;
}

} // namespace

FifoStatsClient::FifoStatsClient(std::filesystem::path request_fifo,
                                 std::filesystem::path response_fifo)
    : request_fifo_(std::move(request_fifo)),
      response_fifo_(std::move(response_fifo)) {}

common::ScanStatisticsSnapshot FifoStatsClient::fetch() const {
  const int request_fd = open(request_fifo_.c_str(), O_WRONLY);
  if (request_fd < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "open request fifo failed");
  }

  write_all(request_fd, "1");
  close(request_fd);

  const int response_fd = open(response_fifo_.c_str(), O_RDONLY);
  if (response_fd < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "open response fifo failed");
  }

  const auto serialized = read_all(response_fd);
  close(response_fd);

  return common::parse_statistics(serialized);
}

} // namespace malware_scan::stats_cli
