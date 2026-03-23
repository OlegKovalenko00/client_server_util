#include "server/stats_fifo_service.hpp"

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <system_error>
#include <unistd.h>

#include <sys/stat.h>

namespace malware_scan::server {
namespace {

void write_all(const int fd, const std::string &payload) {
  std::size_t total_written = 0;

  while (total_written < payload.size()) {
    const auto written = ::write(fd, payload.data() + total_written,
                                 payload.size() - total_written);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }

      throw std::system_error(errno, std::generic_category(),
                              "write to stats fifo failed");
    }

    total_written += static_cast<std::size_t>(written);
  }
}

void create_fifo_if_missing(const std::filesystem::path &path) {
  if (::mkfifo(path.c_str(), 0666) != 0 && errno != EEXIST) {
    throw std::system_error(errno, std::generic_category(),
                            "mkfifo failed for " + path.string());
  }
}

} // namespace

StatsFifoService::StatsFifoService(std::filesystem::path request_fifo,
                                   std::filesystem::path response_fifo)
    : request_fifo_(std::move(request_fifo)),
      response_fifo_(std::move(response_fifo)) {}

void StatsFifoService::ensure_created() const {
  create_fifo_if_missing(request_fifo_);
  create_fifo_if_missing(response_fifo_);
}

void StatsFifoService::remove_if_exists() const {
  std::error_code error;
  std::filesystem::remove(request_fifo_, error);
  std::filesystem::remove(response_fifo_, error);
}

int StatsFifoService::open_request_fd() const {
  ensure_created();

  const int fd = ::open(request_fifo_.c_str(), O_RDWR | O_NONBLOCK);
  if (fd < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "open request fifo failed");
  }

  return fd;
}

std::size_t
StatsFifoService::drain_request_markers(const int request_fd) const {
  std::size_t requests_count = 0;
  char buffer[128];

  while (true) {
    const auto read_result = ::read(request_fd, buffer, sizeof(buffer));
    if (read_result < 0) {
      if (errno == EINTR) {
        continue;
      }

      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }

      throw std::system_error(errno, std::generic_category(),
                              "read request fifo failed");
    }

    if (read_result == 0) {
      break;
    }

    requests_count += static_cast<std::size_t>(read_result);
  }

  return requests_count;
}

void StatsFifoService::send_snapshot(
    const common::ScanStatisticsSnapshot &snapshot) const {
  const int response_fd = ::open(response_fifo_.c_str(), O_WRONLY);
  if (response_fd < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "open response fifo failed");
  }

  try {
    const auto serialized = common::serialize_statistics(snapshot);
    write_all(response_fd, serialized);
    ::close(response_fd);
  } catch (...) {
    ::close(response_fd);
    throw;
  }
}

} // namespace malware_scan::server
