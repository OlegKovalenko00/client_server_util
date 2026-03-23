#include "server/stats_pipe_protocol.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace malware_scan::server {
namespace {

void write_event(int fd, const StatsEvent &event) {
  ssize_t written = 0;

  do {
    written = ::write(fd, &event, sizeof(event));
  } while (written < 0 && errno == EINTR);

  if (written < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "write stats event failed");
  }

  if (static_cast<std::size_t>(written) != sizeof(event)) {
    throw std::runtime_error("short write to stats pipe");
  }
}

} // namespace

void write_file_scanned_event(int fd) {
  StatsEvent event;
  event.type = StatsEventType::file_scanned;
  event.count = 1;
  write_event(fd, event);
}

void write_pattern_hit_event(int fd, const std::string &pattern_id,
                             const std::uint64_t count) {
  if (pattern_id.size() > k_stats_pipe_pattern_id_capacity) {
    throw std::runtime_error("pattern id is too large for stats pipe event");
  }

  StatsEvent event;
  event.type = StatsEventType::pattern_hit;
  event.count = count;
  event.pattern_id_size = static_cast<std::uint32_t>(pattern_id.size());

  if (!pattern_id.empty()) {
    std::memcpy(event.pattern_id, pattern_id.data(), pattern_id.size());
  }

  write_event(fd, event);
}

bool try_read_stats_event(int fd, StatsEvent &event) {
  ssize_t read_result = 0;

  do {
    read_result = ::read(fd, &event, sizeof(event));
  } while (read_result < 0 && errno == EINTR);

  if (read_result < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return false;
    }

    throw std::system_error(errno, std::generic_category(),
                            "read stats event failed");
  }

  if (read_result == 0) {
    return false;
  }

  if (static_cast<std::size_t>(read_result) != sizeof(event)) {
    throw std::runtime_error("short read from stats pipe");
  }

  if (event.pattern_id_size > k_stats_pipe_pattern_id_capacity) {
    throw std::runtime_error("invalid pattern id size in stats pipe event");
  }

  return true;
}

} // namespace malware_scan::server
