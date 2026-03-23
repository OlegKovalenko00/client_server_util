#include "common/socket_io.hpp"

#include <cerrno>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>

namespace malware_scan::common {
void read_exact(int fd, void *buffer, std::size_t size) {
  if (size == 0) {
    return;
  }

  auto *ptr = static_cast<char *>(buffer);
  std::size_t remaining = size;

  while (remaining > 0) {
    const ssize_t n = ::read(fd, ptr, remaining);

    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::system_error(errno, std::generic_category(),
                              "read_exact failed");
    }

    if (n == 0) {
      throw std::runtime_error("unexpected EOF while read from socket");
    }

    ptr += n;
    remaining -= static_cast<std::size_t>(n);
  }
}

void write_exact(int fd, const void *buffer, std::size_t size) {
  if (size == 0) {
    return;
  }

  auto *ptr = static_cast<const char *>(buffer);
  std::size_t remaining = size;

  while (remaining > 0) {
    const ssize_t n = ::write(fd, ptr, remaining);

    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::system_error(errno, std::generic_category(),
                              "write_exact failed");
    }
    if (n == 0) {
      throw std::runtime_error("unexpected EOF while reading from socket");
    }

    ptr += n;
    remaining -= static_cast<std::size_t>(n);
  }
}
} // namespace malware_scan::common