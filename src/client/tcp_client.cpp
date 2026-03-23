#include "client/tcp_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <system_error>

#include "common/wire_protocol.hpp"

namespace malware_scan::client {

ScanClient::ScanClient(const std::uint16_t port) : port_(port) {}

common::FileScanResponse
ScanClient::submit(const common::FileScanRequest &request) const {
  const int socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);

  if (socket_fd < 0) {
    throw std::system_error(errno, std::generic_category(), "socket failed");
  }
  try {
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);

    const int pton_result =
        ::inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if (pton_result != 1) {
      throw std::system_error(errno, std::generic_category(), "pton failed");
      ;
    }

    const int connect_result =
        ::connect(socket_fd, reinterpret_cast<const sockaddr *>(&server_addr),
                  sizeof(server_addr));
    if (connect_result < 0) {
      throw std::system_error(errno, std::generic_category(), "connect failed");
      ;
    }

    common::write_request(socket_fd, request);
    common::FileScanResponse response = common::read_response(socket_fd);

    ::close(socket_fd);
    return response;
  } catch (...) {
    ::close(socket_fd);
    throw;
  }
}

} // namespace malware_scan::client
