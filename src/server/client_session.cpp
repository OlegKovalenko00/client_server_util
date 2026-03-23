#include "server/client_session.hpp"

#include <exception>
#include <iostream>
#include <unistd.h>

#include "common/wire_protocol.hpp"
#include "server/stats_pipe_protocol.hpp"

namespace malware_scan::server {
int serve_single_client(int client_fd, const ClientWorker &worker,
                        const int stats_write_fd) {
  try {
    common::FileScanRequest request = common::read_request(client_fd);
    common::FileScanResponse response = worker.process(request);
    common::write_response(client_fd, response);

    try {
      write_file_scanned_event(stats_write_fd);

      for (const auto &match : response.result.matches) {
        write_pattern_hit_event(stats_write_fd, match.pattern_id,
                                static_cast<std::uint64_t>(match.count));
      }
    } catch (const std::exception &error) {
      std::cerr << "stats pipe error: " << error.what() << '\n';
    }

    if (::close(client_fd) != 0) {
      std::cerr << "failed to close client socket\n";
      return 1;
    }

    return 0;
  } catch (const std::exception &error) {
    ::close(client_fd);
    std::cerr << "client session error: " << error.what() << '\n';
    return 1;
  }
}
} // namespace malware_scan::server