#include "server/server_app.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

#include "server/client_session.hpp"
#include "server/client_worker.hpp"
#include "server/config_loader.hpp"
#include "server/signal_state.hpp"
#include "server/stats_fifo_service.hpp"
#include "server/stats_pipe_protocol.hpp"
#include "server/stats_registry.hpp"
#include <fcntl.h>
#include <string>

namespace {
int create_listening_socket(std::uint16_t port) {
  const int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    throw std::system_error(errno, std::generic_category(), "socket failed");
  }
  try {
    int opt = 1;
    if (::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
        0) {
      throw std::system_error(errno, std::generic_category(),
                              "setsockopt failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(listen_fd, reinterpret_cast<const sockaddr *>(&addr),
               sizeof(addr)) < 0) {
      throw std::system_error(errno, std::generic_category(), "bind failed");
    }
    if (::listen(listen_fd, SOMAXCONN) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "listening failed");
    }
    return listen_fd;
  } catch (...) {
    ::close(listen_fd);
    throw;
  }
}
void reap_finished_children() {
  while (true) {
    const pid_t pid = ::waitpid(-1, nullptr, WNOHANG);
    if (pid <= 0) {
      break;
    }
  }
}
void wait_for_all_children() {
  while (true) {
    const pid_t pid = ::waitpid(-1, nullptr, 0);
    if (pid > 0) {
      continue;
    }
    if (pid < 0 && errno == EINTR) {
      continue;
    }
    if (pid < 0 && errno == ECHILD) {
      break;
    }
    throw std::system_error(errno, std::generic_category(), "waitpid failed");
  }
}
void close_if_valid(int &fd) {
  if (fd >= 0) {
    ::close(fd);
    fd = -1;
  }
}

void set_non_blocking(const int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "fcntl(F_GETFL) failed");
  }

  if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "fcntl(F_SETFL) failed");
  }
}

void apply_stats_event(const malware_scan::server::StatsEvent &event,
                       malware_scan::server::StatsRegistry &stats_registry) {
  using malware_scan::server::StatsEventType;

  switch (event.type) {
  case StatsEventType::file_scanned:
    stats_registry.record_scanned_file();
    return;

  case StatsEventType::pattern_hit:
    stats_registry.record_pattern_hit(
        std::string(event.pattern_id, event.pattern_id_size), event.count);
    return;
  }

  throw std::runtime_error("unknown stats event type");
}

void drain_stats_pipe(const int stats_read_fd,
                      malware_scan::server::StatsRegistry &stats_registry) {
  while (true) {
    malware_scan::server::StatsEvent event;
    if (!malware_scan::server::try_read_stats_event(stats_read_fd, event)) {
      break;
    }

    apply_stats_event(event, stats_registry);
  }
}

} // namespace

namespace malware_scan::server {

ServerApp::ServerApp(ServerOptions options) : options_(std::move(options)) {}

int ServerApp::run() const {
  SignalState::install();

  const auto config = PatternConfigLoader{}.load(options_.config_path);
  const PatternMatcher matcher{config};
  const ClientWorker worker{matcher};
  StatsRegistry stats_registry;
  const StatsFifoService stats_service{options_.stats_request_fifo,
                                       options_.stats_response_fifo};

  int stats_pipe[2] = {-1, -1};
  if (::pipe(stats_pipe) < 0) {
    throw std::system_error(errno, std::generic_category(), "pipe failed");
  }

  set_non_blocking(stats_pipe[0]);

  int listen_fd = -1;
  int stats_request_fd = -1;

  try {
    listen_fd = create_listening_socket(options_.port);

    stats_service.remove_if_exists();
    stats_service.ensure_created();
    stats_request_fd = stats_service.open_request_fd();

    while (!SignalState::stop_requested()) {
      reap_finished_children();

      pollfd fds[3];
      fds[0].fd = listen_fd;
      fds[0].events = POLLIN;
      fds[0].revents = 0;

      fds[1].fd = stats_pipe[0];
      fds[1].events = POLLIN;
      fds[1].revents = 0;

      fds[2].fd = stats_request_fd;
      fds[2].events = POLLIN;
      fds[2].revents = 0;

      const int poll_result = ::poll(fds, 3, -1);
      if (poll_result < 0) {
        if (errno == EINTR) {
          if (SignalState::stop_requested()) {
            break;
          }

          continue;
        }

        throw std::system_error(errno, std::generic_category(), "poll failed");
      }

      if (fds[1].revents & POLLIN) {
        drain_stats_pipe(stats_pipe[0], stats_registry);
      }

      if (fds[2].revents & POLLIN) {
        drain_stats_pipe(stats_pipe[0], stats_registry);

        const std::size_t requests_count =
            stats_service.drain_request_markers(stats_request_fd);
        for (std::size_t i = 0; i < requests_count; ++i) {
          stats_service.send_snapshot(stats_registry.snapshot());
        }
      }

      if (fds[0].revents & POLLIN) {
        const int client_fd = ::accept(listen_fd, nullptr, nullptr);
        if (client_fd < 0) {
          if (errno == EINTR) {
            continue;
          }

          throw std::system_error(errno, std::generic_category(),
                                  "accept failed");
        }

        const pid_t pid = ::fork();
        if (pid < 0) {
          ::close(client_fd);
          throw std::system_error(errno, std::generic_category(),
                                  "fork failed");
        }

        if (pid == 0) {
          close_if_valid(listen_fd);
          close_if_valid(stats_pipe[0]);
          close_if_valid(stats_request_fd);

          const int rc = serve_single_client(client_fd, worker, stats_pipe[1]);
          close_if_valid(stats_pipe[1]);
          ::_exit(rc);
        }

        ::close(client_fd);
      }
    }

    close_if_valid(listen_fd);
    close_if_valid(stats_request_fd);

    wait_for_all_children();
    close_if_valid(stats_pipe[1]);
    drain_stats_pipe(stats_pipe[0], stats_registry);
    close_if_valid(stats_pipe[0]);

    stats_service.remove_if_exists();
    return 0;
  } catch (...) {
    close_if_valid(listen_fd);
    close_if_valid(stats_request_fd);
    close_if_valid(stats_pipe[0]);
    close_if_valid(stats_pipe[1]);
    stats_service.remove_if_exists();
    throw;
  }
}

} // namespace malware_scan::server
