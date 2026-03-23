#include <gtest/gtest.h>
#include <stdexcept>
#include <string>

#include <sys/socket.h>
#include <unistd.h>

#include "common/protocol.hpp"
#include "common/wire_protocol.hpp"
#include "server/client_session.hpp"
#include "server/client_worker.hpp"
#include "server/pattern_matcher.hpp"
#include "server/stats_pipe_protocol.hpp"
#include "server/stats_registry.hpp"

namespace {

class ScopedFd {
public:
  explicit ScopedFd(const int fd = -1) : fd_(fd) {}

  ~ScopedFd() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;

  int get() const { return fd_; }

  int release() {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }

private:
  int fd_ = -1;
};

void apply_event(const malware_scan::server::StatsEvent &event,
                 malware_scan::server::StatsRegistry &registry) {
  using malware_scan::server::StatsEventType;

  if (event.type == StatsEventType::file_scanned) {
    registry.record_scanned_file();
    return;
  }

  if (event.type == StatsEventType::pattern_hit) {
    registry.record_pattern_hit(
        std::string(event.pattern_id, event.pattern_id_size), event.count);
    return;
  }

  throw std::runtime_error("unexpected stats event type");
}

} // namespace

TEST(ClientSessionSmoke, SessionProcessesRequestAndWritesStats) {
  using namespace malware_scan;

  common::PatternConfig config;
  config.patterns.push_back(common::PatternDefinition{"eicar", "EICAR"});
  config.patterns.push_back(
      common::PatternDefinition{"shell_spawn", "/bin/sh"});

  const server::PatternMatcher matcher{config};
  const server::ClientWorker worker{matcher};

  int socket_fds[2];
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds), 0);
  ScopedFd client_fd{socket_fds[0]};
  ScopedFd server_fd{socket_fds[1]};

  int stats_fds[2];
  ASSERT_EQ(::pipe(stats_fds), 0);
  ScopedFd stats_read_fd{stats_fds[0]};
  ScopedFd stats_write_fd{stats_fds[1]};

  common::FileScanRequest request;
  request.file_name = "infected.txt";
  request.content = "prefix EICAR middle /bin/sh tail EICAR";

  common::write_request(client_fd.get(), request);

  const int session_result = server::serve_single_client(
      server_fd.get(), worker, stats_write_fd.get());
  server_fd.release();
  EXPECT_EQ(session_result, 0);

  const auto response = common::read_response(client_fd.get());
  EXPECT_TRUE(response.result.has_threats);
  ASSERT_EQ(response.result.matches.size(), 2U);

  ::close(stats_write_fd.release());

  server::StatsRegistry registry;
  server::StatsEvent event;
  while (server::try_read_stats_event(stats_read_fd.get(), event)) {
    apply_event(event, registry);
  }

  const auto snapshot = registry.snapshot();
  EXPECT_EQ(snapshot.scanned_files, 1U);
  EXPECT_EQ(snapshot.pattern_hits.at("eicar"), 2U);
  EXPECT_EQ(snapshot.pattern_hits.at("shell_spawn"), 1U);
}
