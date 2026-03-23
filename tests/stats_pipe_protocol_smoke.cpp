#include <gtest/gtest.h>
#include <string>

#include <unistd.h>

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

std::string
pattern_id_from_event(const malware_scan::server::StatsEvent &event) {
  return std::string(event.pattern_id, event.pattern_id_size);
}

} // namespace

TEST(StatsPipeProtocolSmoke, EventsCanBeReadAndAggregated) {
  using namespace malware_scan;

  int pipe_fds[2];
  ASSERT_EQ(::pipe(pipe_fds), 0);
  ScopedFd read_fd{pipe_fds[0]};
  ScopedFd write_fd{pipe_fds[1]};

  server::write_file_scanned_event(write_fd.get());
  server::write_pattern_hit_event(write_fd.get(), "eicar", 2);
  server::write_pattern_hit_event(write_fd.get(), "shell_spawn", 1);
  ::close(write_fd.release());

  server::StatsRegistry registry;
  server::StatsEvent event;

  ASSERT_TRUE(server::try_read_stats_event(read_fd.get(), event));
  EXPECT_EQ(event.type, server::StatsEventType::file_scanned);

  registry.record_scanned_file();

  ASSERT_TRUE(server::try_read_stats_event(read_fd.get(), event));
  EXPECT_EQ(event.type, server::StatsEventType::pattern_hit);

  registry.record_pattern_hit(pattern_id_from_event(event), event.count);

  ASSERT_TRUE(server::try_read_stats_event(read_fd.get(), event));
  EXPECT_EQ(event.type, server::StatsEventType::pattern_hit);

  registry.record_pattern_hit(pattern_id_from_event(event), event.count);

  EXPECT_FALSE(server::try_read_stats_event(read_fd.get(), event));

  const auto snapshot = registry.snapshot();
  EXPECT_EQ(snapshot.scanned_files, 1U);
  EXPECT_EQ(snapshot.pattern_hits.at("eicar"), 2U);
  EXPECT_EQ(snapshot.pattern_hits.at("shell_spawn"), 1U);
}
