#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include "common/protocol.hpp"
#include "common/wire_protocol.hpp"

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

} // namespace

TEST(WireProtocolSmoke, RequestAndResponseRoundTrip) {
  using namespace malware_scan;

  int fds[2];
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
  const ScopedFd client_fd{fds[0]};
  const ScopedFd server_fd{fds[1]};

  common::FileScanRequest request;
  request.file_name = "sample.txt";
  request.content = "hello EICAR and /bin/sh";

  common::write_request(client_fd.get(), request);
  const auto decoded_request = common::read_request(server_fd.get());

  EXPECT_EQ(decoded_request.file_name, request.file_name);
  EXPECT_EQ(decoded_request.content, request.content);

  common::FileScanResponse response;
  response.result.has_threats = true;
  response.result.matches.push_back(common::PatternMatch{"eicar", 1});
  response.result.matches.push_back(common::PatternMatch{"shell_spawn", 1});
  response.summary = "Threats found in file: sample.txt";

  common::write_response(server_fd.get(), response);
  const auto decoded_response = common::read_response(client_fd.get());

  EXPECT_EQ(decoded_response.result.has_threats, response.result.has_threats);
  ASSERT_EQ(decoded_response.result.matches.size(),
            response.result.matches.size());

  for (std::size_t index = 0; index < response.result.matches.size(); ++index) {
    EXPECT_EQ(decoded_response.result.matches[index].pattern_id,
              response.result.matches[index].pattern_id);
    EXPECT_EQ(decoded_response.result.matches[index].count,
              response.result.matches[index].count);
  }

  EXPECT_EQ(decoded_response.summary, response.summary);
}
